from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.port import Port
from tools.base import Tool


class InternetDBTool(Tool):
    """Small wrapper around Shodan InternetDB's unauthenticated IP lookup API."""

    api_endpoint = "https://internetdb.shodan.io"

    @classmethod
    def name(cls) -> str:
        return "internetdb"

    @classmethod
    def category(cls) -> str:
        return "Network"

    @classmethod
    def description(cls) -> str:
        return "Queries Shodan InternetDB for passive IP information"

    @classmethod
    def version(cls) -> str:
        return "1.0.0"

    def launch(self, value: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
        """
        Query InternetDB for an IP address.

        Returns the raw InternetDB JSON response, or None when the IP has no
        InternetDB record.
        """
        response = requests.get(
            f"{self.api_endpoint}/{value}",
            headers={"Accept": "application/json"},
            timeout=timeout,
        )

        # InternetDB returns 404 when it has no information for an address.
        if response.status_code == 404:
            return None

        response.raise_for_status()
        payload = response.json()

        if not isinstance(payload, dict):
            raise ValueError("InternetDB returned an unexpected response type")

        return payload


class InternetDBResult(BaseModel):
    """Structured multi-entity result returned by the InternetDB enricher."""

    ip: Ip
    hostnames: List[Domain] = Field(default_factory=list)
    ports: List[Port] = Field(default_factory=list)


@flowsint_enricher
class IpToInternetDBEnricher(Enricher):
    """[InternetDB] Enrich an IP with Shodan InternetDB passive data."""

    InputType = Ip
    OutputType = InternetDBResult

    @classmethod
    def name(cls) -> str:
        return "ip_to_internetdb"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def required_params(cls) -> bool:
        return False

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return []

    @classmethod
    def documentation(cls) -> str:
        return """
        Queries the free Shodan InternetDB API for an IP address.

        InternetDB data is mapped as follows:
        - cpes  -> stored on the IP node as `cpes`
        - tags  -> stored on the IP node as `tags`
        - vulns -> stored on the IP node as `vulns`
        - hostnames -> Domain nodes linked from the IP with REVERSE_RESOLVES_TO
        - ports -> Port nodes linked from the IP with HAS_PORT

        No API key is required.
        """

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        internetdb = InternetDBTool()

        for ip in data:
            try:
                Logger.info(
                    self.sketch_id,
                    {"message": f"[InternetDB] Querying {ip.address}"},
                )

                raw = internetdb.launch(ip.address)
                if raw is None:
                    Logger.info(
                        self.sketch_id,
                        {"message": f"[InternetDB] No information available for {ip.address}"},
                    )
                    continue

                # Keep all existing IP properties, then add the InternetDB fields.
                ip_data = ip.model_dump()
                ip_data.update(
                    {
                        "cpes": self._clean_strings(raw.get("cpes", [])),
                        "tags": self._clean_strings(raw.get("tags", [])),
                        "vulns": self._clean_strings(raw.get("vulns", [])),
                    }
                )
                enriched_ip = Ip(**ip_data)

                hostnames: List[Domain] = []
                seen_hostnames = set()
                for hostname in self._clean_strings(raw.get("hostnames", [])):
                    hostname = hostname.rstrip(".").lower()
                    if not hostname or hostname in seen_hostnames:
                        continue
                    try:
                        hostnames.append(Domain(domain=hostname))
                        seen_hostnames.add(hostname)
                    except ValueError:
                        Logger.warn(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[InternetDB] Ignoring invalid hostname returned for "
                                    f"{ip.address}: {hostname}"
                                )
                            },
                        )

                ports: List[Port] = []
                seen_ports = set()
                for value in raw.get("ports", []) or []:
                    try:
                        port_number = int(value)
                        if port_number in seen_ports:
                            continue
                        ports.append(
                            Port(
                                number=port_number,
                                protocol="TCP",
                                state="open",
                            )
                        )
                        seen_ports.add(port_number)
                    except (TypeError, ValueError):
                        Logger.warn(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[InternetDB] Ignoring invalid port returned for "
                                    f"{ip.address}: {value}"
                                )
                            },
                        )

                result = InternetDBResult(
                    ip=enriched_ip,
                    hostnames=hostnames,
                    ports=ports,
                )
                results.append(result)

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[InternetDB] {ip.address}: "
                            f"{len(hostnames)} hostname(s), {len(ports)} port(s), "
                            f"{len(enriched_ip.cpes)} CPE(s), "
                            f"{len(enriched_ip.tags)} tag(s), "
                            f"{len(enriched_ip.vulns)} vuln(s)"
                        )
                    },
                )

            except requests.exceptions.RequestException as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[InternetDB] HTTP error for {ip.address}: {e}"},
                )
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[InternetDB] Error enriching {ip.address}: {e}"},
                )

        return results

    def postprocess(
        self,
        results: List[OutputType],
        input_data: List[InputType] = None,
    ) -> List[OutputType]:
        """Persist the enriched IP and create related Domain and Port nodes."""
        for result in results:
            ip_obj = result.ip

            # Re-create/update the IP node with cpes, tags and vulns included.
            self.create_node(ip_obj)

            for domain_obj in result.hostnames:
                self.create_node(domain_obj)
                self.create_relationship(ip_obj, domain_obj, "REVERSE_RESOLVES_TO")
                self.log_graph_message(
                    f"InternetDB hostname for {ip_obj.address} -> {domain_obj.domain}"
                )

            for port_obj in result.ports:
                self.create_node(port_obj)
                self.create_relationship(ip_obj, port_obj, "HAS_PORT")
                self.log_graph_message(
                    f"InternetDB open port {port_obj.number}/TCP found on {ip_obj.address}"
                )

            self.log_graph_message(
                f"InternetDB enriched {ip_obj.address} with "
                f"{len(ip_obj.cpes)} CPE(s), {len(ip_obj.tags)} tag(s), "
                f"and {len(ip_obj.vulns)} vulnerability ID(s)"
            )

        return results

    @staticmethod
    def _clean_strings(values: Any) -> List[str]:
        """Normalize an InternetDB array into a de-duplicated list of strings."""
        if not isinstance(values, list):
            return []

        cleaned: List[str] = []
        seen = set()

        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            cleaned.append(text)

        return cleaned


InputType = IpToInternetDBEnricher.InputType
OutputType = IpToInternetDBEnricher.OutputType

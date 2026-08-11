import json
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.port import Port


class _ShodanIpTool:
    """Small embedded wrapper around Shodan's host-information endpoint."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": "Flowsint-Shodan-IP-Enricher/1.0",
            }
        )

    def launch(
        self,
        ip_address: str,
        api_key: str,
        *,
        history: bool = False,
        minify: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Return Shodan host information for one IP address."""
        if not api_key:
            raise ValueError("SHODAN_API_KEY is missing")

        response = self.session.get(
            f"{self.BASE_URL}/shodan/host/{ip_address}",
            params={
                "key": api_key,
                "history": str(history).lower(),
                "minify": str(minify).lower(),
            },
            timeout=self.timeout,
        )

        # Shodan returns 404 when it has no information for the host.
        if response.status_code == 404:
            return None
        if response.status_code == 401:
            raise RuntimeError("Shodan rejected the API key (HTTP 401)")
        if response.status_code == 429:
            raise RuntimeError("Shodan API rate limit reached (HTTP 429)")

        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError("Shodan returned a non-JSON response") from exc

        if not isinstance(payload, dict):
            raise RuntimeError("Unexpected Shodan response format")

        return payload


@flowsint_enricher
class IpToShodanEnricher(Enricher):
    """[SHODAN] Passively enrich IP addresses with Shodan host intelligence."""

    InputType = Ip
    OutputType = Ip

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault=None,
        params: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
        )
        self.ip_asn_mapping: List[Tuple[Ip, ASN]] = []
        self.ip_domain_mapping: List[Tuple[Ip, Domain]] = []
        self.ip_port_mapping: List[Tuple[Ip, Port]] = []

    @classmethod
    def required_params(cls) -> bool:
        return True

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "SHODAN_API_KEY",
                "type": "vaultSecret",
                "description": "Shodan API key used for passive host lookups.",
                "required": True,
            },
            {
                "name": "history",
                "type": "select",
                "description": "Include historical Shodan service banners.",
                "required": False,
                "default": "false",
                "options": [
                    {"label": "Disabled", "value": "false"},
                    {"label": "Enabled", "value": "true"},
                ],
            },
            {
                "name": "include_banners",
                "type": "select",
                "description": "Retrieve service banners and use them to enrich Port nodes.",
                "required": False,
                "default": "true",
                "options": [
                    {"label": "Enabled", "value": "true"},
                    {"label": "Disabled", "value": "false"},
                ],
            },
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_shodan"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def documentation(cls) -> str:
        return """
        Passively enriches IP addresses using Shodan's /shodan/host/{ip} API.

        The IP node is updated with Shodan geolocation, ISP and passive metadata.
        The enricher also creates related ASN, Domain and Port nodes using the
        standard BELONGS_TO, REVERSE_RESOLVES_TO and HAS_PORT relationships.

        No active Shodan scan is triggered by this enricher.
        """

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        self.ip_asn_mapping = []
        self.ip_domain_mapping = []
        self.ip_port_mapping = []

        api_key = self.get_secret("SHODAN_API_KEY", os.getenv("SHODAN_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {
                    "message": "[SHODAN] Missing SHODAN_API_KEY. Configure it in the Flowsint vault."
                },
            )
            return results

        history = str(self.params.get("history", "false")).lower() == "true"
        include_banners = (
            str(self.params.get("include_banners", "true")).lower() == "true"
        )

        shodan = _ShodanIpTool()

        for input_ip in data:
            try:
                Logger.info(
                    self.sketch_id,
                    {"message": f"[SHODAN] Looking up {input_ip.address}"},
                )

                host = shodan.launch(
                    input_ip.address,
                    api_key,
                    history=history,
                    minify=not include_banners,
                )

                if not host:
                    Logger.warn(
                        self.sketch_id,
                        {
                            "message": f"[SHODAN] No host information found for {input_ip.address}"
                        },
                    )
                    continue

                # Work on a copy so the original input remains untouched until the
                # enriched entity is returned and persisted by postprocessing.
                enriched_ip = input_ip.model_copy(deep=True)
                self._enrich_ip(enriched_ip, host)

                asn = self._build_asn(host)
                if asn:
                    self.ip_asn_mapping.append((enriched_ip, asn))

                for domain in self._build_domains(host):
                    self.ip_domain_mapping.append((enriched_ip, domain))

                for port in self._build_ports(host, include_banners=include_banners):
                    self.ip_port_mapping.append((enriched_ip, port))

                results.append(enriched_ip)

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[SHODAN] Enriched {input_ip.address}: "
                            f"{len(host.get('ports') or [])} ports, "
                            f"{len(host.get('hostnames') or [])} hostnames, "
                            f"ASN {host.get('asn') or 'unknown'}"
                        )
                    },
                )

            except Exception as exc:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"[SHODAN] Error enriching {input_ip.address}: {exc}"
                    },
                )
                continue

        return results

    def postprocess(
        self,
        results: List[OutputType],
        input_data: List[InputType] = None,
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        # Persist the enriched IP nodes first.
        for ip in results:
            self.create_node(ip)

        for ip, asn in self.ip_asn_mapping:
            self.create_node(asn)
            self.create_relationship(ip, asn, "BELONGS_TO")
            self.log_graph_message(
                f"[SHODAN] {ip.address} belongs to {asn.asn_str}"
            )

        for ip, domain in self.ip_domain_mapping:
            self.create_node(domain)
            self.create_relationship(ip, domain, "REVERSE_RESOLVES_TO")
            self.log_graph_message(
                f"[SHODAN] Hostname/domain {domain.domain} observed for {ip.address}"
            )

        for ip, port in self.ip_port_mapping:
            self.create_node(port)
            self.create_relationship(ip, port, "HAS_PORT")
            service = f" ({port.service})" if port.service else ""
            protocol = f"/{port.protocol}" if port.protocol else ""
            self.log_graph_message(
                f"[SHODAN] Port {port.number}{protocol}{service} observed on {ip.address}"
            )

        return results

    @staticmethod
    def _enrich_ip(ip: Ip, host: Dict[str, Any]) -> None:
        """Map Shodan host-level information onto the IP entity."""
        ip.latitude = host.get("latitude")
        ip.longitude = host.get("longitude")
        ip.country = host.get("country_name") or host.get("country_code")
        ip.city = host.get("city")
        ip.isp = host.get("isp")

        hostnames = IpToShodanEnricher._clean_string_list(host.get("hostnames"))
        domains = IpToShodanEnricher._clean_string_list(host.get("domains"))
        tags = IpToShodanEnricher._clean_string_list(host.get("tags"))
        ports = IpToShodanEnricher._clean_int_list(host.get("ports"))
        vulnerabilities = IpToShodanEnricher._collect_vulnerabilities(host)
        cpes = IpToShodanEnricher._collect_cpes(host)

        # FlowsintType permits extra fields. Prefix source-specific properties to
        # keep them clearly attributable to Shodan in the graph/UI.
        setattr(ip, "shodan_org", host.get("org"))
        setattr(ip, "shodan_asn", host.get("asn"))
        setattr(ip, "shodan_os", host.get("os"))
        setattr(ip, "shodan_region_code", host.get("region_code"))
        setattr(ip, "shodan_postal_code", host.get("postal_code"))
        setattr(ip, "shodan_last_update", host.get("last_update"))
        setattr(ip, "shodan_hostnames", hostnames)
        setattr(ip, "shodan_domains", domains)
        setattr(ip, "shodan_ports", ports)
        setattr(ip, "shodan_tags", tags)
        setattr(ip, "shodan_vulnerabilities", vulnerabilities)
        setattr(ip, "shodan_cpes", cpes)
        setattr(ip, "shodan_service_count", len(host.get("data") or []))
        setattr(ip, "shodan_url", f"https://www.shodan.io/host/{ip.address}")

    @staticmethod
    def _build_asn(host: Dict[str, Any]) -> Optional[ASN]:
        raw_asn = host.get("asn")
        if not raw_asn:
            return None

        try:
            return ASN(
                asn_str=str(raw_asn),
                name=host.get("org") or host.get("isp"),
                country=host.get("country_code"),
                description=(
                    f"Observed by Shodan for {host.get('ip_str')}"
                    if host.get("ip_str")
                    else "Observed by Shodan"
                ),
            )
        except Exception:
            return None

    @staticmethod
    def _build_domains(host: Dict[str, Any]) -> List[Domain]:
        candidates = set()

        for value in (host.get("hostnames") or []):
            if isinstance(value, str) and value.strip():
                candidates.add(value.strip().rstrip(".").lower())

        for value in (host.get("domains") or []):
            if isinstance(value, str) and value.strip():
                candidates.add(value.strip().rstrip(".").lower())

        for banner in host.get("data") or []:
            if not isinstance(banner, dict):
                continue
            for key in ("hostnames", "domains"):
                for value in banner.get(key) or []:
                    if isinstance(value, str) and value.strip():
                        candidates.add(value.strip().rstrip(".").lower())

        domains: List[Domain] = []
        for candidate in sorted(candidates):
            try:
                domains.append(Domain(domain=candidate))
            except Exception:
                # Shodan occasionally returns PTR-style labels that do not satisfy
                # Flowsint's Domain validator; ignore those instead of aborting.
                continue

        return domains

    @staticmethod
    def _build_ports(
        host: Dict[str, Any],
        *,
        include_banners: bool,
    ) -> List[Port]:
        banners_by_key: Dict[Tuple[int, str], List[Dict[str, Any]]] = defaultdict(list)

        for banner in host.get("data") or []:
            if not isinstance(banner, dict):
                continue
            port_number = banner.get("port")
            try:
                port_number = int(port_number)
            except (TypeError, ValueError):
                continue
            if not 0 <= port_number <= 65535:
                continue

            transport = str(banner.get("transport") or "").upper()
            banners_by_key[(port_number, transport)].append(banner)

        ports: List[Port] = []
        represented_numbers = set()

        for (port_number, transport), observations in sorted(banners_by_key.items()):
            represented_numbers.add(port_number)
            # ISO timestamps sort lexicographically, so this reliably picks the
            # newest observation for normal Shodan timestamps.
            latest = max(
                observations,
                key=lambda item: str(item.get("timestamp") or ""),
            )

            product = latest.get("product")
            version = latest.get("version")
            module = (latest.get("_shodan") or {}).get("module")
            service = product or module

            banner_text = None
            if include_banners:
                raw_banner = latest.get("data")
                if isinstance(raw_banner, str):
                    cleaned = raw_banner.strip()
                    if cleaned:
                        banner_text = cleaned[:4096]

            if not banner_text and product:
                banner_text = f"{product} {version}".strip() if version else str(product)

            port = Port(
                number=port_number,
                protocol=transport or None,
                state="open",
                service=str(service) if service else None,
                banner=banner_text,
            )

            setattr(port, "shodan_product", product)
            setattr(port, "shodan_version", version)
            setattr(port, "shodan_timestamp", latest.get("timestamp"))
            setattr(port, "shodan_module", module)
            setattr(port, "shodan_observation_count", len(observations))
            setattr(port, "shodan_cpes", IpToShodanEnricher._clean_string_list(latest.get("cpe")))
            setattr(port, "shodan_vulnerabilities", IpToShodanEnricher._extract_vuln_keys(latest.get("vulns")))

            http = latest.get("http")
            if isinstance(http, dict):
                setattr(port, "shodan_http_title", http.get("title"))
                setattr(port, "shodan_http_server", http.get("server"))

            ssl = latest.get("ssl")
            if isinstance(ssl, dict):
                cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
                fingerprint = cert.get("fingerprint") if isinstance(cert.get("fingerprint"), dict) else {}
                setattr(port, "shodan_ssl_versions", IpToShodanEnricher._clean_string_list(ssl.get("versions")))
                setattr(port, "shodan_ssl_cert_expired", cert.get("expired"))
                setattr(port, "shodan_ssl_cert_sha256", fingerprint.get("sha256"))
                if cert.get("subject") is not None:
                    setattr(port, "shodan_ssl_subject", IpToShodanEnricher._json_string(cert.get("subject")))
                if cert.get("issuer") is not None:
                    setattr(port, "shodan_ssl_issuer", IpToShodanEnricher._json_string(cert.get("issuer")))

            ports.append(port)

        # When minify=true Shodan omits service banners but still returns the
        # top-level list of observed open ports. Preserve those as basic Port nodes.
        for port_number in IpToShodanEnricher._clean_int_list(host.get("ports")):
            if port_number in represented_numbers:
                continue
            ports.append(Port(number=port_number, state="open"))

        return ports

    @staticmethod
    def _collect_vulnerabilities(host: Dict[str, Any]) -> List[str]:
        vulnerabilities = set(IpToShodanEnricher._extract_vuln_keys(host.get("vulns")))

        for banner in host.get("data") or []:
            if isinstance(banner, dict):
                vulnerabilities.update(
                    IpToShodanEnricher._extract_vuln_keys(banner.get("vulns"))
                )

        return sorted(vulnerabilities)

    @staticmethod
    def _collect_cpes(host: Dict[str, Any]) -> List[str]:
        cpes = set(IpToShodanEnricher._clean_string_list(host.get("cpe")))
        for banner in host.get("data") or []:
            if isinstance(banner, dict):
                cpes.update(IpToShodanEnricher._clean_string_list(banner.get("cpe")))
        return sorted(cpes)

    @staticmethod
    def _extract_vuln_keys(value: Any) -> List[str]:
        if isinstance(value, dict):
            return sorted(str(key) for key in value.keys() if key)
        if isinstance(value, (list, tuple, set)):
            return sorted(str(item) for item in value if item)
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    @staticmethod
    def _clean_string_list(value: Any) -> List[str]:
        if not isinstance(value, (list, tuple, set)):
            return []
        return sorted({str(item).strip() for item in value if str(item).strip()})

    @staticmethod
    def _clean_int_list(value: Any) -> List[int]:
        if not isinstance(value, (list, tuple, set)):
            return []

        result = set()
        for item in value:
            try:
                number = int(item)
            except (TypeError, ValueError):
                continue
            if 0 <= number <= 65535:
                result.add(number)
        return sorted(result)

    @staticmethod
    def _json_string(value: Any) -> str:
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False)
        except Exception:
            return str(value)


# Make types available at module level for easy access.
InputType = IpToShodanEnricher.InputType
OutputType = IpToShodanEnricher.OutputType

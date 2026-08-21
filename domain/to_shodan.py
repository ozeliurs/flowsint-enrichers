import ipaddress
import os
from typing import Any, Dict, List, Optional, Tuple

import requests
from pydantic import BaseModel, ConfigDict, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.dns_record import DNSRecord
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.port import Port


class ParamsModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    SHODAN_API_KEY: str
    history: str = "false"
    record_type: str = "ALL"
    max_pages: int = Field(default=1, ge=1, le=100)
    enrich_host_ips: str = "true"
    max_host_lookups: int = Field(default=25, ge=1, le=1000)
    host_history: str = "false"
    host_minify: str = "false"
    timeout: int = Field(default=30, ge=1, le=300)


class ShodanDomainClient:
    """Small Shodan REST client used by the enricher.

    Kept in this file on purpose so the enricher can be dropped into
    flowsint-enrichers without adding a separate tools/ module.
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = dict(params or {})
        query["key"] = self.api_key

        response = self.session.get(
            f"{self.BASE_URL}{path}",
            params=query,
            timeout=self.timeout,
        )

        try:
            payload = response.json()
        except Exception:
            payload = {}

        if response.status_code != 200:
            error = payload.get("error") if isinstance(payload, dict) else None
            raise RuntimeError(
                f"Shodan API returned HTTP {response.status_code}: "
                f"{error or response.text[:500]}"
            )

        if not isinstance(payload, dict):
            raise RuntimeError("Shodan API returned an unexpected response")

        return payload

    def domain_info(
        self,
        domain: str,
        *,
        history: bool = False,
        record_type: Optional[str] = None,
        page: int = 1,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "history": str(history).lower(),
            "page": page,
        }
        if record_type:
            params["type"] = record_type

        return self._get(f"/dns/domain/{domain}", params=params)

    def host_info(
        self,
        ip: str,
        *,
        history: bool = False,
        minify: bool = False,
    ) -> Dict[str, Any]:
        return self._get(
            f"/shodan/host/{ip}",
            params={
                "history": str(history).lower(),
                "minify": str(minify).lower(),
            },
        )


@flowsint_enricher
class DomainToShodanEnricher(Enricher):
    """[SHODAN] Enrich a domain using Shodan DNS data and optional host pivots."""

    InputType = Domain
    OutputType = DNSRecord

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault=None,
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
            **kwargs,
        )

        # Context collected during scan() and consumed by postprocess().
        self._record_links: List[Tuple[Domain, Domain, DNSRecord]] = []
        self._subdomain_links: List[Tuple[Domain, Domain]] = []
        self._ip_links: List[Tuple[Domain, Ip]] = []
        self._asn_links: List[Tuple[Ip, ASN]] = []
        self._port_links: List[Tuple[Ip, Port]] = []

    @classmethod
    def required_params(cls) -> bool:
        return True

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "SHODAN_API_KEY",
                "type": "vaultSecret",
                "description": "Your Shodan API key.",
                "required": True,
            },
            {
                "name": "history",
                "type": "select",
                "description": "Include historical Shodan DNS observations.",
                "required": False,
                "default": "false",
                "options": [
                    {"label": "Disabled", "value": "false"},
                    {"label": "Enabled", "value": "true"},
                ],
            },
            {
                "name": "record_type",
                "type": "select",
                "description": "Restrict Shodan DNS results to one record type.",
                "required": False,
                "default": "ALL",
                "options": [
                    {"label": "All", "value": "ALL"},
                    {"label": "A", "value": "A"},
                    {"label": "AAAA", "value": "AAAA"},
                    {"label": "CNAME", "value": "CNAME"},
                    {"label": "MX", "value": "MX"},
                    {"label": "NS", "value": "NS"},
                    {"label": "SOA", "value": "SOA"},
                    {"label": "TXT", "value": "TXT"},
                ],
            },
            {
                "name": "max_pages",
                "type": "number",
                "description": (
                    "Maximum number of Shodan DNS pages to retrieve. "
                    "Each page contains up to 100 records."
                ),
                "required": False,
                "default": 1,
            },
            {
                "name": "enrich_host_ips",
                "type": "select",
                "description": (
                    "For A/AAAA records, also query Shodan host intelligence "
                    "and create IP -> ASN / Port graph pivots."
                ),
                "required": False,
                "default": "true",
                "options": [
                    {"label": "Enabled", "value": "true"},
                    {"label": "Disabled", "value": "false"},
                ],
            },
            {
                "name": "max_host_lookups",
                "type": "number",
                "description": (
                    "Maximum unique A/AAAA addresses to pivot into Shodan host lookups."
                ),
                "required": False,
                "default": 25,
            },
            {
                "name": "host_history",
                "type": "select",
                "description": "Include historical banners in Shodan host pivots.",
                "required": False,
                "default": "false",
                "options": [
                    {"label": "Disabled", "value": "false"},
                    {"label": "Enabled", "value": "true"},
                ],
            },
            {
                "name": "host_minify",
                "type": "select",
                "description": (
                    "Use Shodan's minified host response. This is lighter but "
                    "provides less service/banner detail."
                ),
                "required": False,
                "default": "false",
                "options": [
                    {"label": "Disabled", "value": "false"},
                    {"label": "Enabled", "value": "true"},
                ],
            },
            {
                "name": "timeout",
                "type": "number",
                "description": "HTTP timeout in seconds.",
                "required": False,
                "default": 30,
            },
        ]

    @classmethod
    def get_params_model(cls):
        return ParamsModel

    @classmethod
    def name(cls) -> str:
        return "domain_to_shodan"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}

    @staticmethod
    def _as_int(value: Any, default: int, minimum: int = 1, maximum: int = 1000) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(parsed, maximum))

    @staticmethod
    def _fqdn(root_domain: str, subdomain: Any) -> str:
        sub = str(subdomain or "").strip().strip(".")
        if not sub:
            return root_domain
        return f"{sub}.{root_domain}".lower()

    @staticmethod
    def _domain_or_none(value: str) -> Optional[Domain]:
        # Wildcard Shodan DNS entries are valid intelligence, but the current
        # Flowsint Domain type intentionally rejects "*.<domain>".
        if not value or "*" in value:
            return None
        try:
            return Domain(domain=value.rstrip("."))
        except Exception:
            return None

    @staticmethod
    def _ip_or_none(value: Any) -> Optional[Ip]:
        try:
            address = str(value).strip()
            ipaddress.ip_address(address)
            return Ip(address=address)
        except Exception:
            return None

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []

        self._record_links = []
        self._subdomain_links = []
        self._ip_links = []
        self._asn_links = []
        self._port_links = []

        api_key = self.get_secret("SHODAN_API_KEY", os.getenv("SHODAN_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "[SHODAN] SHODAN_API_KEY is not configured."},
            )
            return results

        params = self.params or {}
        history = self._as_bool(params.get("history"), False)
        record_type = str(params.get("record_type", "ALL")).upper()
        if record_type == "ALL":
            record_type = None

        max_pages = self._as_int(params.get("max_pages"), 1, 1, 100)
        enrich_host_ips = self._as_bool(params.get("enrich_host_ips"), True)
        max_host_lookups = self._as_int(
            params.get("max_host_lookups"), 25, 1, 1000
        )
        host_history = self._as_bool(params.get("host_history"), False)
        host_minify = self._as_bool(params.get("host_minify"), False)
        timeout = self._as_int(params.get("timeout"), 30, 1, 300)

        client = ShodanDomainClient(api_key=api_key, timeout=timeout)

        seen_records = set()
        seen_subdomain_links = set()
        seen_ip_links = set()

        # Unique IP objects used for the optional host pivot.
        ip_objects: Dict[str, Ip] = {}

        for root in data:
            Logger.info(
                self.sketch_id,
                {"message": f"[SHODAN] Looking up DNS intelligence for {root.domain}"},
            )

            for page in range(1, max_pages + 1):
                try:
                    payload = client.domain_info(
                        root.domain,
                        history=history,
                        record_type=record_type,
                        page=page,
                    )
                except Exception as exc:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": (
                                f"[SHODAN] Domain lookup failed for {root.domain} "
                                f"(page {page}): {exc}"
                            )
                        },
                    )
                    break

                records = payload.get("data") or []
                if not isinstance(records, list):
                    records = []

                for item in records:
                    if not isinstance(item, dict):
                        continue

                    rtype = str(item.get("type") or "").upper().strip()
                    value = item.get("value")
                    if not rtype or value is None:
                        continue

                    value_str = str(value).strip()
                    fqdn = self._fqdn(root.domain, item.get("subdomain"))

                    dedupe_key = (
                        root.domain.lower(),
                        fqdn.lower(),
                        rtype,
                        value_str,
                        item.get("last_seen"),
                    )
                    if dedupe_key in seen_records:
                        continue
                    seen_records.add(dedupe_key)

                    try:
                        record = DNSRecord(
                            value=value_str,
                            record_type=rtype,
                            last_seen=item.get("last_seen"),
                            source="Shodan",
                            associated_domains=[fqdn],
                            description=f"Shodan DNS observation for {fqdn}",
                        )
                    except Exception as exc:
                        Logger.warn(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[SHODAN] Could not model {rtype} record "
                                    f"{fqdn} -> {value_str}: {exc}"
                                )
                            },
                        )
                        continue

                    results.append(record)

                    fqdn_obj = self._domain_or_none(fqdn) or root
                    self._record_links.append((root, fqdn_obj, record))

                    if fqdn_obj.domain.lower() != root.domain.lower():
                        link_key = (root.domain.lower(), fqdn_obj.domain.lower())
                        if link_key not in seen_subdomain_links:
                            seen_subdomain_links.add(link_key)
                            self._subdomain_links.append((root, fqdn_obj))

                    if rtype in {"A", "AAAA"}:
                        ip_obj = self._ip_or_none(value_str)
                        if ip_obj:
                            existing = ip_objects.get(ip_obj.address)
                            if existing is None:
                                ip_objects[ip_obj.address] = ip_obj
                                existing = ip_obj

                            link_key = (fqdn_obj.domain.lower(), existing.address)
                            if link_key not in seen_ip_links:
                                seen_ip_links.add(link_key)
                                self._ip_links.append((fqdn_obj, existing))

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[SHODAN] {root.domain}: page {page}, "
                            f"{len(records)} DNS records"
                        )
                    },
                )

                if not payload.get("more"):
                    break

        if enrich_host_ips and ip_objects:
            addresses = list(ip_objects.keys())[:max_host_lookups]

            if len(ip_objects) > max_host_lookups:
                Logger.warn(
                    self.sketch_id,
                    {
                        "message": (
                            f"[SHODAN] Found {len(ip_objects)} unique IPs but "
                            f"host pivots are capped at {max_host_lookups}."
                        )
                    },
                )

            seen_asn_links = set()
            seen_port_links = set()

            for address in addresses:
                ip_obj = ip_objects[address]

                try:
                    host = client.host_info(
                        address,
                        history=host_history,
                        minify=host_minify,
                    )
                except Exception as exc:
                    Logger.warn(
                        self.sketch_id,
                        {
                            "message": (
                                f"[SHODAN] Host pivot failed for {address}: {exc}"
                            )
                        },
                    )
                    continue

                # Populate fields already supported by the Flowsint Ip type.
                ip_obj.latitude = host.get("latitude")
                ip_obj.longitude = host.get("longitude")
                ip_obj.country = host.get("country_name")
                ip_obj.city = host.get("city")
                ip_obj.isp = host.get("isp") or host.get("org")

                asn_str = host.get("asn")
                if asn_str:
                    try:
                        asn = ASN(
                            asn_str=str(asn_str),
                            name=host.get("org") or host.get("isp"),
                            country=host.get("country_code"),
                            description=host.get("isp") or host.get("org"),
                        )
                        key = (address, asn.asn_str)
                        if key not in seen_asn_links:
                            seen_asn_links.add(key)
                            self._asn_links.append((ip_obj, asn))
                    except Exception as exc:
                        Logger.warn(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[SHODAN] Could not model ASN {asn_str} "
                                    f"for {address}: {exc}"
                                )
                            },
                        )

                banners = host.get("data") or []
                modeled_ports = set()

                if isinstance(banners, list):
                    for banner in banners:
                        if not isinstance(banner, dict):
                            continue

                        port_number = banner.get("port")
                        try:
                            port_number = int(port_number)
                        except (TypeError, ValueError):
                            continue

                        protocol = str(
                            banner.get("transport") or "tcp"
                        ).upper()

                        product = banner.get("product")
                        version = banner.get("version")
                        module = None
                        if isinstance(banner.get("_shodan"), dict):
                            module = banner["_shodan"].get("module")

                        service = product or module
                        if product and version:
                            service = f"{product} {version}"

                        raw_banner = banner.get("data")
                        if raw_banner is not None:
                            raw_banner = str(raw_banner)
                            # Avoid creating unreasonably large Neo4j properties.
                            if len(raw_banner) > 8000:
                                raw_banner = raw_banner[:8000] + "…"

                        try:
                            port = Port(
                                number=port_number,
                                protocol=protocol,
                                state="open",
                                service=service,
                                banner=raw_banner,
                            )
                        except Exception:
                            continue

                        key = (address, port.number, port.protocol)
                        if key in seen_port_links:
                            continue

                        seen_port_links.add(key)
                        modeled_ports.add(port.number)
                        self._port_links.append((ip_obj, port))

                # A minified host response may have only the top-level ports list.
                for port_number in host.get("ports") or []:
                    try:
                        port_number = int(port_number)
                    except (TypeError, ValueError):
                        continue

                    if port_number in modeled_ports:
                        continue

                    try:
                        port = Port(
                            number=port_number,
                            protocol="TCP",
                            state="open",
                        )
                    except Exception:
                        continue

                    key = (address, port.number, port.protocol)
                    if key in seen_port_links:
                        continue

                    seen_port_links.add(key)
                    self._port_links.append((ip_obj, port))

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[SHODAN] Host pivot {address}: "
                            f"{len(host.get('ports') or [])} open ports"
                        )
                    },
                )

        return results

    def postprocess(
        self,
        results: List[OutputType],
        original_input: List[InputType] = None,
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for root, fqdn, record in self._record_links:
            self.create_node(root)
            self.create_node(fqdn)
            self.create_node(record)

            self.create_relationship(fqdn, record, "HAS_DNS_RECORD")

        for root, subdomain in self._subdomain_links:
            self.create_node(root)
            self.create_node(subdomain)
            self.create_relationship(root, subdomain, "HAS_SUBDOMAIN")

        for domain_obj, ip_obj in self._ip_links:
            self.create_node(domain_obj)
            self.create_node(ip_obj)
            self.create_relationship(domain_obj, ip_obj, "RESOLVES_TO")

        for ip_obj, asn in self._asn_links:
            self.create_node(ip_obj)
            self.create_node(asn)
            self.create_relationship(ip_obj, asn, "BELONGS_TO")

        for ip_obj, port in self._port_links:
            self.create_node(ip_obj)
            self.create_node(port)
            self.create_relationship(ip_obj, port, "HAS_PORT")

        self.log_graph_message(
            "[SHODAN] Added domain DNS intelligence and host pivots to the graph"
        )

        return results


InputType = DomainToShodanEnricher.InputType
OutputType = DomainToShodanEnricher.OutputType

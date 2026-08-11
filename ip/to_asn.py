import ipaddress
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR
from flowsint_types.ip import Ip


@flowsint_enricher
class IpToAsnEnricher(Enricher):
    """[TEAM CYMRU] Resolve an IP address to its BGP origin ASN using DNS."""

    InputType = Ip
    OutputType = ASN

    IPV4_ORIGIN_ZONE = "origin.asn.cymru.com"
    IPV6_ORIGIN_ZONE = "origin6.asn.cymru.com"
    ASN_ZONE = "asn.cymru.com"
    DNS_LIFETIME = 5.0

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault=None,
        params: Optional[Dict[str, Any]] = None,
        graph_service=None,
    ) -> None:
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
            graph_service=graph_service,
        )
        self.ip_asn_mapping: List[tuple[Ip, ASN]] = []
        self.resolver = dns.resolver.Resolver()

    @classmethod
    def name(cls) -> str:
        # Keep the existing enricher identifier so this is a drop-in replacement.
        return "ip_to_asn"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def documentation(cls) -> str:
        return """
        Resolve IPv4 and IPv6 addresses to their BGP origin Autonomous System
        using Team Cymru's public DNS IP-to-ASN service.

        Team Cymru DNS resolution is implemented directly in this enricher.
        No API key or auxiliary module is required.

        For each public IP, the enricher performs:

        1. An origin.asn.cymru.com/origin6.asn.cymru.com TXT lookup to obtain
           the BGP origin ASN and advertised prefix.
        2. An AS<NUMBER>.asn.cymru.com TXT lookup to obtain the ASN name and
           registry metadata.

        Non-global IP addresses are ignored.
        """

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self.ip_asn_mapping = []

        # Aggregate identical ASN nodes across the input while preserving every
        # IP -> ASN relationship separately.
        asns_by_number: Dict[int, ASN] = {}
        seen_relationships: set[tuple[str, int]] = set()

        for ip in data:
            try:
                records = self._lookup_ip(ip.address)
            except ValueError as exc:
                Logger.error(
                    self.sketch_id,
                    {"message": f"Invalid IP address {ip.address}: {exc}"},
                )
                continue
            except Exception as exc:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": (
                            f"[TEAM CYMRU] Error resolving ASN for "
                            f"{ip.address}: {exc}"
                        )
                    },
                )
                continue

            if not records:
                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[TEAM CYMRU] No public BGP origin ASN found "
                            f"for {ip.address}"
                        )
                    },
                )
                continue

            for record in records:
                asn_number = int(record["asn"])
                prefix = record.get("prefix")

                if asn_number not in asns_by_number:
                    cidrs = [CIDR(network=prefix)] if prefix else []
                    asns_by_number[asn_number] = ASN(
                        asn_str=f"AS{asn_number}",
                        number=asn_number,
                        name=record.get("asn_name"),
                        country=record.get("asn_country")
                        or record.get("prefix_country"),
                        description=record.get("asn_name"),
                        cidrs=cidrs,
                    )
                elif prefix:
                    asn = asns_by_number[asn_number]
                    existing_cidrs = {str(cidr.network) for cidr in asn.cidrs}
                    if prefix not in existing_cidrs:
                        asn.cidrs.append(CIDR(network=prefix))

                asn = asns_by_number[asn_number]
                relationship_key = (ip.address, asn_number)
                if relationship_key not in seen_relationships:
                    seen_relationships.add(relationship_key)
                    self.ip_asn_mapping.append((ip, asn))

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[TEAM CYMRU] {ip.address} -> {asn.asn_str} "
                            f"({asn.name or 'unknown'})"
                            + (f" via {prefix}" if prefix else "")
                        )
                    },
                )

        return list(asns_by_number.values())

    def postprocess(
        self,
        results: List[OutputType],
        input_data: List[InputType] = None,
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        created_asns: set[str] = set()

        for ip, asn in self.ip_asn_mapping:
            self.create_node(ip)

            if asn.asn_str not in created_asns:
                self.create_node(asn)
                created_asns.add(asn.asn_str)

            self.create_relationship(ip, asn, "BELONGS_TO")
            self.log_graph_message(
                f"IP {ip.address} belongs to {asn.asn_str}"
                + (f" ({asn.name})" if asn.name else "")
            )

        return results

    def _lookup_ip(self, value: str) -> List[Dict[str, Any]]:
        """Resolve one IP address through Team Cymru's DNS service."""
        address = ipaddress.ip_address(value.strip())

        # Private, loopback, link-local, reserved, multicast, etc. do not have a
        # meaningful public BGP origin ASN.
        if not address.is_global:
            return []

        query_name = self._origin_query_name(address)
        origin_records = self._resolve_txt(query_name)
        results: List[Dict[str, Any]] = []

        for record in origin_records:
            origin = self._parse_origin_record(record)
            if not origin:
                continue

            for asn_number in origin["asns"]:
                asn_info = self._lookup_asn(asn_number)
                results.append(
                    {
                        "asn": asn_number,
                        "prefix": origin["prefix"],
                        "prefix_country": origin["country"],
                        "prefix_registry": origin["registry"],
                        "prefix_allocated": origin["allocated"],
                        "asn_country": asn_info.get("country"),
                        "asn_registry": asn_info.get("registry"),
                        "asn_allocated": asn_info.get("allocated"),
                        "asn_name": asn_info.get("name"),
                    }
                )

        return self._deduplicate(results)

    def _origin_query_name(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> str:
        if isinstance(address, ipaddress.IPv4Address):
            reversed_octets = ".".join(reversed(str(address).split(".")))
            return f"{reversed_octets}.{self.IPV4_ORIGIN_ZONE}"

        # Team Cymru's IPv6 service expects the fully expanded address reversed
        # nibble-by-nibble.
        nibbles = address.exploded.replace(":", "")
        reversed_nibbles = ".".join(reversed(nibbles))
        return f"{reversed_nibbles}.{self.IPV6_ORIGIN_ZONE}"

    def _lookup_asn(self, asn_number: int) -> Dict[str, Optional[str]]:
        records = self._resolve_txt(f"AS{asn_number}.{self.ASN_ZONE}")
        for record in records:
            parsed = self._parse_asn_record(record)
            if parsed:
                return parsed

        return {
            "country": None,
            "registry": None,
            "allocated": None,
            "name": None,
        }

    def _resolve_txt(self, query_name: str) -> List[str]:
        try:
            answer = self.resolver.resolve(
                query_name,
                "TXT",
                lifetime=self.DNS_LIFETIME,
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ) as exc:
            raise RuntimeError(
                f"DNS lookup failed for {query_name}: {exc}"
            ) from exc

        records: List[str] = []
        for rdata in answer:
            # dnspython may expose a TXT record as one or several byte strings.
            if hasattr(rdata, "strings"):
                text = b"".join(rdata.strings).decode(
                    "utf-8",
                    errors="replace",
                )
            else:
                text = rdata.to_text().strip('"')

            records.append(text.strip())

        return records

    @staticmethod
    def _parse_origin_record(record: str) -> Optional[Dict[str, Any]]:
        # origin/origin6 format:
        # ASN | BGP Prefix | CC | Registry | Allocated
        parts = [part.strip() for part in record.split("|")]
        if len(parts) < 5:
            return None

        asns: List[int] = []
        for token in parts[0].split():
            token = token.upper().removeprefix("AS")
            if token.isdigit():
                asns.append(int(token))

        if not asns:
            return None

        return {
            "asns": asns,
            "prefix": parts[1] or None,
            "country": parts[2] or None,
            "registry": parts[3] or None,
            "allocated": parts[4] or None,
        }

    @staticmethod
    def _parse_asn_record(record: str) -> Optional[Dict[str, Optional[str]]]:
        # ASN detail format:
        # ASN | CC | Registry | Allocated | AS Name
        parts = [part.strip() for part in record.split("|", 4)]
        if len(parts) < 5:
            return None

        return {
            "country": parts[1] or None,
            "registry": parts[2] or None,
            "allocated": parts[3] or None,
            "name": parts[4] or None,
        }

    @staticmethod
    def _deduplicate(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set[tuple[int, Optional[str]]] = set()
        unique: List[Dict[str, Any]] = []

        for record in records:
            key = (record["asn"], record.get("prefix"))
            if key in seen:
                continue

            seen.add(key)
            unique.append(record)

        return unique


InputType = IpToAsnEnricher.InputType
OutputType = IpToAsnEnricher.OutputType

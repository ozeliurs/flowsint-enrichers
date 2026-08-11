from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR
from flowsint_types.ip import Ip
from tools.network.team_cymru import TeamCymruDnsTool


@flowsint_enricher
class IpToAsnEnricher(Enricher):
    """[TEAM CYMRU] Resolve an IP address to its BGP origin ASN using DNS."""

    InputType = Ip
    OutputType = ASN

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

        The enricher performs two DNS lookups:

        1. The Team Cymru origin/origin6 zone maps the IP to its BGP prefix and
           origin ASN.
        2. The Team Cymru ASN zone adds the ASN name and registry metadata.

        No API key is required. Non-global IP addresses are ignored.
        """

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        tool = TeamCymruDnsTool()
        self.ip_asn_mapping = []

        # Aggregate identical ASN nodes across the input while preserving every
        # IP -> ASN relationship separately.
        asns_by_number: Dict[int, ASN] = {}
        seen_relationships: set[tuple[str, int]] = set()

        for ip in data:
            try:
                records = tool.launch(ip.address)
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


InputType = IpToAsnEnricher.InputType
OutputType = IpToAsnEnricher.OutputType

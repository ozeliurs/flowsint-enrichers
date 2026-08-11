from collections import defaultdict
from typing import Any, Dict, List, Literal, Tuple

import httpx
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.dns_record import DNSRecord
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


SUPPORTED_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
GEONET_BASE_URL = "https://geonet.shodan.io/api/geodns"


class GeoNetLocation(BaseModel):
    city: str | None = None
    country: str | None = None
    latlon: str | None = None


class GeoNetRecord(BaseModel):
    """
    A unique GeoNet DNS answer and every geographic vantage point
    that observed it.
    """

    domain: str
    record_type: Literal["A", "AAAA", "MX", "NS", "TXT"]
    value: str
    locations: List[GeoNetLocation] = Field(default_factory=list)


@flowsint_enricher
class DomainToGeoNetShodanEnricher(Enricher):
    """
    Resolve DNS records through Shodan GeoNet.

    The enricher queries:
      - A
      - AAAA
      - MX
      - NS
      - TXT

    Results returned by multiple GeoNet locations are deduplicated.

    Graph mapping:
      A/AAAA -> Ip
      MX/NS  -> Domain
      TXT    -> DNSRecord
    """

    InputType = Domain
    OutputType = GeoNetRecord

    @classmethod
    def name(cls) -> str:
        return "domain_to_geonet_shodan"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def documentation(cls) -> str:
        return """
        Query Shodan GeoNet for A, AAAA, MX, NS and TXT records.

        GeoNet performs DNS lookups from several geographic locations.
        Identical answers are deduplicated while preserving all geographic
        vantage points that observed each result.

        Graph output:

          A / AAAA -> Ip
                      RESOLVES_TO

          MX       -> Domain
                      HAS_MAIL_EXCHANGER

          NS       -> Domain
                      HAS_NAMESERVER

          TXT      -> DNSRecord
                      HAS_TXT_RECORD

        GeoNet metadata is added to generated target nodes through:

          geonet_source
          geonet_record_types
          geonet_observations
        """

    async def scan(
        self,
        data: List[InputType],
    ) -> List[OutputType]:
        results: List[OutputType] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
            headers={
                "accept": "application/json",
            },
        ) as client:
            for domain_obj in data:
                unique_records: Dict[
                    Tuple[str, str],
                    Dict[str, Any],
                ] = {}

                for requested_type in SUPPORTED_RECORD_TYPES:
                    try:
                        response = await client.get(
                            f"{GEONET_BASE_URL}/{domain_obj.domain}",
                            params={
                                "rtype": requested_type,
                            },
                        )

                        response.raise_for_status()

                        payload = response.json()

                        if not isinstance(payload, list):
                            raise ValueError(
                                "Unexpected GeoNet response type: "
                                f"{type(payload).__name__}"
                            )

                    except (httpx.HTTPError, ValueError) as exc:
                        Logger.error(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[Shodan GeoNet] Failed "
                                    f"{requested_type} lookup for "
                                    f"{domain_obj.domain}: {exc}"
                                )
                            },
                        )

                        continue

                    for observation in payload:
                        if not isinstance(observation, dict):
                            continue

                        location = self._parse_location(
                            observation.get("from_loc")
                        )

                        answers = observation.get("answers", [])

                        if not isinstance(answers, list):
                            continue

                        for answer in answers:
                            if not isinstance(answer, dict):
                                continue

                            record_type = str(
                                answer.get("type") or requested_type
                            ).upper()

                            if record_type not in SUPPORTED_RECORD_TYPES:
                                continue

                            raw_value = answer.get("value")

                            if raw_value is None:
                                continue

                            value = self._normalize_value(
                                record_type,
                                str(raw_value),
                            )

                            if not value:
                                continue

                            # The same answer is normally returned by several
                            # GeoNet geographic probes.
                            record_key = (
                                record_type,
                                value,
                            )

                            if record_key not in unique_records:
                                unique_records[record_key] = {
                                    "record_type": record_type,
                                    "value": value,
                                    "locations": {},
                                }

                            if location is not None:
                                location_key = (
                                    location.city or "",
                                    location.country or "",
                                    location.latlon or "",
                                )

                                unique_records[
                                    record_key
                                ]["locations"][location_key] = location

                domain_records = []

                for _, entry in sorted(unique_records.items()):
                    locations = [
                        entry["locations"][location_key]
                        for location_key in sorted(
                            entry["locations"]
                        )
                    ]

                    domain_records.append(
                        GeoNetRecord(
                            domain=domain_obj.domain,
                            record_type=entry["record_type"],
                            value=entry["value"],
                            locations=locations,
                        )
                    )

                results.extend(domain_records)

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[Shodan GeoNet] {domain_obj.domain}: "
                            f"{len(domain_records)} unique DNS answers "
                            f"across "
                            f"{', '.join(SUPPORTED_RECORD_TYPES)}"
                        )
                    },
                )

        return results

    def postprocess(
        self,
        results: List[OutputType],
        input_data: List[InputType] = None,
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        nodes: Dict[
            Tuple[str, str],
            Any,
        ] = {}

        relationships: set[
            Tuple[
                Tuple[str, str],
                Tuple[str, str],
                str,
            ]
        ] = set()

        record_types_by_node: Dict[
            Tuple[str, str],
            set[str],
        ] = defaultdict(set)

        observations_by_node: Dict[
            Tuple[str, str],
            set[str],
        ] = defaultdict(set)

        source_domains_by_node: Dict[
            Tuple[str, str],
            set[str],
        ] = defaultdict(set)

        #
        # Seed input Domain nodes.
        #
        for domain_obj in input_data or []:
            source_key = (
                "Domain",
                domain_obj.domain,
            )

            nodes.setdefault(
                source_key,
                domain_obj,
            )

        #
        # Build unique graph nodes + relationships.
        #
        for result in results:
            source = Domain(
                domain=result.domain
            )

            source_key = (
                "Domain",
                source.domain,
            )

            nodes.setdefault(
                source_key,
                source,
            )

            target = self._record_to_node(
                result
            )

            target_key = self._node_key(
                target
            )

            #
            # Node deduplication happens here.
            #
            nodes.setdefault(
                target_key,
                target,
            )

            record_types_by_node[
                target_key
            ].add(
                result.record_type
            )

            source_domains_by_node[
                target_key
            ].add(
                result.domain
            )

            for location in result.locations:
                observations_by_node[
                    target_key
                ].add(
                    self._format_observation(
                        result.domain,
                        location,
                    )
                )

            relationships.add(
                (
                    source_key,
                    target_key,
                    self._relationship_for_type(
                        result.record_type
                    ),
                )
            )

        #
        # Create nodes once all duplicate observations have been merged.
        #
        for node_key, node in nodes.items():
            record_types = record_types_by_node.get(
                node_key
            )

            if record_types:
                #
                # FlowsintType allows extra properties, so this metadata
                # can be stored directly on Ip / Domain / DNSRecord nodes.
                #
                setattr(
                    node,
                    "geonet_source",
                    "Shodan GeoNet",
                )

                setattr(
                    node,
                    "geonet_record_types",
                    sorted(record_types),
                )

                setattr(
                    node,
                    "geonet_observations",
                    sorted(
                        observations_by_node.get(
                            node_key,
                            set(),
                        )
                    ),
                )

                #
                # DNSRecord uses value as its primary identifier.
                # Aggregate domains/types if the same TXT value appears
                # more than once.
                #
                if isinstance(node, DNSRecord):
                    node.record_type = ",".join(
                        sorted(record_types)
                    )

                    node.source = "Shodan GeoNet"

                    node.associated_domains = sorted(
                        source_domains_by_node.get(
                            node_key,
                            set(),
                        )
                    )

            self.create_node(node)

        #
        # Create unique relationships.
        #
        for (
            source_key,
            target_key,
            relationship,
        ) in sorted(relationships):
            source = nodes[source_key]
            target = nodes[target_key]

            self.create_relationship(
                source,
                target,
                relationship,
            )

            self.log_graph_message(
                f"[Shodan GeoNet] "
                f"{source.domain} "
                f"-[{relationship}]-> "
                f"{self._node_label(target)}"
            )

        return results

    @staticmethod
    def _parse_location(
        value: Any,
    ) -> GeoNetLocation | None:
        if not isinstance(value, dict):
            return None

        location = GeoNetLocation(
            city=value.get("city"),
            country=value.get("country"),
            latlon=value.get("latlon"),
        )

        if not any(
            (
                location.city,
                location.country,
                location.latlon,
            )
        ):
            return None

        return location

    @staticmethod
    def _normalize_value(
        record_type: str,
        value: str,
    ) -> str:
        value = value.strip()

        #
        # GeoNet returns MX / NS domains as FQDNs ending in "."
        #
        # Example:
        #
        #   aspmx.l.google.com.
        #
        if (
            record_type in {"MX", "NS"}
            and value.endswith(".")
            and value != "."
        ):
            value = value[:-1]

        return value

    @staticmethod
    def _record_to_node(
        record: GeoNetRecord,
    ) -> Any:
        #
        # A / AAAA
        #
        if record.record_type in {
            "A",
            "AAAA",
        }:
            try:
                return Ip(
                    address=record.value
                )
            except ValueError:
                pass

        #
        # MX / NS
        #
        if record.record_type in {
            "MX",
            "NS",
        }:
            try:
                return Domain(
                    domain=record.value
                )
            except ValueError:
                pass

        #
        # TXT normally lands here.
        #
        # We also preserve malformed/unusual responses rather than
        # silently throwing them away.
        #
        return DNSRecord(
            value=record.value,
            record_type=record.record_type,
            source="Shodan GeoNet",
            associated_domains=[
                record.domain
            ],
        )

    @staticmethod
    def _relationship_for_type(
        record_type: str,
    ) -> str:
        relationships = {
            "A": "RESOLVES_TO",
            "AAAA": "RESOLVES_TO",
            "MX": "HAS_MAIL_EXCHANGER",
            "NS": "HAS_NAMESERVER",
            "TXT": "HAS_TXT_RECORD",
        }

        return relationships[
            record_type
        ]

    @staticmethod
    def _node_key(
        node: Any,
    ) -> Tuple[str, str]:
        if isinstance(node, Ip):
            return (
                "Ip",
                node.address,
            )

        if isinstance(node, Domain):
            return (
                "Domain",
                node.domain,
            )

        if isinstance(node, DNSRecord):
            return (
                "DNSRecord",
                node.value,
            )

        raise TypeError(
            f"Unsupported graph node type: "
            f"{type(node).__name__}"
        )

    @staticmethod
    def _format_observation(
        domain: str,
        location: GeoNetLocation,
    ) -> str:
        location_parts = [
            part
            for part in (
                location.city,
                location.country,
                location.latlon,
            )
            if part
        ]

        return (
            f"{domain} | "
            f"{' | '.join(location_parts)}"
        )

    @staticmethod
    def _node_label(
        node: Any,
    ) -> str:
        if isinstance(node, Ip):
            return node.address

        if isinstance(node, Domain):
            return node.domain

        if isinstance(node, DNSRecord):
            return node.value

        return str(node)


InputType = DomainToGeoNetShodanEnricher.InputType
OutputType = DomainToGeoNetShodanEnricher.OutputType

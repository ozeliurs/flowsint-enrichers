from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.dns_record import DNSRecord
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


SHODAN_DOMAIN_URL = "https://api.shodan.io/dns/domain"

# Defensive limit against a broken/looping API response.
MAX_PAGES = 1000


class ShodanDNSRecord(BaseModel):
    subdomain: str = ""
    record_type: str
    value: str
    options: Dict[str, Any] = Field(default_factory=dict)
    last_seen: Optional[str] = None


class ShodanDomainLookup(BaseModel):
    domain: str
    tags: List[str] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    records: List[ShodanDNSRecord] = Field(default_factory=list)


@flowsint_enricher
class DomainToShodanDomainEnricher(Enricher):
    """
    Query Shodan DNSDB for all known DNS information about a domain.

    Graph model:

        example.com
            |
            +-- HAS_SUBDOMAIN --> www.example.com
            |                         |
            |                         +-- RESOLVES_TO --> 1.2.3.4
            |
            +-- HAS_MX_RECORD --> DNSRecord
                                    |
                                    +-- POINTS_TO --> mail.example.com

        A / AAAA -> Ip
        CNAME    -> Domain
        MX       -> DNSRecord -> Domain
        NS       -> DNSRecord -> Domain
        SOA      -> DNSRecord -> Domain
        TXT      -> DNSRecord

    Results and graph entities are deduplicated.
    """

    InputType = Domain
    OutputType = ShodanDomainLookup

    @classmethod
    def name(cls) -> str:
        return "domain_to_shodan_domain"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "SHODAN_API_KEY",
                "type": "vaultSecret",
                "description": "Shodan API key.",
                "required": True,
            }
        ]

    @classmethod
    def documentation(cls) -> str:
        return """
        Query Shodan's DNS domain database.

        API endpoint:

            GET https://api.shodan.io/dns/domain/{domain}

        SHODAN_API_KEY is retrieved from the Flowsint vault.

        Pagination is followed automatically until Shodan returns:

            "more": false

        Supported Shodan DNS records include:

            A
            AAAA
            CNAME
            MX
            NS
            SOA
            TXT

        Standard hostname labels are represented as Flowsint Domain nodes.

        DNS owners that cannot be represented by Flowsint's Domain type,
        such as:

            *.example.com
            _dmarc.example.com

        are still preserved in DNSRecord metadata.
        """

    async def scan(
        self,
        data: List[InputType],
    ) -> List[OutputType]:
        api_key = self.get_secret("SHODAN_API_KEY")

        if not api_key:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        "[Shodan] SHODAN_API_KEY is missing "
                        "from the vault."
                    )
                },
            )
            return []

        results: List[OutputType] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,
            headers={
                "accept": "application/json",
            },
        ) as client:
            for domain_obj in data:
                domain = domain_obj.domain.lower()

                tags: set[str] = set()
                subdomains: set[str] = set()

                #
                # Dedupe key:
                #
                #   owner + type + value
                #
                unique_records: Dict[
                    Tuple[str, str, str],
                    ShodanDNSRecord,
                ] = {}

                page = 1

                while page <= MAX_PAGES:
                    try:
                        response = await client.get(
                            f"{SHODAN_DOMAIN_URL}/{domain}",
                            params={
                                "key": api_key,
                                "page": page,
                            },
                        )

                    except httpx.HTTPError as exc:
                        #
                        # Don't log the request URL here:
                        # it contains the Shodan API key.
                        #
                        Logger.error(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[Shodan] Network error for "
                                    f"{domain} page {page}: "
                                    f"{type(exc).__name__}"
                                )
                            },
                        )
                        break

                    if response.status_code >= 400:
                        error = self._get_api_error(
                            response
                        )

                        message = (
                            f"[Shodan] Lookup failed for "
                            f"{domain} page {page}: "
                            f"HTTP {response.status_code}"
                        )

                        if error:
                            message += f" - {error}"

                        Logger.error(
                            self.sketch_id,
                            {
                                "message": message
                            },
                        )
                        break

                    try:
                        payload = response.json()
                    except ValueError:
                        Logger.error(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[Shodan] Invalid JSON "
                                    f"response for {domain} "
                                    f"page {page}."
                                )
                            },
                        )
                        break

                    if not isinstance(
                        payload,
                        dict,
                    ):
                        Logger.error(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[Shodan] Unexpected "
                                    f"response for {domain}."
                                )
                            },
                        )
                        break

                    #
                    # Tags
                    #
                    payload_tags = payload.get(
                        "tags",
                        [],
                    )

                    if isinstance(
                        payload_tags,
                        list,
                    ):
                        tags.update(
                            str(tag)
                            for tag in payload_tags
                            if tag is not None
                        )

                    #
                    # Subdomains
                    #
                    payload_subdomains = payload.get(
                        "subdomains",
                        [],
                    )

                    if isinstance(
                        payload_subdomains,
                        list,
                    ):
                        subdomains.update(
                            str(subdomain)
                            for subdomain in payload_subdomains
                            if subdomain is not None
                        )

                    #
                    # DNS records
                    #
                    page_data = payload.get(
                        "data",
                        [],
                    )

                    if not isinstance(
                        page_data,
                        list,
                    ):
                        page_data = []

                    for raw_record in page_data:
                        if not isinstance(
                            raw_record,
                            dict,
                        ):
                            continue

                        record_type = str(
                            raw_record.get("type")
                            or ""
                        ).upper().strip()

                        raw_value = raw_record.get(
                            "value"
                        )

                        if (
                            not record_type
                            or raw_value is None
                        ):
                            continue

                        subdomain = str(
                            raw_record.get(
                                "subdomain"
                            )
                            or ""
                        ).strip()

                        value = (
                            self._normalize_value(
                                record_type,
                                str(raw_value),
                            )
                        )

                        if not value:
                            continue

                        options = raw_record.get(
                            "options"
                        )

                        if not isinstance(
                            options,
                            dict,
                        ):
                            options = {}

                        last_seen = raw_record.get(
                            "last_seen"
                        )

                        if last_seen is not None:
                            last_seen = str(
                                last_seen
                            )

                        record_key = (
                            subdomain,
                            record_type,
                            value,
                        )

                        new_record = (
                            ShodanDNSRecord(
                                subdomain=subdomain,
                                record_type=record_type,
                                value=value,
                                options=options,
                                last_seen=last_seen,
                            )
                        )

                        existing = (
                            unique_records.get(
                                record_key
                            )
                        )

                        if existing is None:
                            unique_records[
                                record_key
                            ] = new_record

                        else:
                            #
                            # Duplicate observation:
                            # keep newest last_seen.
                            #
                            if (
                                new_record.last_seen
                                and (
                                    not existing.last_seen
                                    or new_record.last_seen
                                    > existing.last_seen
                                )
                            ):
                                existing.last_seen = (
                                    new_record.last_seen
                                )

                            existing.options.update(
                                new_record.options
                            )

                    more = bool(
                        payload.get(
                            "more",
                            False,
                        )
                    )

                    if not more:
                        break

                    #
                    # Prevent a possible endless loop
                    # if Shodan behaves unexpectedly.
                    #
                    if not page_data:
                        Logger.error(
                            self.sketch_id,
                            {
                                "message": (
                                    f"[Shodan] {domain} "
                                    f"returned more=true but "
                                    f"page {page} was empty. "
                                    f"Pagination stopped."
                                )
                            },
                        )
                        break

                    page += 1

                if page > MAX_PAGES:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": (
                                f"[Shodan] Pagination limit "
                                f"of {MAX_PAGES} pages reached "
                                f"for {domain}."
                            )
                        },
                    )

                records = sorted(
                    unique_records.values(),
                    key=lambda record: (
                        record.subdomain,
                        record.record_type,
                        record.value,
                    ),
                )

                lookup = ShodanDomainLookup(
                    domain=domain,
                    tags=sorted(tags),
                    subdomains=sorted(
                        subdomains
                    ),
                    records=records,
                )

                results.append(
                    lookup
                )

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[Shodan] {domain}: "
                            f"{len(lookup.subdomains)} "
                            f"subdomains, "
                            f"{len(lookup.records)} "
                            f"unique DNS records."
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

        observations: Dict[
            Tuple[str, str],
            set[str],
        ] = defaultdict(set)

        owners: Dict[
            Tuple[str, str],
            set[str],
        ] = defaultdict(set)

        record_types: Dict[
            Tuple[str, str],
            set[str],
        ] = defaultdict(set)

        last_seen: Dict[
            Tuple[str, str],
            str,
        ] = {}

        #
        # Seed input Domain nodes.
        #
        for domain_obj in input_data or []:
            domain_node = Domain(
                domain=domain_obj.domain.lower()
            )

            nodes.setdefault(
                self._node_key(
                    domain_node
                ),
                domain_node,
            )

        for lookup in results:
            root = Domain(
                domain=lookup.domain
            )

            root_key = self._node_key(
                root
            )

            nodes.setdefault(
                root_key,
                root,
            )

            setattr(
                nodes[root_key],
                "shodan_source",
                "Shodan DNSDB",
            )

            setattr(
                nodes[root_key],
                "shodan_tags",
                lookup.tags,
            )

            #
            # Create the subdomain nodes from
            # Shodan's subdomains array.
            #
            for subdomain in lookup.subdomains:
                fqdn = self._fqdn(
                    lookup.domain,
                    subdomain,
                )

                child = self._safe_domain(
                    fqdn
                )

                #
                # Flowsint Domain doesn't support
                # wildcard / underscore DNS labels.
                #
                if child is None:
                    continue

                child_key = self._node_key(
                    child
                )

                nodes.setdefault(
                    child_key,
                    child,
                )

                setattr(
                    nodes[child_key],
                    "shodan_source",
                    "Shodan DNSDB",
                )

                if child_key != root_key:
                    relationships.add(
                        (
                            root_key,
                            child_key,
                            "HAS_SUBDOMAIN",
                        )
                    )

            #
            # DNS records
            #
            for record in lookup.records:
                owner_fqdn = self._fqdn(
                    lookup.domain,
                    record.subdomain,
                )

                owner_node = self._safe_domain(
                    owner_fqdn
                )

                #
                # _dmarc.example.com and *.example.com,
                # for example, cannot be Domain nodes.
                #
                if owner_node is None:
                    source_key = root_key

                else:
                    source_key = self._node_key(
                        owner_node
                    )

                    nodes.setdefault(
                        source_key,
                        owner_node,
                    )

                    setattr(
                        nodes[source_key],
                        "shodan_source",
                        "Shodan DNSDB",
                    )

                    if source_key != root_key:
                        relationships.add(
                            (
                                root_key,
                                source_key,
                                "HAS_SUBDOMAIN",
                            )
                        )

                observation = (
                    self._format_observation(
                        owner_fqdn,
                        record,
                    )
                )

                #
                # A / AAAA
                #
                if record.record_type in {
                    "A",
                    "AAAA",
                }:
                    target = self._safe_ip(
                        record.value
                    )

                    if target is None:
                        target = (
                            self._dns_record(
                                record
                            )
                        )

                        relationship = (
                            "HAS_DNS_RECORD"
                        )

                    else:
                        relationship = (
                            "WILDCARD_RESOLVES_TO"
                            if "*"
                            in record.subdomain
                            else "RESOLVES_TO"
                        )

                    target_key = (
                        self._node_key(
                            target
                        )
                    )

                    nodes.setdefault(
                        target_key,
                        target,
                    )

                    self._collect_metadata(
                        target_key,
                        owner_fqdn,
                        record,
                        observation,
                        observations,
                        owners,
                        record_types,
                        last_seen,
                    )

                    relationships.add(
                        (
                            source_key,
                            target_key,
                            relationship,
                        )
                    )

                    continue

                #
                # CNAME
                #
                if record.record_type == "CNAME":
                    target = (
                        self._safe_domain(
                            record.value
                        )
                    )

                    if target is None:
                        target = (
                            self._dns_record(
                                record
                            )
                        )

                        relationship = (
                            "HAS_CNAME_RECORD"
                        )

                    else:
                        relationship = (
                            "CNAME_TO"
                        )

                    target_key = (
                        self._node_key(
                            target
                        )
                    )

                    nodes.setdefault(
                        target_key,
                        target,
                    )

                    self._collect_metadata(
                        target_key,
                        owner_fqdn,
                        record,
                        observation,
                        observations,
                        owners,
                        record_types,
                        last_seen,
                    )

                    relationships.add(
                        (
                            source_key,
                            target_key,
                            relationship,
                        )
                    )

                    continue

                #
                # Everything else becomes a
                # native Flowsint DNSRecord.
                #
                dns_record = self._dns_record(
                    record
                )

                dns_key = self._node_key(
                    dns_record
                )

                nodes.setdefault(
                    dns_key,
                    dns_record,
                )

                self._collect_metadata(
                    dns_key,
                    owner_fqdn,
                    record,
                    observation,
                    observations,
                    owners,
                    record_types,
                    last_seen,
                )

                relationships.add(
                    (
                        source_key,
                        dns_key,
                        self._record_relationship(
                            record.record_type
                        ),
                    )
                )

                #
                # MX / NS / SOA values are normally
                # useful Domain pivots too.
                #
                if record.record_type in {
                    "MX",
                    "NS",
                    "SOA",
                }:
                    target = self._safe_domain(
                        record.value
                    )

                    if target is not None:
                        target_key = (
                            self._node_key(
                                target
                            )
                        )

                        nodes.setdefault(
                            target_key,
                            target,
                        )

                        setattr(
                            nodes[target_key],
                            "shodan_source",
                            "Shodan DNSDB",
                        )

                        relationship = (
                            "PRIMARY_NAMESERVER"
                            if record.record_type
                            == "SOA"
                            else "POINTS_TO"
                        )

                        relationships.add(
                            (
                                dns_key,
                                target_key,
                                relationship,
                            )
                        )

        #
        # Merge metadata after node deduplication.
        #
        for node_key, node in nodes.items():
            node_observations = observations.get(
                node_key
            )

            if node_observations:
                setattr(
                    node,
                    "shodan_source",
                    "Shodan DNSDB",
                )

                setattr(
                    node,
                    "shodan_dns_observations",
                    sorted(
                        node_observations
                    ),
                )

            if isinstance(
                node,
                DNSRecord,
            ):
                types = record_types.get(
                    node_key
                )

                if types:
                    node.record_type = ",".join(
                        sorted(types)
                    )

                associated = owners.get(
                    node_key
                )

                if associated:
                    node.associated_domains = (
                        sorted(associated)
                    )

                if node_key in last_seen:
                    node.last_seen = (
                        last_seen[node_key]
                    )

            self.create_node(
                node
            )

        #
        # Create relationships once.
        #
        for (
            source_key,
            target_key,
            relationship,
        ) in sorted(relationships):
            source = nodes[
                source_key
            ]

            target = nodes[
                target_key
            ]

            self.create_relationship(
                source,
                target,
                relationship,
            )

            self.log_graph_message(
                f"[Shodan] "
                f"{self._node_label(source)} "
                f"-[{relationship}]-> "
                f"{self._node_label(target)}"
            )

        return results

    @staticmethod
    def _get_api_error(
        response: httpx.Response,
    ) -> Optional[str]:
        try:
            payload = response.json()
        except ValueError:
            return None

        if isinstance(
            payload,
            dict,
        ):
            error = payload.get(
                "error"
            )

            if error is not None:
                return str(
                    error
                )

        return None

    @staticmethod
    def _fqdn(
        root_domain: str,
        subdomain: str,
    ) -> str:
        subdomain = subdomain.strip()

        if not subdomain:
            return root_domain

        return (
            f"{subdomain}."
            f"{root_domain}"
        )

    @staticmethod
    def _normalize_value(
        record_type: str,
        value: str,
    ) -> str:
        value = value.strip()

        domain_types = {
            "CNAME",
            "MX",
            "NS",
            "SOA",
        }

        if (
            record_type in domain_types
            and value.endswith(".")
            and value != "."
        ):
            value = value[:-1]

        if record_type in domain_types:
            value = value.lower()

        return value

    @staticmethod
    def _safe_domain(
        value: str,
    ) -> Optional[Domain]:
        try:
            return Domain(
                domain=value
            )
        except ValueError:
            return None

    @staticmethod
    def _safe_ip(
        value: str,
    ) -> Optional[Ip]:
        try:
            return Ip(
                address=value
            )
        except ValueError:
            return None

    @staticmethod
    def _dns_record(
        record: ShodanDNSRecord,
    ) -> DNSRecord:
        return DNSRecord(
            value=record.value,
            record_type=record.record_type,
            ttl=(
                DomainToShodanDomainEnricher
                ._to_int(
                    record.options.get(
                        "ttl"
                    )
                )
            ),
            priority=(
                DomainToShodanDomainEnricher
                ._to_int(
                    record.options.get(
                        "priority"
                    )
                )
            ),
            last_seen=record.last_seen,
            source="Shodan DNSDB",
        )

    @staticmethod
    def _record_relationship(
        record_type: str,
    ) -> str:
        mapping = {
            "MX": "HAS_MX_RECORD",
            "NS": "HAS_NS_RECORD",
            "SOA": "HAS_SOA_RECORD",
            "TXT": "HAS_TXT_RECORD",
        }

        return mapping.get(
            record_type,
            "HAS_DNS_RECORD",
        )

    @staticmethod
    def _collect_metadata(
        node_key: Tuple[str, str],
        owner: str,
        record: ShodanDNSRecord,
        observation: str,
        observations: Dict[
            Tuple[str, str],
            set[str],
        ],
        owners: Dict[
            Tuple[str, str],
            set[str],
        ],
        record_types: Dict[
            Tuple[str, str],
            set[str],
        ],
        last_seen: Dict[
            Tuple[str, str],
            str,
        ],
    ) -> None:
        observations[
            node_key
        ].add(
            observation
        )

        owners[
            node_key
        ].add(
            owner
        )

        record_types[
            node_key
        ].add(
            record.record_type
        )

        if record.last_seen:
            previous = last_seen.get(
                node_key
            )

            if (
                previous is None
                or record.last_seen
                > previous
            ):
                last_seen[
                    node_key
                ] = record.last_seen

    @staticmethod
    def _format_observation(
        owner: str,
        record: ShodanDNSRecord,
    ) -> str:
        parts = [
            owner,
            record.record_type,
            record.value,
        ]

        for key in (
            "ttl",
            "priority",
            "serial",
            "refresh",
            "retry",
            "expires",
            "minttl",
            "hostmaster",
        ):
            value = record.options.get(
                key
            )

            if value is not None:
                parts.append(
                    f"{key}={value}"
                )

        if record.last_seen:
            parts.append(
                f"last_seen="
                f"{record.last_seen}"
            )

        return " | ".join(
            parts
        )

    @staticmethod
    def _to_int(
        value: Any,
    ) -> Optional[int]:
        if value is None:
            return None

        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _node_key(
        node: Any,
    ) -> Tuple[str, str]:
        if isinstance(
            node,
            Ip,
        ):
            return (
                "Ip",
                node.address,
            )

        if isinstance(
            node,
            Domain,
        ):
            return (
                "Domain",
                node.domain,
            )

        if isinstance(
            node,
            DNSRecord,
        ):
            return (
                "DNSRecord",
                node.value,
            )

        raise TypeError(
            f"Unsupported graph node: "
            f"{type(node).__name__}"
        )

    @staticmethod
    def _node_label(
        node: Any,
    ) -> str:
        if isinstance(
            node,
            Ip,
        ):
            return node.address

        if isinstance(
            node,
            Domain,
        ):
            return node.domain

        if isinstance(
            node,
            DNSRecord,
        ):
            return node.value

        return str(node)


InputType = DomainToShodanDomainEnricher.InputType
OutputType = DomainToShodanDomainEnricher.OutputType

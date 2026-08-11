from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.domain.to_geonet_shodan import (
    DomainToGeoNetShodanEnricher,
)
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.ssl_certificate import SSLCertificate


SHODAN_CT_URL = "https://ctl.shodan.io/api/v1/domain"

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4/"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6/"


# Current Cloudflare ranges.
#
# These are only used if the live Cloudflare endpoints cannot
# be retrieved when the enricher runs.
CLOUDFLARE_IPV4_FALLBACK = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

CLOUDFLARE_IPV6_FALLBACK = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


class ShodanCTCertificate(BaseModel):
    hash: str
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_before: Optional[int] = None
    not_after: Optional[int] = None
    san_dns_names: List[str] = Field(default_factory=list)


class ShodanCTLookup(BaseModel):
    domain: str
    certificates: List[ShodanCTCertificate] = Field(
        default_factory=list
    )

    #
    # Only domains with at least one A / AAAA result
    # appear here.
    #
    # The root domain may be absent if it currently
    # has no address record. It is still kept in the
    # graph because it was the original input.
    #
    resolved_ips: Dict[str, List[str]] = Field(
        default_factory=dict
    )


@flowsint_enricher
class DomainToShodanCTEnricher(Enricher):
    """
    Discover domains through Shodan Certificate Transparency,
    validate discovered subdomains using Shodan GeoNet, and
    remove non-resolving CT artifacts from the graph.

    Graph model:

        example.com
            |
            +-- HAS_SUBDOMAIN --> app.example.com
            |                       |
            |                       +-- RESOLVES_TO --> 203.0.113.10
            |                       |
            |                       +-- HOSTED_IN ----> CLOUDFLARENET
            |
            +-- HAS_CT_CERTIFICATE --> SSLCertificate

        SSLCertificate
            |
            +-- HAS_DOMAIN --> app.example.com

    Cloudflare addresses are collapsed into one ASN node.
    """

    InputType = Domain
    OutputType = ShodanCTLookup

    @classmethod
    def name(cls) -> str:
        return "domain_to_shodan_ct"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def documentation(cls) -> str:
        return """
        Query Shodan Certificate Transparency and validate
        discovered subdomains using Shodan GeoNet.

        Workflow:

        1. Query:

               GET https://ctl.shodan.io/api/v1/domain/{domain}

        2. Extract Subject CN and SAN DNS names.

        3. Normalize wildcard names:

               *.app.example.com
                   ->
               app.example.com

        4. Resolve every in-scope discovered domain through
           the GeoNet enricher.

        5. Drop CT-discovered subdomains with no A or AAAA
           result.

        6. Link domain hierarchy using:

               HAS_SUBDOMAIN

        7. Link certificates to covered domains using:

               HAS_DOMAIN

           Subject/SAN duplicates therefore produce only one
           graph relationship.

        8. Cloudflare IPs are detected against Cloudflare's
           published IPv4 and IPv6 proxy ranges.

           Instead of creating every Cloudflare IP node:

               Domain
                   |
                   +-- HOSTED_IN --> CLOUDFLARENET

        9. Non-Cloudflare IPs remain:

               Domain
                   |
                   +-- RESOLVES_TO --> Ip

        Root -> HAS_CT_CERTIFICATE is only created when the
        certificate explicitly covers:

               example.com

        or:

               *.example.com
        """

    async def scan(
        self,
        data: List[InputType],
    ) -> List[OutputType]:
        results: List[OutputType] = []

        #
        # Populated here and consumed by postprocess().
        #
        self._cloudflare_cidr_strings: List[str] = []

        self._cloudflare_networks: List[
            ipaddress.IPv4Network
            | ipaddress.IPv6Network
        ] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,
            headers={
                "accept": "application/json",
            },
        ) as client:
            #
            # Pull the current Cloudflare ranges.
            #
            await self._load_cloudflare_networks(
                client
            )

            #
            # Reuse the existing GeoNet enricher.
            #
            # We intentionally call scan() instead of
            # execute(), because this CT enricher controls
            # the final graph generation.
            #
            geonet = (
                DomainToGeoNetShodanEnricher(
                    sketch_id=self.sketch_id,
                    scan_id=self.scan_id,
                    graph_service=self._graph_service,
                )
            )

            for domain_obj in data:
                root_domain = (
                    domain_obj.domain
                    .lower()
                    .rstrip(".")
                )

                certificates = (
                    await self._fetch_ct_certificates(
                        client,
                        root_domain,
                    )
                )

                if certificates is None:
                    continue

                #
                # Extract every in-scope domain discovered
                # through Subject CN / SAN.
                #
                candidate_domains = (
                    self._collect_in_scope_domains(
                        root_domain,
                        certificates,
                    )
                )

                #
                # Resolve the root too.
                #
                # Failure to resolve it doesn't delete it
                # because it's the user's original node.
                #
                candidate_domains.add(
                    root_domain
                )

                resolved_ips = (
                    await self._resolve_domains_with_geonet(
                        geonet,
                        candidate_domains,
                    )
                )

                unresolved_subdomains = sorted(
                    domain
                    for domain
                    in candidate_domains
                    if (
                        domain != root_domain
                        and domain
                        not in resolved_ips
                    )
                )

                if unresolved_subdomains:
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": (
                                f"[Shodan CT] "
                                f"{root_domain}: "
                                f"pruning "
                                f"{len(unresolved_subdomains)} "
                                f"CT-discovered subdomains "
                                f"with no A/AAAA GeoNet result"
                            )
                        },
                    )

                results.append(
                    ShodanCTLookup(
                        domain=root_domain,
                        certificates=certificates,
                        resolved_ips={
                            domain: sorted(
                                addresses
                            )
                            for (
                                domain,
                                addresses,
                            )
                            in sorted(
                                resolved_ips.items()
                            )
                        },
                    )
                )

                retained_subdomains = sum(
                    1
                    for domain in resolved_ips
                    if domain != root_domain
                )

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[Shodan CT] "
                            f"{root_domain}: "
                            f"{len(certificates)} "
                            f"unique certificates, "
                            f"{retained_subdomains} "
                            f"resolving subdomains retained"
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

        domain_nodes: Dict[
            str,
            Domain,
        ] = {}

        ip_nodes: Dict[
            str,
            Ip,
        ] = {}

        certificate_nodes: Dict[
            str,
            SSLCertificate,
        ] = {}

        relationships: set[
            Tuple[
                Tuple[str, str],
                Tuple[str, str],
                str,
            ]
        ] = set()

        #
        # SSLCertificate is keyed by subject in Flowsint.
        #
        certificates_by_subject: Dict[
            str,
            Dict[
                str,
                ShodanCTCertificate,
            ],
        ] = defaultdict(dict)

        queries_by_subject: Dict[
            str,
            set[str],
        ] = defaultdict(set)

        #
        # subject -> domain -> {subject, san}
        #
        # We preserve these roles as metadata, but graph
        # relationships are collapsed into HAS_DOMAIN.
        #
        domain_roles_by_subject: Dict[
            str,
            Dict[
                str,
                set[str],
            ],
        ] = defaultdict(
            lambda: defaultdict(set)
        )

        #
        # Only root / *.root certificates get a direct
        # root -> certificate relationship.
        #
        root_certificate_links: set[
            Tuple[str, str]
        ] = set()

        #
        # Used so certificates which only concern dead,
        # non-resolving subdomains don't become orphan
        # graph nodes.
        #
        active_certificate_subjects: set[
            str
        ] = set()

        #
        # Original input nodes are always kept.
        #
        for domain_obj in (
            input_data
            or []
        ):
            node = self._safe_domain(
                domain_obj.domain
            )

            if node:
                domain_nodes.setdefault(
                    node.domain,
                    node,
                )

        cloudflare_used = False

        cloudflare_asn: Optional[
            ASN
        ] = None

        for lookup in results:
            root = self._safe_domain(
                lookup.domain
            )

            if root is None:
                continue

            domain_nodes.setdefault(
                root.domain,
                root,
            )

            #
            # Only GeoNet-validated in-scope domains
            # survive.
            #
            retained_in_scope = {
                domain
                for domain
                in lookup.resolved_ips
                if self._belongs_to(
                    domain,
                    root.domain,
                )
            }

            #
            # Root is always retained.
            #
            retained_in_scope.add(
                root.domain
            )

            #
            # Standard domain hierarchy.
            #
            for subdomain in sorted(
                retained_in_scope
            ):
                if (
                    subdomain
                    == root.domain
                ):
                    continue

                node = self._safe_domain(
                    subdomain
                )

                if node is None:
                    continue

                domain_nodes.setdefault(
                    node.domain,
                    node,
                )

                relationships.add(
                    (
                        (
                            "Domain",
                            root.domain,
                        ),
                        (
                            "Domain",
                            node.domain,
                        ),
                        "HAS_SUBDOMAIN",
                    )
                )

            #
            # Resolution graph.
            #
            for (
                domain_name,
                addresses,
            ) in (
                lookup.resolved_ips.items()
            ):
                domain_node = (
                    self._safe_domain(
                        domain_name
                    )
                )

                if domain_node is None:
                    continue

                domain_nodes.setdefault(
                    domain_node.domain,
                    domain_node,
                )

                for address in addresses:
                    #
                    # Cloudflare:
                    #
                    # Don't create the individual IP.
                    #
                    if self._is_cloudflare_ip(
                        address
                    ):
                        if cloudflare_asn is None:
                            cloudflare_asn = (
                                self._build_cloudflare_asn()
                            )

                        cloudflare_used = True

                        relationships.add(
                            (
                                (
                                    "Domain",
                                    domain_node.domain,
                                ),
                                (
                                    "ASN",
                                    cloudflare_asn.asn_str,
                                ),
                                "HOSTED_IN",
                            )
                        )

                        continue

                    #
                    # Normal/non-Cloudflare IP.
                    #
                    ip_node = self._safe_ip(
                        address
                    )

                    if ip_node is None:
                        continue

                    ip_nodes.setdefault(
                        ip_node.address,
                        ip_node,
                    )

                    relationships.add(
                        (
                            (
                                "Domain",
                                domain_node.domain,
                            ),
                            (
                                "Ip",
                                ip_node.address,
                            ),
                            "RESOLVES_TO",
                        )
                    )

            #
            # Certificates.
            #
            for cert in (
                lookup.certificates
            ):
                subject = (
                    self._subject_key(
                        cert
                    )
                )

                certificates_by_subject[
                    subject
                ].setdefault(
                    cert.hash,
                    cert,
                )

                queries_by_subject[
                    subject
                ].add(
                    root.domain
                )

                #
                # Root or *.root only.
                #
                if (
                    self._certificate_covers_root(
                        cert,
                        root.domain,
                    )
                ):
                    root_certificate_links.add(
                        (
                            root.domain,
                            subject,
                        )
                    )

                    active_certificate_subjects.add(
                        subject
                    )

                #
                # Subject CN.
                #
                if cert.subject_cn:
                    self._collect_certificate_domain(
                        root=root.domain,
                        subject=subject,
                        raw_name=(
                            cert.subject_cn
                        ),
                        role="subject",
                        retained_in_scope=(
                            retained_in_scope
                        ),
                        domain_nodes=(
                            domain_nodes
                        ),
                        domain_roles_by_subject=(
                            domain_roles_by_subject
                        ),
                        active_certificate_subjects=(
                            active_certificate_subjects
                        ),
                    )

                #
                # SANs.
                #
                for raw_san in (
                    cert.san_dns_names
                ):
                    self._collect_certificate_domain(
                        root=root.domain,
                        subject=subject,
                        raw_name=raw_san,
                        role="san",
                        retained_in_scope=(
                            retained_in_scope
                        ),
                        domain_nodes=(
                            domain_nodes
                        ),
                        domain_roles_by_subject=(
                            domain_roles_by_subject
                        ),
                        active_certificate_subjects=(
                            active_certificate_subjects
                        ),
                    )

        now = int(
            datetime.now(
                timezone.utc
            ).timestamp()
        )

        #
        # Build aggregated certificate nodes.
        #
        for subject in sorted(
            active_certificate_subjects
        ):
            by_hash = (
                certificates_by_subject.get(
                    subject
                )
            )

            if not by_hash:
                continue

            certs = sorted(
                by_hash.values(),
                key=lambda cert: (
                    cert.not_before or 0,
                    cert.not_after or 0,
                    cert.hash,
                ),
            )

            latest = max(
                certs,
                key=lambda cert: (
                    cert.not_before or 0,
                    cert.not_after or 0,
                ),
            )

            raw_sans = sorted(
                {
                    san
                    for cert in certs
                    for san
                    in cert.san_dns_names
                }
            )

            issuers = sorted(
                {
                    cert.issuer_cn
                    for cert in certs
                    if cert.issuer_cn
                }
            )

            fingerprints = sorted(
                {
                    cert.hash
                    for cert in certs
                }
            )

            is_expired: Optional[
                bool
            ] = None

            if (
                latest.not_after
                is not None
            ):
                is_expired = (
                    now
                    > latest.not_after
                )

            is_valid: Optional[
                bool
            ] = None

            if (
                latest.not_before
                is not None
                and latest.not_after
                is not None
            ):
                is_valid = (
                    latest.not_before
                    <= now
                    <= latest.not_after
                )

            cert_node = SSLCertificate(
                subject=subject,
                issuer=latest.issuer_cn,
                valid_from=(
                    self._epoch_to_iso(
                        latest.not_before
                    )
                ),
                valid_until=(
                    self._epoch_to_iso(
                        latest.not_after
                    )
                ),
                san_domains=(
                    raw_sans
                    or None
                ),
                is_valid=is_valid,
                is_expired=is_expired,
                is_wildcard=(
                    subject.startswith(
                        "*."
                    )
                    or any(
                        san.startswith("*.")
                        for san
                        in raw_sans
                    )
                ),
                source=(
                    "Shodan Certificate "
                    "Transparency"
                ),
                fingerprint_sha256=(
                    latest.hash
                ),
            )

            setattr(
                cert_node,
                "shodan_ct_certificate_count",
                len(certs),
            )

            setattr(
                cert_node,
                "shodan_ct_fingerprints_sha256",
                fingerprints,
            )

            setattr(
                cert_node,
                "shodan_ct_issuers",
                issuers,
            )

            setattr(
                cert_node,
                "shodan_ct_query_domains",
                sorted(
                    queries_by_subject[
                        subject
                    ]
                ),
            )

            setattr(
                cert_node,
                "shodan_ct_certificate_history",
                [
                    self._format_certificate_history(
                        cert
                    )
                    for cert in certs
                ],
            )

            setattr(
                cert_node,
                "shodan_ct_domain_roles",
                [
                    (
                        f"{domain}="
                        f"{','.join(sorted(roles))}"
                    )
                    for (
                        domain,
                        roles,
                    )
                    in sorted(
                        domain_roles_by_subject[
                            subject
                        ].items()
                    )
                ],
            )

            certificate_nodes[
                subject
            ] = cert_node

            #
            # One HAS_DOMAIN relationship regardless
            # of whether the hostname appeared in
            # Subject, SAN, or both.
            #
            for domain_name in (
                domain_roles_by_subject[
                    subject
                ]
            ):
                relationships.add(
                    (
                        (
                            "SSLCertificate",
                            subject,
                        ),
                        (
                            "Domain",
                            domain_name,
                        ),
                        "HAS_DOMAIN",
                    )
                )

        #
        # Root certificates only.
        #
        for (
            root_domain,
            subject,
        ) in root_certificate_links:
            if (
                subject
                not in certificate_nodes
            ):
                continue

            relationships.add(
                (
                    (
                        "Domain",
                        root_domain,
                    ),
                    (
                        "SSLCertificate",
                        subject,
                    ),
                    "HAS_CT_CERTIFICATE",
                )
            )

        #
        # Domain nodes.
        #
        for domain_name in sorted(
            domain_nodes
        ):
            node = domain_nodes[
                domain_name
            ]

            setattr(
                node,
                "shodan_ct_source",
                (
                    "Shodan Certificate "
                    "Transparency"
                ),
            )

            self.create_node(
                node
            )

        #
        # Non-Cloudflare IP nodes.
        #
        for address in sorted(
            ip_nodes
        ):
            node = ip_nodes[
                address
            ]

            setattr(
                node,
                "geonet_source",
                "Shodan GeoNet",
            )

            self.create_node(
                node
            )

        #
        # One Cloudflare node regardless of how
        # many addresses matched.
        #
        if (
            cloudflare_used
            and cloudflare_asn
            is not None
        ):
            self.create_node(
                cloudflare_asn
            )

        #
        # Certificate nodes.
        #
        for subject in sorted(
            certificate_nodes
        ):
            self.create_node(
                certificate_nodes[
                    subject
                ]
            )

        #
        # Relationships.
        #
        for (
            source_key,
            target_key,
            relationship,
        ) in sorted(
            relationships
        ):
            source = self._resolve_node(
                source_key,
                domain_nodes,
                ip_nodes,
                certificate_nodes,
                (
                    cloudflare_asn
                    if cloudflare_used
                    else None
                ),
            )

            target = self._resolve_node(
                target_key,
                domain_nodes,
                ip_nodes,
                certificate_nodes,
                (
                    cloudflare_asn
                    if cloudflare_used
                    else None
                ),
            )

            if (
                source is None
                or target is None
            ):
                continue

            self.create_relationship(
                source,
                target,
                relationship,
            )

            self.log_graph_message(
                f"[Shodan CT] "
                f"{self._node_label(source)} "
                f"-[{relationship}]-> "
                f"{self._node_label(target)}"
            )

        return results

    async def _fetch_ct_certificates(
        self,
        client: httpx.AsyncClient,
        domain: str,
    ) -> Optional[
        List[ShodanCTCertificate]
    ]:
        try:
            response = await client.get(
                f"{SHODAN_CT_URL}/{domain}"
            )

            response.raise_for_status()

            payload = response.json()

        except httpx.HTTPStatusError as exc:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        f"[Shodan CT] "
                        f"{domain}: "
                        f"HTTP "
                        f"{exc.response.status_code}"
                    )
                },
            )

            return None

        except httpx.HTTPError as exc:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        f"[Shodan CT] "
                        f"{domain}: "
                        f"{type(exc).__name__}"
                    )
                },
            )

            return None

        except ValueError:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        f"[Shodan CT] "
                        f"Invalid JSON for "
                        f"{domain}"
                    )
                },
            )

            return None

        if not isinstance(
            payload,
            list,
        ):
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        f"[Shodan CT] "
                        f"Unexpected response "
                        f"for {domain}"
                    )
                },
            )

            return None

        unique: Dict[
            str,
            ShodanCTCertificate,
        ] = {}

        for raw in payload:
            if not isinstance(
                raw,
                dict,
            ):
                continue

            fingerprint = str(
                raw.get("hash")
                or ""
            ).strip().lower()

            if not fingerprint:
                continue

            sans = raw.get(
                "san_dns_names",
                [],
            )

            if not isinstance(
                sans,
                list,
            ):
                sans = []

            cert = ShodanCTCertificate(
                hash=fingerprint,
                subject_cn=(
                    self._optional_string(
                        raw.get(
                            "subject_cn"
                        )
                    )
                ),
                issuer_cn=(
                    self._optional_string(
                        raw.get(
                            "issuer_cn"
                        )
                    )
                ),
                not_before=(
                    self._to_int(
                        raw.get(
                            "not_before"
                        )
                    )
                ),
                not_after=(
                    self._to_int(
                        raw.get(
                            "not_after"
                        )
                    )
                ),
                san_dns_names=sorted(
                    {
                        str(name).strip()
                        for name in sans
                        if (
                            name is not None
                            and str(
                                name
                            ).strip()
                        )
                    }
                ),
            )

            unique.setdefault(
                fingerprint,
                cert,
            )

        return sorted(
            unique.values(),
            key=lambda cert: (
                cert.subject_cn
                or "",
                cert.not_before
                or 0,
                cert.hash,
            ),
        )

    async def _resolve_domains_with_geonet(
        self,
        geonet: (
            DomainToGeoNetShodanEnricher
        ),
        domains: set[str],
    ) -> Dict[
        str,
        set[str],
    ]:
        inputs: List[
            Domain
        ] = []

        for domain in sorted(
            domains
        ):
            node = self._safe_domain(
                domain
            )

            if node is not None:
                inputs.append(
                    node
                )

        if not inputs:
            return {}

        try:
            #
            # This invokes your existing GeoNet
            # enricher logic.
            #
            geonet_results = (
                await geonet.scan(
                    inputs
                )
            )

        except Exception as exc:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        "[Shodan CT] "
                        "GeoNet chained "
                        "resolution failed: "
                        f"{type(exc).__name__}: "
                        f"{exc}"
                    )
                },
            )

            return {}

        resolved: Dict[
            str,
            set[str],
        ] = defaultdict(set)

        for record in (
            geonet_results
        ):
            record_type = str(
                getattr(
                    record,
                    "record_type",
                    "",
                )
            ).upper()

            #
            # Only A / AAAA determine whether
            # the hostname actually resolves.
            #
            if record_type not in {
                "A",
                "AAAA",
            }:
                continue

            domain = str(
                getattr(
                    record,
                    "domain",
                    "",
                )
            ).lower().rstrip(".")

            value = str(
                getattr(
                    record,
                    "value",
                    "",
                )
            ).strip()

            if (
                not domain
                or not value
            ):
                continue

            try:
                ipaddress.ip_address(
                    value
                )

            except ValueError:
                continue

            resolved[
                domain
            ].add(
                value
            )

        return resolved

    async def _load_cloudflare_networks(
        self,
        client: httpx.AsyncClient,
    ) -> None:
        v4 = await self._fetch_cidr_list(
            client,
            CLOUDFLARE_IPV4_URL,
            ip_version=4,
        )

        v6 = await self._fetch_cidr_list(
            client,
            CLOUDFLARE_IPV6_URL,
            ip_version=6,
        )

        if not v4:
            v4 = list(
                CLOUDFLARE_IPV4_FALLBACK
            )

            Logger.warn(
                self.sketch_id,
                {
                    "message": (
                        "[Shodan CT] "
                        "Could not retrieve "
                        "Cloudflare IPv4 ranges; "
                        "using embedded fallback"
                    )
                },
            )

        if not v6:
            v6 = list(
                CLOUDFLARE_IPV6_FALLBACK
            )

            Logger.warn(
                self.sketch_id,
                {
                    "message": (
                        "[Shodan CT] "
                        "Could not retrieve "
                        "Cloudflare IPv6 ranges; "
                        "using embedded fallback"
                    )
                },
            )

        self._cloudflare_cidr_strings = (
            list(
                dict.fromkeys(
                    v4
                    + v6
                )
            )
        )

        self._cloudflare_networks = [
            ipaddress.ip_network(
                cidr,
                strict=False,
            )
            for cidr
            in self._cloudflare_cidr_strings
        ]

        Logger.info(
            self.sketch_id,
            {
                "message": (
                    f"[Shodan CT] "
                    f"Loaded {len(v4)} "
                    f"Cloudflare IPv4 and "
                    f"{len(v6)} IPv6 ranges"
                )
            },
        )

    async def _fetch_cidr_list(
        self,
        client: httpx.AsyncClient,
        url: str,
        ip_version: int,
    ) -> List[str]:
        try:
            response = await client.get(
                url,
                headers={
                    "accept": "text/plain",
                },
            )

            response.raise_for_status()

        except httpx.HTTPError:
            return []

        cidrs: List[
            str
        ] = []

        for raw_line in (
            response.text.splitlines()
        ):
            line = raw_line.strip()

            if not line:
                continue

            try:
                network = (
                    ipaddress.ip_network(
                        line,
                        strict=False,
                    )
                )

            except ValueError:
                continue

            if (
                network.version
                != ip_version
            ):
                continue

            cidrs.append(
                str(
                    network
                )
            )

        return cidrs

    def _build_cloudflare_asn(
        self,
    ) -> ASN:
        #
        # Native Flowsint ASN requires
        # an AS<number> identifier.
        #
        asn = ASN(
            asn_str="AS13335",
            number=13335,
            name="CLOUDFLARENET",
            country="US",
            description=(
                "Cloudflare, Inc. "
                "edge/proxy network"
            ),
            cidrs=[
                CIDR(
                    network=cidr
                )
                for cidr
                in self._cloudflare_cidr_strings
            ],
        )

        #
        # Keep the graph visually compact.
        #
        asn.nodeLabel = (
            "CLOUDFLARENET"
        )

        #
        # Native cidrs remains List[CIDR],
        # as required by Flowsint.
        #
        # Also provide the exact convenient
        # comma-separated representation.
        #
        setattr(
            asn,
            "cidr_blocks_csv",
            ", ".join(
                self._cloudflare_cidr_strings
            ),
        )

        setattr(
            asn,
            "source",
            (
                "Cloudflare published "
                "IP ranges"
            ),
        )

        return asn

    def _is_cloudflare_ip(
        self,
        address: str,
    ) -> bool:
        try:
            ip_obj = (
                ipaddress.ip_address(
                    address
                )
            )

        except ValueError:
            return False

        for network in getattr(
            self,
            "_cloudflare_networks",
            [],
        ):
            if (
                network.version
                != ip_obj.version
            ):
                continue

            if ip_obj in network:
                return True

        return False

    @staticmethod
    def _collect_in_scope_domains(
        root: str,
        certificates: List[
            ShodanCTCertificate
        ],
    ) -> set[str]:
        domains: set[
            str
        ] = set()

        for cert in certificates:
            for raw_name in (
                DomainToShodanCTEnricher
                ._certificate_names(
                    cert
                )
            ):
                normalized = (
                    DomainToShodanCTEnricher
                    ._normalize_dns_name(
                        raw_name
                    )
                )

                if not normalized:
                    continue

                if not (
                    DomainToShodanCTEnricher
                    ._belongs_to(
                        normalized,
                        root,
                    )
                ):
                    continue

                node = (
                    DomainToShodanCTEnricher
                    ._safe_domain(
                        normalized
                    )
                )

                if node is not None:
                    domains.add(
                        node.domain
                    )

        return domains

    @staticmethod
    def _collect_certificate_domain(
        root: str,
        subject: str,
        raw_name: str,
        role: str,
        retained_in_scope: set[
            str
        ],
        domain_nodes: Dict[
            str,
            Domain,
        ],
        domain_roles_by_subject: Dict[
            str,
            Dict[
                str,
                set[str],
            ],
        ],
        active_certificate_subjects: set[
            str
        ],
    ) -> None:
        normalized = (
            DomainToShodanCTEnricher
            ._normalize_dns_name(
                raw_name
            )
        )

        if not normalized:
            return

        #
        # In-scope subdomain?
        #
        # It must have survived GeoNet
        # resolution.
        #
        if (
            DomainToShodanCTEnricher
            ._belongs_to(
                normalized,
                root,
            )
        ):
            if (
                normalized
                != root
                and normalized
                not in retained_in_scope
            ):
                return

        node = (
            DomainToShodanCTEnricher
            ._safe_domain(
                normalized
            )
        )

        if node is None:
            return

        domain_nodes.setdefault(
            node.domain,
            node,
        )

        domain_roles_by_subject[
            subject
        ][
            node.domain
        ].add(
            role
        )

        active_certificate_subjects.add(
            subject
        )

    @staticmethod
    def _certificate_covers_root(
        cert: ShodanCTCertificate,
        root: str,
    ) -> bool:
        root = (
            root
            .lower()
            .rstrip(".")
        )

        accepted = {
            root,
            f"*.{root}",
        }

        for raw_name in (
            DomainToShodanCTEnricher
            ._certificate_names(
                cert
            )
        ):
            name = (
                raw_name
                .strip()
                .lower()
                .rstrip(".")
            )

            if name in accepted:
                return True

        return False

    @staticmethod
    def _certificate_names(
        cert: ShodanCTCertificate,
    ) -> List[str]:
        names = list(
            cert.san_dns_names
        )

        if cert.subject_cn:
            names.append(
                cert.subject_cn
            )

        return names

    @staticmethod
    def _subject_key(
        cert: ShodanCTCertificate,
    ) -> str:
        if cert.subject_cn:
            return (
                cert.subject_cn
                .strip()
                .lower()
                .rstrip(".")
            )

        return (
            f"sha256:{cert.hash}"
        )

    @staticmethod
    def _normalize_dns_name(
        value: str,
    ) -> Optional[str]:
        value = (
            value
            .strip()
            .lower()
            .rstrip(".")
        )

        #
        # *.a.example.com
        # ->
        # a.example.com
        #
        while value.startswith(
            "*."
        ):
            value = value[
                2:
            ]

        return (
            value
            or None
        )

    @staticmethod
    def _safe_domain(
        value: str,
    ) -> Optional[Domain]:
        normalized = (
            DomainToShodanCTEnricher
            ._normalize_dns_name(
                value
            )
        )

        if not normalized:
            return None

        try:
            return Domain(
                domain=normalized
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
    def _belongs_to(
        candidate: str,
        root: str,
    ) -> bool:
        candidate = (
            candidate
            .lower()
            .rstrip(".")
        )

        root = (
            root
            .lower()
            .rstrip(".")
        )

        return (
            candidate == root
            or candidate.endswith(
                f".{root}"
            )
        )

    @staticmethod
    def _epoch_to_iso(
        value: Optional[int],
    ) -> Optional[str]:
        if value is None:
            return None

        try:
            return (
                datetime.fromtimestamp(
                    value,
                    tz=timezone.utc,
                )
                .isoformat()
                .replace(
                    "+00:00",
                    "Z",
                )
            )

        except (
            OverflowError,
            OSError,
            ValueError,
        ):
            return None

    @staticmethod
    def _format_certificate_history(
        cert: ShodanCTCertificate,
    ) -> str:
        return " | ".join(
            [
                (
                    f"sha256="
                    f"{cert.hash}"
                ),
                (
                    f"issuer="
                    f"{cert.issuer_cn or ''}"
                ),
                (
                    "not_before="
                    f"{DomainToShodanCTEnricher._epoch_to_iso(cert.not_before) or ''}"
                ),
                (
                    "not_after="
                    f"{DomainToShodanCTEnricher._epoch_to_iso(cert.not_after) or ''}"
                ),
            ]
        )

    @staticmethod
    def _to_int(
        value: Any,
    ) -> Optional[int]:
        if value is None:
            return None

        try:
            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _optional_string(
        value: Any,
    ) -> Optional[str]:
        if value is None:
            return None

        value = str(
            value
        ).strip()

        return (
            value
            or None
        )

    @staticmethod
    def _resolve_node(
        key: Tuple[
            str,
            str,
        ],
        domain_nodes: Dict[
            str,
            Domain,
        ],
        ip_nodes: Dict[
            str,
            Ip,
        ],
        certificate_nodes: Dict[
            str,
            SSLCertificate,
        ],
        cloudflare_asn: Optional[
            ASN
        ],
    ) -> Optional[Any]:
        node_type, value = key

        if node_type == "Domain":
            return domain_nodes.get(
                value
            )

        if node_type == "Ip":
            return ip_nodes.get(
                value
            )

        if (
            node_type
            == "SSLCertificate"
        ):
            return certificate_nodes.get(
                value
            )

        if (
            node_type == "ASN"
            and cloudflare_asn
            is not None
            and value
            == cloudflare_asn.asn_str
        ):
            return cloudflare_asn

        return None

    @staticmethod
    def _node_label(
        node: Any,
    ) -> str:
        if isinstance(
            node,
            Domain,
        ):
            return node.domain

        if isinstance(
            node,
            Ip,
        ):
            return node.address

        if isinstance(
            node,
            ASN,
        ):
            return (
                node.nodeLabel
                or node.asn_str
            )

        if isinstance(
            node,
            SSLCertificate,
        ):
            return node.subject

        return str(
            node
        )


InputType = (
    DomainToShodanCTEnricher
    .InputType
)

OutputType = (
    DomainToShodanCTEnricher
    .OutputType
)

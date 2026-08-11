from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ssl_certificate import SSLCertificate


SHODAN_CT_URL = "https://ctl.shodan.io/api/v1/domain"


class ShodanCTCertificate(BaseModel):
    hash: str
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_before: Optional[int] = None
    not_after: Optional[int] = None
    san_dns_names: List[str] = Field(default_factory=list)


class ShodanCTLookup(BaseModel):
    domain: str
    certificates: List[ShodanCTCertificate] = Field(default_factory=list)


@flowsint_enricher
class DomainToShodanCTEnricher(Enricher):
    """
    Query Shodan Certificate Transparency for a domain.

    Graph model:

        root.example.com
            |
            +-- DISCOVERED_VIA_CT --> app.root.example.com
            |                           ^
            |                           |
            |                      HAS_DOMAIN
            |                           |
            |                    SSLCertificate
            |
            +-- HAS_CT_CERTIFICATE --> SSLCertificate
                                        |
                                   HAS_DOMAIN
                                        |
                                        v
                                 root.example.com

    HAS_CT_CERTIFICATE is only created when the certificate explicitly
    covers the queried root domain or its direct wildcard:

        example.com
        *.example.com

    Certificates for subdomains are connected to those subdomains rather
    than directly to the queried root.
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
        Query Shodan's public Certificate Transparency API:

            GET https://ctl.shodan.io/api/v1/domain/{domain}

        No API key is required.

        Returned certificate records include:

            hash
            subject_cn
            issuer_cn
            not_before
            not_after
            san_dns_names

        Graph behavior:

            example.com
              |
              +-- DISCOVERED_VIA_CT --> app.example.com
              |                           ^
              |                           |
              |                      HAS_DOMAIN
              |                           |
              |                    SSLCertificate
              |
              +-- HAS_CT_CERTIFICATE --> SSLCertificate
                                          |
                                     HAS_DOMAIN
                                          |
                                          v
                                      example.com

        Root -> HAS_CT_CERTIFICATE is only created when the certificate
        explicitly contains either:

            example.com
            *.example.com

        A certificate such as:

            *.app.example.com

        instead produces:

            example.com
                |
                +-- DISCOVERED_VIA_CT --> app.example.com
                                            ^
                                            |
                                       HAS_DOMAIN
                                            |
                                    SSLCertificate

        Subject and SAN relationships are deduplicated into a single
        HAS_DOMAIN relationship.

        Wildcard DNS names are normalized when creating Domain nodes:

            *.app.example.com -> app.example.com

        The original wildcard value remains preserved on the certificate.
        """

    async def scan(
        self,
        data: List[InputType],
    ) -> List[OutputType]:
        results: List[OutputType] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,
            headers={
                "accept": "application/json",
            },
        ) as client:
            for domain_obj in data:
                domain = (
                    domain_obj.domain
                    .lower()
                    .rstrip(".")
                )

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
                                f"[Shodan CT] {domain}: "
                                f"HTTP {exc.response.status_code}"
                            )
                        },
                    )
                    continue

                except httpx.HTTPError as exc:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": (
                                f"[Shodan CT] {domain}: "
                                f"{type(exc).__name__}"
                            )
                        },
                    )
                    continue

                except ValueError:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": (
                                f"[Shodan CT] Invalid JSON "
                                f"for {domain}"
                            )
                        },
                    )
                    continue

                if not isinstance(payload, list):
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": (
                                f"[Shodan CT] Unexpected "
                                f"response for {domain}"
                            )
                        },
                    )
                    continue

                #
                # Deduplicate raw CT entries by SHA-256.
                #
                unique: Dict[
                    str,
                    ShodanCTCertificate,
                ] = {}

                for raw in payload:
                    if not isinstance(raw, dict):
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

                    if not isinstance(sans, list):
                        sans = []

                    cert = ShodanCTCertificate(
                        hash=fingerprint,
                        subject_cn=self._optional_string(
                            raw.get("subject_cn")
                        ),
                        issuer_cn=self._optional_string(
                            raw.get("issuer_cn")
                        ),
                        not_before=self._to_int(
                            raw.get("not_before")
                        ),
                        not_after=self._to_int(
                            raw.get("not_after")
                        ),
                        san_dns_names=sorted(
                            {
                                str(name).strip()
                                for name in sans
                                if (
                                    name is not None
                                    and str(name).strip()
                                )
                            }
                        ),
                    )

                    unique.setdefault(
                        fingerprint,
                        cert,
                    )

                certificates = sorted(
                    unique.values(),
                    key=lambda cert: (
                        cert.subject_cn or "",
                        cert.not_before or 0,
                        cert.hash,
                    ),
                )

                results.append(
                    ShodanCTLookup(
                        domain=domain,
                        certificates=certificates,
                    )
                )

                discovered = {
                    normalized
                    for cert in certificates
                    for raw_name in self._certificate_names(
                        cert
                    )
                    if (
                        normalized :=
                        self._normalize_dns_name(
                            raw_name
                        )
                    )
                    and self._belongs_to(
                        normalized,
                        domain,
                    )
                }

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[Shodan CT] {domain}: "
                            f"{len(certificates)} "
                            f"unique certificates, "
                            f"{len(discovered)} "
                            f"in-scope DNS names"
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
        # Therefore certificate renewals for the same subject
        # are aggregated here.
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
        # subject ->
        #     normalized domain ->
        #         {"subject", "san"}
        #
        # Keeping the roles in metadata lets us collapse the
        # graph relationship to HAS_DOMAIN without losing the
        # distinction entirely.
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
        # Only certificates that explicitly cover the root
        # are allowed to have root -> certificate edges.
        #
        root_certificate_links: set[
            Tuple[str, str]
        ] = set()

        #
        # Seed original input Domain nodes.
        #
        for domain_obj in input_data or []:
            node = self._safe_domain(
                domain_obj.domain
            )

            if node:
                domain_nodes.setdefault(
                    node.domain,
                    node,
                )

        #
        # Collect graph entities and relationships.
        #
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

            for cert in lookup.certificates:
                subject = self._subject_key(
                    cert
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
                # Only explicitly root-scoped certificates
                # are connected directly to the root.
                #
                if self._certificate_covers_root(
                    cert,
                    root.domain,
                ):
                    root_certificate_links.add(
                        (
                            root.domain,
                            subject,
                        )
                    )

                #
                # Subject CN.
                #
                if cert.subject_cn:
                    normalized = (
                        self._normalize_dns_name(
                            cert.subject_cn
                        )
                    )

                    if normalized:
                        node = self._safe_domain(
                            normalized
                        )

                        if node:
                            domain_nodes.setdefault(
                                node.domain,
                                node,
                            )

                            domain_roles_by_subject[
                                subject
                            ][
                                node.domain
                            ].add(
                                "subject"
                            )

                            #
                            # Any in-scope subdomain found
                            # through CT is linked to the root.
                            #
                            if (
                                node.domain
                                != root.domain
                                and self._belongs_to(
                                    node.domain,
                                    root.domain,
                                )
                            ):
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
                                        "DISCOVERED_VIA_CT",
                                    )
                                )

                #
                # SAN entries.
                #
                for raw_san in cert.san_dns_names:
                    normalized = (
                        self._normalize_dns_name(
                            raw_san
                        )
                    )

                    if not normalized:
                        continue

                    node = self._safe_domain(
                        normalized
                    )

                    if node is None:
                        continue

                    domain_nodes.setdefault(
                        node.domain,
                        node,
                    )

                    domain_roles_by_subject[
                        subject
                    ][
                        node.domain
                    ].add(
                        "san"
                    )

                    #
                    # External SANs stay connected to the
                    # certificate but are NOT children of
                    # the queried root.
                    #
                    if (
                        node.domain
                        != root.domain
                        and self._belongs_to(
                            node.domain,
                            root.domain,
                        )
                    ):
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
                                "DISCOVERED_VIA_CT",
                            )
                        )

        now = int(
            datetime.now(
                timezone.utc
            ).timestamp()
        )

        #
        # Build certificate nodes.
        #
        for (
            subject,
            by_hash,
        ) in certificates_by_subject.items():
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
                    for san in cert.san_dns_names
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

            is_expired: Optional[bool] = None

            if latest.not_after is not None:
                is_expired = (
                    now > latest.not_after
                )

            is_valid: Optional[bool] = None

            if (
                latest.not_before is not None
                and latest.not_after is not None
            ):
                is_valid = (
                    latest.not_before
                    <= now
                    <= latest.not_after
                )

            cert_node = SSLCertificate(
                subject=subject,
                issuer=latest.issuer_cn,
                valid_from=self._epoch_to_iso(
                    latest.not_before
                ),
                valid_until=self._epoch_to_iso(
                    latest.not_after
                ),
                san_domains=(
                    raw_sans
                    or None
                ),
                is_valid=is_valid,
                is_expired=is_expired,
                is_wildcard=(
                    subject.startswith("*.")
                    or any(
                        san.startswith("*.")
                        for san in raw_sans
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

            #
            # Additional CT history.
            #
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

            #
            # Keep certificate history in string form.
            #
            # This avoids relying on nested-map storage
            # for Neo4j node properties.
            #
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

            #
            # Preserve whether each HAS_DOMAIN edge was
            # originally found via Subject, SAN, or both.
            #
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
                    ) in sorted(
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
            # Certificate -> covered Domain.
            #
            # Using a set of relationship tuples means:
            #
            #     Subject = app.example.com
            #     SAN     = app.example.com
            #
            # still creates just:
            #
            #     certificate -[HAS_DOMAIN]-> app.example.com
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
        # Root -> certificate relationships.
        #
        # These only exist for certificates explicitly
        # covering:
        #
        #     example.com
        #     *.example.com
        #
        for (
            root_domain,
            subject,
        ) in root_certificate_links:
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
        # Create Domain nodes.
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
        # Create certificate nodes.
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
        # Create relationships once.
        #
        for (
            source_key,
            target_key,
            relationship,
        ) in sorted(relationships):
            source = self._resolve_node(
                source_key,
                domain_nodes,
                certificate_nodes,
            )

            target = self._resolve_node(
                target_key,
                domain_nodes,
                certificate_nodes,
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

    @staticmethod
    def _certificate_covers_root(
        cert: ShodanCTCertificate,
        root: str,
    ) -> bool:
        """
        Return True only if the certificate explicitly contains:

            example.com

        or:

            *.example.com

        It intentionally does NOT match:

            app.example.com
            *.app.example.com
        """

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
        """
        Convert wildcard certificate names into usable
        Flowsint Domain nodes.

        Examples:

            *.example.com
                -> example.com

            *.a.example.com
                -> a.example.com
        """

        value = (
            value
            .strip()
            .lower()
            .rstrip(".")
        )

        while value.startswith(
            "*."
        ):
            value = value[2:]

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
                f"sha256={cert.hash}",
                (
                    "issuer="
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
        key: Tuple[str, str],
        domain_nodes: Dict[
            str,
            Domain,
        ],
        certificate_nodes: Dict[
            str,
            SSLCertificate,
        ],
    ) -> Optional[Any]:
        node_type, value = key

        if node_type == "Domain":
            return domain_nodes.get(
                value
            )

        if (
            node_type
            == "SSLCertificate"
        ):
            return certificate_nodes.get(
                value
            )

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
            SSLCertificate,
        ):
            return node.subject

        return str(
            node
        )


InputType = DomainToShodanCTEnricher.InputType
OutputType = DomainToShodanCTEnricher.OutputType

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

    Certificates are deduplicated by SHA-256 fingerprint.

    Graph model:

        Domain
          |
          +-- HAS_CT_CERTIFICATE --> SSLCertificate
          |                             |
          |                             +-- HAS_SUBJECT --> Domain
          |                             +-- HAS_SAN -----> Domain
          |
          +-- DISCOVERED_VIA_CT -----> Domain
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

        Graph:

            Domain
              |
              +-- HAS_CT_CERTIFICATE --> SSLCertificate
              |                             |
              |                             +-- HAS_SUBJECT --> Domain
              |                             +-- HAS_SAN -----> Domain
              |
              +-- DISCOVERED_VIA_CT -----> Domain

        Certificates are first deduplicated by SHA-256 fingerprint.

        Flowsint's native SSLCertificate entity uses "subject" as its
        primary identifier. Multiple certificate renewals for the same
        subject are therefore aggregated into one SSLCertificate node.

        Every individual certificate fingerprint, issuer, validity period,
        and SAN list is retained in the "shodan_ct_certificates" property.

        Wildcard names such as:

            *.example.com

        remain present on the certificate while the corresponding Domain
        entity is normalized to:

            example.com

        External SANs are retained through HAS_SAN relationships but are
        not marked as DISCOVERED_VIA_CT children of the queried root.
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
                                f"HTTP "
                                f"{exc.response.status_code}"
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

                if not isinstance(
                    payload,
                    list,
                ):
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
                # Certificate fingerprint is the real unique
                # identifier returned by Shodan.
                #
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
                        subject_cn=self._optional_string(
                            raw.get(
                                "subject_cn"
                            )
                        ),
                        issuer_cn=self._optional_string(
                            raw.get(
                                "issuer_cn"
                            )
                        ),
                        not_before=self._to_int(
                            raw.get(
                                "not_before"
                            )
                        ),
                        not_after=self._to_int(
                            raw.get(
                                "not_after"
                            )
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
                    for raw_name in (
                        self._certificate_names(
                            cert
                        )
                    )
                    if (
                        normalized :=
                        self._normalize_dns_name(
                            raw_name
                        )
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
                            f"unique DNS names"
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
        # Native SSLCertificate uses subject as primary.
        #
        # Therefore:
        #
        # subject ->
        #     fingerprint -> certificate observation
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
        # Collect certificate history and domains.
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
                # Discover hostname-like values from both
                # Subject CN and SAN.
                #
                for raw_name in (
                    self._certificate_names(
                        cert
                    )
                ):
                    name = (
                        self._normalize_dns_name(
                            raw_name
                        )
                    )

                    if not name:
                        continue

                    node = self._safe_domain(
                        name
                    )

                    if node is None:
                        continue

                    domain_nodes.setdefault(
                        node.domain,
                        node,
                    )

                    #
                    # Only in-scope children of the queried
                    # domain receive DISCOVERED_VIA_CT.
                    #
                    # External SANs are still connected to
                    # the certificate later.
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
        # Build aggregated native certificate nodes.
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

            #
            # Latest issuance is used for the native
            # SSLCertificate scalar properties.
            #
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

            if latest.not_after is not None:
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

            #
            # Preserve full Shodan CT history.
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

            setattr(
                cert_node,
                "shodan_ct_certificates",
                [
                    {
                        "hash": cert.hash,
                        "subject_cn": (
                            cert.subject_cn
                        ),
                        "issuer_cn": (
                            cert.issuer_cn
                        ),
                        "not_before": (
                            self._epoch_to_iso(
                                cert.not_before
                            )
                        ),
                        "not_after": (
                            self._epoch_to_iso(
                                cert.not_after
                            )
                        ),
                        "san_dns_names": (
                            cert.san_dns_names
                        ),
                    }
                    for cert in certs
                ],
            )

            certificate_nodes[
                subject
            ] = cert_node

            #
            # Queried Domain -> certificate.
            #
            for query_domain in (
                queries_by_subject[
                    subject
                ]
            ):
                relationships.add(
                    (
                        (
                            "Domain",
                            query_domain,
                        ),
                        (
                            "SSLCertificate",
                            subject,
                        ),
                        "HAS_CT_CERTIFICATE",
                    )
                )

            #
            # Certificate -> Subject CN Domain.
            #
            normalized_subject = (
                self._normalize_dns_name(
                    subject
                )
            )

            if normalized_subject:
                subject_domain = (
                    self._safe_domain(
                        normalized_subject
                    )
                )

                if subject_domain:
                    domain_nodes.setdefault(
                        subject_domain.domain,
                        subject_domain,
                    )

                    relationships.add(
                        (
                            (
                                "SSLCertificate",
                                subject,
                            ),
                            (
                                "Domain",
                                subject_domain.domain,
                            ),
                            "HAS_SUBJECT",
                        )
                    )

            #
            # Certificate -> SAN Domain.
            #
            for raw_san in raw_sans:
                san = self._safe_domain(
                    raw_san
                )

                if san is None:
                    continue

                domain_nodes.setdefault(
                    san.domain,
                    san,
                )

                relationships.add(
                    (
                        (
                            "SSLCertificate",
                            subject,
                        ),
                        (
                            "Domain",
                            san.domain,
                        ),
                        "HAS_SAN",
                    )
                )

        #
        # Create unique Domain nodes.
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
        # Create unique certificate nodes.
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
        # Create unique graph relationships.
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

        #
        # Defensive fallback if Shodan ever
        # returns a certificate without subject_cn.
        #
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
        # *.foo.example.com
        # becomes:
        #
        # foo.example.com
        #
        while value.startswith(
            "*."
        ):
            value = value[2:]

        return value or None

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
            #
            # Preserve the original value on the
            # certificate instead of inventing a
            # malformed Domain node.
            #
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

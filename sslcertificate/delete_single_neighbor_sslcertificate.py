from typing import List

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ssl_certificate import SSLCertificate


@flowsint_enricher
class DeleteSingleNeighborSSLCertificateEnricher(Enricher):
    """
    Delete an SSL certificate node when it has exactly one direct neighbour.

    The node deletion uses Flowsint's graph service, so the certificate and its
    relationships are soft-deleted in the current sketch.
    """

    InputType = SSLCertificate
    OutputType = SSLCertificate

    @classmethod
    def name(cls) -> str:
        return "sslcertificate_delete_single_neighbor"

    @classmethod
    def category(cls) -> str:
        return "SSLCertificate"

    @classmethod
    def key(cls) -> str:
        return "subject"

    @classmethod
    def required_params(cls) -> bool:
        return False

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        # No external lookup is needed. The actual graph inspection and deletion
        # happen in postprocess(), where the graph service is available.
        return data

    def postprocess(
        self,
        results: List[OutputType],
        input_data: List[InputType] = None,
    ) -> List[OutputType]:
        certificates = input_data or results or []

        if not certificates:
            return []

        try:
            # The enricher input contains the SSLCertificate properties, but not
            # the Neo4j element ID required by delete_nodes(). Resolve the graph
            # nodes once and match certificates by their type + node label.
            graph = self.graph_service.get_sketch_graph()

            certificate_nodes = {
                node.nodeLabel: node
                for node in graph.nodes
                if node.nodeType == "sslcertificate"
            }

            for certificate in certificates:
                label = certificate.nodeLabel or certificate.subject
                graph_node = certificate_nodes.get(label)

                if graph_node is None:
                    Logger.warn(
                        self.sketch_id,
                        {
                            "message": (
                                f"[SSL Certificate Cleanup] Could not resolve graph node "
                                f"for certificate '{label}'."
                            )
                        },
                    )
                    continue

                neighborhood = self.graph_service.get_neighbors(graph_node.id)

                # get_neighbors() includes the center node itself in nodes, so
                # remove it before counting unique directly connected nodes.
                neighbours = [
                    node
                    for node in neighborhood.nodes
                    if node.id != graph_node.id
                ]

                neighbour_count = len(neighbours)

                if neighbour_count != 1:
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": (
                                f"[SSL Certificate Cleanup] Keeping '{label}': "
                                f"found {neighbour_count} neighbour(s)."
                            )
                        },
                    )
                    continue

                deleted_count = self.graph_service.delete_nodes([graph_node.id])

                if deleted_count:
                    neighbour = neighbours[0]
                    self.log_graph_message(
                        f"Deleted SSL certificate '{label}' because it had exactly "
                        f"one neighbour: {neighbour.nodeType} '{neighbour.nodeLabel}'"
                    )
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": (
                                f"[SSL Certificate Cleanup] Deleted '{label}' because "
                                f"it had exactly one neighbour."
                            )
                        },
                    )
                else:
                    Logger.warn(
                        self.sketch_id,
                        {
                            "message": (
                                f"[SSL Certificate Cleanup] '{label}' matched the deletion "
                                f"criteria, but no node was deleted."
                            )
                        },
                    )

        except Exception as exc:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        f"[SSL Certificate Cleanup] Error while pruning certificates: {exc}"
                    )
                },
            )

        # This is an action/filter enricher. It does not create output nodes.
        return []


InputType = DeleteSingleNeighborSSLCertificateEnricher.InputType
OutputType = DeleteSingleNeighborSSLCertificateEnricher.OutputType

import os
import time
from typing import Any, Dict, List

import requests
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.port import Port


class NmapaaSClient:
    """REST client for creating and polling NmapaaS scans."""

    BASE_URL = "https://nmapaas.ozeliurs.com"
    TERMINAL_STATUSES = {"cancelled", "completed", "failed"}

    def __init__(self, api_key: str, timeout: int = 30) -> None:
        if not api_key:
            raise ValueError("NMAPAAS_API_KEY is missing")

        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "Flowsint-NmapaaS-Enricher/1.0",
            }
        )

    def create_scan(self, target: str, profile: str) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.BASE_URL}/v1/scans",
            json={"target": target, "profile": profile},
            timeout=self.timeout,
        )
        return self._payload(response, expected_status=202)

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        response = self.session.get(
            f"{self.BASE_URL}/v1/scans/{scan_id}",
            timeout=self.timeout,
        )
        return self._payload(response, expected_status=200)

    def wait_for_scan(
        self,
        scan: Dict[str, Any],
        poll_interval: int,
        max_wait: int,
    ) -> Dict[str, Any]:
        scan_id = scan.get("id")
        if not scan_id:
            raise RuntimeError("NmapaaS create response did not contain a scan ID")

        deadline = time.monotonic() + max_wait
        current = scan

        while str(current.get("status") or "").lower() not in self.TERMINAL_STATUSES:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"NmapaaS scan {scan_id} did not finish within {max_wait} seconds"
                )

            time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))
            current = self.get_scan(str(scan_id))

        return current

    @staticmethod
    def _payload(response: requests.Response, expected_status: int) -> Dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"NmapaaS returned a non-JSON response (HTTP {response.status_code})"
            ) from exc

        if response.status_code != expected_status:
            detail = payload.get("detail") if isinstance(payload, dict) else None
            raise RuntimeError(
                f"NmapaaS returned HTTP {response.status_code}: {detail or 'request failed'}"
            )

        if not isinstance(payload, dict):
            raise RuntimeError("NmapaaS returned an unexpected response format")

        return payload


class NmapaaSResult(BaseModel):
    ip: Ip
    ports: List[Port] = Field(default_factory=list)


@flowsint_enricher
class IpToNmapaaSEnricher(Enricher):
    """[NMAPAAS] Actively scan an IP address and add its open ports."""

    InputType = Ip
    OutputType = NmapaaSResult

    @classmethod
    def name(cls) -> str:
        return "ip_to_nmapaas"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def required_params(cls) -> bool:
        return True

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "NMAPAAS_API_KEY",
                "type": "vaultSecret",
                "description": "API key for nmapaas.ozeliurs.com.",
                "required": True,
            },
            {
                "name": "profile",
                "type": "select",
                "description": "Nmap scan profile.",
                "required": False,
                "default": "standard",
                "options": [
                    {"label": "Quick", "value": "quick"},
                    {"label": "Standard", "value": "standard"},
                    {"label": "Full", "value": "full"},
                ],
            },
            {
                "name": "poll_interval",
                "type": "number",
                "description": "Seconds between scan status checks.",
                "required": False,
                "default": 5,
            },
            {
                "name": "max_wait",
                "type": "number",
                "description": "Maximum seconds to wait for each scan.",
                "required": False,
                "default": 900,
            },
            {
                "name": "timeout",
                "type": "number",
                "description": "HTTP request timeout in seconds.",
                "required": False,
                "default": 30,
            },
        ]

    @classmethod
    def documentation(cls) -> str:
        return """
        Actively scans each IP address through nmapaas.ozeliurs.com and waits for
        the asynchronous scan to complete. Open services are represented as Port
        nodes connected to the input IP with HAS_PORT relationships.

        The Nmap service, product, version, banner, scanner version, scan profile,
        location and scan ID are retained on the resulting graph entities.

        This enricher performs active network reconnaissance. Ensure that you are
        authorized to scan every supplied target.
        """

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        api_key = self.get_secret("NMAPAAS_API_KEY", os.getenv("NMAPAAS_API_KEY"))

        if not api_key:
            Logger.error(
                self.sketch_id,
                {
                    "message": (
                        "[NMAPAAS] Missing NMAPAAS_API_KEY. "
                        "Configure it in the Flowsint vault."
                    )
                },
            )
            return results

        params = self.params or {}
        profile = str(params.get("profile", "standard")).lower()
        if profile not in {"quick", "standard", "full"}:
            Logger.error(
                self.sketch_id,
                {"message": f"[NMAPAAS] Invalid scan profile: {profile}"},
            )
            return results

        poll_interval = self._bounded_int(params.get("poll_interval"), 5, 1, 300)
        max_wait = self._bounded_int(params.get("max_wait"), 900, 1, 86400)
        timeout = self._bounded_int(params.get("timeout"), 30, 1, 300)
        client = NmapaaSClient(api_key=api_key, timeout=timeout)

        for input_ip in data:
            try:
                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[NMAPAAS] Starting {profile} scan for {input_ip.address}"
                        )
                    },
                )
                created = client.create_scan(input_ip.address, profile)
                completed = client.wait_for_scan(created, poll_interval, max_wait)

                status = str(completed.get("status") or "").lower()
                if status != "completed":
                    raise RuntimeError(
                        f"scan ended with status {status or 'unknown'}: "
                        f"{completed.get('error') or 'no error details'}"
                    )

                ports = self._build_ports(completed)
                enriched_ip = input_ip.model_copy(deep=True)
                setattr(enriched_ip, "nmapaas_scan_id", completed.get("id"))
                setattr(enriched_ip, "nmapaas_profile", completed.get("profile"))
                setattr(enriched_ip, "nmapaas_location", completed.get("location"))
                setattr(enriched_ip, "nmapaas_completed_at", completed.get("completed_at"))
                setattr(enriched_ip, "nmapaas_open_port_count", len(ports))

                results.append(NmapaaSResult(ip=enriched_ip, ports=ports))
                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"[NMAPAAS] {input_ip.address}: found "
                            f"{len(ports)} open port(s)"
                        )
                    },
                )
            except Exception as exc:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": (
                            f"[NMAPAAS] Error scanning {input_ip.address}: {exc}"
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

        for result in results:
            self.create_node(result.ip)
            for port in result.ports:
                self.create_node(port)
                self.create_relationship(result.ip, port, "HAS_PORT")
                protocol = f"/{port.protocol}" if port.protocol else ""
                service = f" ({port.service})" if port.service else ""
                self.log_graph_message(
                    f"[NMAPAAS] Open port {port.number}{protocol}{service} "
                    f"found on {result.ip.address}"
                )

        return results

    @staticmethod
    def _build_ports(scan: Dict[str, Any]) -> List[Port]:
        result = scan.get("result")
        if not isinstance(result, dict):
            return []

        scanner = result.get("scanner")
        nmap_version = result.get("nmap_version")
        ports: List[Port] = []
        seen = set()

        for host in result.get("hosts") or []:
            if not isinstance(host, dict):
                continue
            for raw_port in host.get("ports") or []:
                if not isinstance(raw_port, dict):
                    continue
                if str(raw_port.get("state") or "").lower() != "open":
                    continue

                try:
                    number = int(raw_port.get("port"))
                except (TypeError, ValueError):
                    continue
                if not 0 <= number <= 65535:
                    continue

                protocol = str(raw_port.get("protocol") or "").upper() or None
                key = (number, protocol)
                if key in seen:
                    continue
                seen.add(key)

                banner = raw_port.get("banner")
                if banner is not None:
                    banner = str(banner)[:8000]

                port = Port(
                    number=number,
                    protocol=protocol,
                    state="open",
                    service=raw_port.get("service"),
                    banner=banner,
                )
                setattr(port, "nmap_product", raw_port.get("product"))
                setattr(port, "nmap_version", raw_port.get("version"))
                setattr(port, "nmap_scanner", scanner)
                setattr(port, "nmap_scanner_version", nmap_version)
                setattr(port, "nmapaas_scan_id", scan.get("id"))
                ports.append(port)

        return ports

    @staticmethod
    def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(parsed, maximum))


InputType = IpToNmapaaSEnricher.InputType
OutputType = IpToNmapaaSEnricher.OutputType

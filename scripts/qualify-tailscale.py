#!/usr/bin/env python3
"""Run the real Tailscale LocalAPI qualification without touching an app."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

from agentctl.trusted import (  # noqa: E402
    TailscaleLocalAPIClient,
    TailscaleLocalAPITransportVerifier,
    TransportObservation,
    TrustedAccessError,
)


def _status(name: str, value: str, detail: str = "") -> dict[str, str]:
    result = {"name": name, "status": value}
    if detail:
        result["detail"] = detail
    return result


def _tailscale_ip() -> str:
    result = subprocess.run(
        ["tailscale", "ip", "-1"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    address = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if not address:
        raise RuntimeError("tailscale ip -1 returned no address")
    return address


def _real_socket_observation(address: str) -> TransportObservation:
    server = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_address = (address, 0, 0, 0) if ":" in address else (address, 0)
    server.bind(bind_address)
    server.listen(1)
    port = server.getsockname()[1]
    connect_address = (address, port, 0, 0) if ":" in address else (address, port)
    client = socket.create_connection(connect_address, timeout=3)
    try:
        connection, _ = server.accept()
        with connection:
            peer = connection.getpeername()[0]
        return TransportObservation("tailscale", peer)
    finally:
        client.close()
        server.close()


def _assert_rejected(operation) -> bool:
    try:
        operation()
    except TrustedAccessError:
        return True
    return False


def qualify(socket_path: str) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    path = Path(socket_path)
    socket_ready = path.exists() and stat.S_ISSOCK(path.stat().st_mode)
    checks.append(_status("TAILSCALE_LOCALAPI", "PASS" if socket_ready else "FAIL", str(path)))
    if not socket_ready:
        return {"overall": "FAIL", "checks": checks}

    try:
        address = _tailscale_ip()
        observation = _real_socket_observation(address)
        checks.append(_status("REAL_TAILSCALE_CONNECTION", "PASS", f"local address={address}"))
        checks.append(
            _status(
                "SOCKET_PEER_BINDING",
                "PASS" if observation.peer_address == address else "FAIL",
                f"observed={observation.peer_address}",
            )
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        checks.append(_status("REAL_TAILSCALE_CONNECTION", "FAIL", str(exc)))
        return {"overall": "FAIL", "checks": checks}

    client = TailscaleLocalAPIClient(socket_path)
    verifier = TailscaleLocalAPITransportVerifier(client)
    try:
        evidence = verifier.verify(observation)
        peer = evidence.tailscale_peer
        checks.append(_status("TAILSCALE_WHOIS", "PASS", peer.resolver if peer else ""))
        checks.append(_status("NODE_IDENTITY", "PASS" if peer and peer.stable_id else "FAIL", peer.stable_id if peer else ""))
        if peer and peer.user_id and peer.login_name:
            checks.append(_status("USER_IDENTITY", "PASS", peer.login_name))
        else:
            checks.append(_status("USER_IDENTITY", "NOT_AVAILABLE_WITH_REASON", "WhoIs did not return a complete user profile"))
        checks.append(_status("TAG_IDENTITY", "PASS" if peer and peer.tags else "NOT_CONFIGURED", "" if peer and peer.tags else "WhoIs node has no ACL tags"))
    except TrustedAccessError as exc:
        checks.append(_status("TAILSCALE_WHOIS", "FAIL", exc.code))
        return {"overall": "FAIL", "checks": checks}

    spoofed = _assert_rejected(
        lambda: verifier.verify(
            TransportObservation(
                "tailscale",
                observation.peer_address,
                forwarded_headers_present=True,
            )
        )
    )
    checks.append(_status("SPOOFED_HEADERS_REJECTED_OR_IGNORED", "PASS" if spoofed else "FAIL"))

    unavailable = _assert_rejected(
        lambda: TailscaleLocalAPITransportVerifier(
            TailscaleLocalAPIClient(str(path) + ".missing")
        ).verify(observation)
    )
    checks.append(_status("LOCALAPI_FAILURE_FAIL_CLOSED", "PASS" if unavailable else "FAIL"))

    unknown_address = "100.64.0.1" if address != "100.64.0.1" else "100.64.0.2"
    unknown = _assert_rejected(
        lambda: verifier.verify(TransportObservation("tailscale", unknown_address))
    )
    checks.append(_status("UNKNOWN_PEER_FAIL_CLOSED", "PASS" if unknown else "FAIL", unknown_address))

    # There is no IP-only branch in TailscaleLocalAPITransportVerifier. A
    # provider with an unavailable LocalAPI must reject even an in-range IP.
    ip_only_disabled = _assert_rejected(
        lambda: TailscaleLocalAPITransportVerifier(
            TailscaleLocalAPIClient(str(path) + ".missing")
        ).verify(TransportObservation("tailscale", observation.peer_address))
    )
    checks.append(_status("IP_ONLY_TRUST_DISABLED", "PASS" if ip_only_disabled else "FAIL"))

    allowed = {"PASS", "NOT_AVAILABLE_WITH_REASON", "NOT_CONFIGURED"}
    overall = "PASS" if all(item["status"] in allowed for item in checks) else "FAIL"
    return {"overall": overall, "socket_path": socket_path, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=os.environ.get("TAILSCALE_SOCKET", "/run/tailscale/tailscaled.sock"))
    args = parser.parse_args()
    try:
        result = qualify(args.socket)
    except Exception as exc:  # qualification output must remain machine-readable
        result = {"overall": "FAIL", "checks": [_status("HARNESS", "FAIL", str(exc))]}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

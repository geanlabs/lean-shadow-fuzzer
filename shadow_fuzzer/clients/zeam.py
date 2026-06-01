from __future__ import annotations

import re
from typing import Any

from .base import ClientParser, parse_block_size_bytes

_SOURCE = "zeam_text"

_ZEAM_TS_RE = re.compile(r"[A-Z][a-z]{2}-\d{2}\s+(\d+):(\d+):(\d+)\.(\d+)")


class ZeamParser(ClientParser):
    name = "zeam"
    attestation_id_warning = (
        "zeam text fallback uses (slot, validator_id), not a cryptographic attestation ID"
    )

    def match_host(self, host_name: str) -> bool:
        return True

    def parse_timestamp(self, line: str, default_ts_ms: float) -> float:
        m = _ZEAM_TS_RE.search(line)
        if m:
            h, mi, s, ms = m.groups()
            return (int(h) * 3600 + int(mi) * 60 + int(s) + int(ms) / 1_000) * 1000
        return default_ts_ms

    def parse_line(self, line: str, ts_ms: float) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        m = re.search(
            r"received gossip attestation for slot=(\d+)\s+validator=(\d+)", line
        )
        if m:
            events.append({
                "_kind": "receive_attestation",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "validator_id": int(m.group(2)),
                "source": _SOURCE,
            })
            return events

        m = re.search(r"received gossip block slot=(\d+)\s+proposer=(\d+)", line)
        if m:
            evt = {
                "_kind": "receive_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "source": _SOURCE,
            }
            size_bytes = parse_block_size_bytes(line)
            if size_bytes is not None:
                evt["size_bytes"] = size_bytes
            events.append(evt)
            return events

        m = re.search(
            r"received gossip block for slot=(\d+)\s+.*?proposer=(\d+)", line
        )
        if m:
            evt = {
                "_kind": "receive_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "source": _SOURCE,
            }
            size_bytes = parse_block_size_bytes(line)
            if size_bytes is not None:
                evt["size_bytes"] = size_bytes
            events.append(evt)
            return events

        m = re.search(
            r"published block to network:\s+slot=(\d+)\s+proposer=(\d+)", line
        )
        if m:
            evt = {
                "_kind": "publish_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "source": _SOURCE,
            }
            size_bytes = parse_block_size_bytes(line)
            if size_bytes is not None:
                evt["size_bytes"] = size_bytes
            events.append(evt)
            return events

        m = re.search(
            r"published attestation to network:\s+slot=(\d+)\s+validator=(\d+)", line
        )
        if m:
            events.append({
                "_kind": "publish_attestation",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "validator_id": int(m.group(2)),
                "source": _SOURCE,
            })
            return events

        return events

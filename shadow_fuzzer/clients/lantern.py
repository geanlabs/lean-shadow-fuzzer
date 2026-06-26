from __future__ import annotations

import re
from typing import Any

from .base import ClientParser, parse_block_size_bytes

_SOURCE = "lantern_text"

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3,9})Z"
)
_ROOT_RE = r"0x[0-9a-fA-F]+"


class LanternParser(ClientParser):
    name = "lantern"
    attestation_id_warning = (
        "lantern text parser uses (slot, validator_id), not a cryptographic "
        "attestation ID"
    )

    def match_host(self, host_name: str) -> bool:
        return host_name.startswith("lantern-")

    def parse_timestamp(self, line: str, default_ts_ms: float) -> float:
        m = _TS_RE.search(line)
        if m:
            _date, h, mi, s, frac = m.groups()
            ms = int(frac[:3])
            return (int(h) * 3600 + int(mi) * 60 + int(s) + ms / 1000) * 1000
        return default_ts_ms

    def parse_line(self, line: str, ts_ms: float) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        line = _ANSI_RE.sub("", line)

        m = re.search(
            rf"\[attest\]\s+slot\s+(\d+),\s+validator\s+(\d+),\s+"
            rf"target\s+({_ROOT_RE})\s+@\s+(\d+),\s+"
            rf"source\s+({_ROOT_RE})\s+@\s+(\d+)",
            line,
        )
        if m:
            events.append({
                "_kind": "publish_attestation",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "validator_id": int(m.group(2)),
                "target_root": m.group(3).lower(),
                "target_slot": int(m.group(4)),
                "source_root": m.group(5).lower(),
                "source_slot": int(m.group(6)),
                "source": _SOURCE,
            })
            return events

        m = re.search(
            rf"processed vote validator=(\d+)\s+slot=(\d+)\s+head=({_ROOT_RE})\s+"
            rf"target=({_ROOT_RE})@(\d+)\s+source=({_ROOT_RE})@(\d+)",
            line,
        )
        if m:
            events.append({
                "_kind": "receive_attestation",
                "ts": ts_ms / 1000,
                "validator_id": int(m.group(1)),
                "slot": int(m.group(2)),
                "head_root": m.group(3).lower(),
                "target_root": m.group(4).lower(),
                "target_slot": int(m.group(5)),
                "source_root": m.group(6).lower(),
                "source_slot": int(m.group(7)),
                "source": _SOURCE,
            })
            return events

        m = re.search(
            rf"received block slot=(\d+)\s+proposer=(\d+)\s+"
            rf"root=({_ROOT_RE})\s+source=(\S+)",
            line,
        )
        if m:
            root = m.group(3).lower()
            evt = {
                "_kind": "publish_block" if m.group(4) == "local" else "receive_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "block_hash": root,
                "block_root": root,
                "block_source": m.group(4),
                "source": _SOURCE,
            }
            size_bytes = parse_block_size_bytes(line)
            if size_bytes is not None:
                evt["size_bytes"] = size_bytes
            events.append(evt)
            return events

        return events

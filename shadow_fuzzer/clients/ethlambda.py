from __future__ import annotations

import re
from typing import Any

from .base import ClientParser

_SOURCE = "ethlambda_text"

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3,9})Z"
)
_BANDWIDTH_KV_RE = re.compile(
    r'\b(direction|protocol|message_kind|bytes|delivery|consensus_slot)=("[^"]*"|[^\s,]+)'
)


class EthlambdaParser(ClientParser):
    name = "ethlambda"
    attestation_id_warning = (
        "ethlambda text fallback uses (slot, validator_id), "
        "not a cryptographic attestation ID"
    )

    def match_host(self, host_name: str) -> bool:
        return host_name.startswith("ethlambda-")

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

        if "P2P bandwidth event" in line:
            fields = {
                key: value.strip('"')
                for key, value in _BANDWIDTH_KV_RE.findall(line)
            }
            required = {"direction", "protocol", "message_kind", "bytes", "delivery"}
            if required.issubset(fields):
                evt: dict[str, Any] = {
                    "_kind": "bandwidth",
                    "ts": ts_ms / 1000,
                    "direction": fields["direction"],
                    "protocol": fields["protocol"],
                    "message_kind": fields["message_kind"],
                    "bytes": int(fields["bytes"]),
                    "delivery": fields["delivery"],
                    "source": _SOURCE,
                }
                if "consensus_slot" in fields:
                    evt["consensus_slot"] = int(fields["consensus_slot"])
                events.append(evt)
            return events

        # --- receive_attestation (aggregated, via gossip) ---
        m = re.search(
            r"Received aggregated attestation from gossip "
            r"slot=(\d+)\s+target_slot=(\d+)\s+target_root=([0-9a-fA-F]+)\s+"
            r"source_slot=(\d+)\s+source_root=([0-9a-fA-F]+)",
            line,
        )
        if m:
            events.append({
                "_kind": "receive_attestation",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "target_slot": int(m.group(2)),
                "target_root": m.group(3).lower(),
                "source_slot": int(m.group(4)),
                "source_root": m.group(5).lower(),
                "source": _SOURCE,
            })
            return events

        # --- receive_attestation (aggregated, processed with num_participants) ---
        m = re.search(
            r"Aggregated attestation processed "
            r"slot=(\d+)\s+num_participants=(\d+)\s+"
            r"target_slot=(\d+)\s+target_root=([0-9a-fA-F]+)\s+"
            r"source_slot=(\d+)",
            line,
        )
        if m:
            events.append({
                "_kind": "receive_attestation",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "num_participants": int(m.group(2)),
                "target_slot": int(m.group(3)),
                "target_root": m.group(4).lower(),
                "source_slot": int(m.group(5)),
                "source": _SOURCE,
            })
            return events

        # --- publish_attestation ---
        m = re.search(
            r"Published attestation to gossipsub "
            r"slot=(\d+)\s+validator=(\d+)\s+subnet_id=(\d+)\s+"
            r"target_slot=(\d+)\s+target_root=([0-9a-fA-F]+)\s+"
            r"source_slot=(\d+)\s+source_root=([0-9a-fA-F]+)",
            line,
        )
        if m:
            events.append({
                "_kind": "publish_attestation",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "validator_id": int(m.group(2)),
                "subnet_id": int(m.group(3)),
                "target_slot": int(m.group(4)),
                "target_root": m.group(5).lower(),
                "source_slot": int(m.group(6)),
                "source_root": m.group(7).lower(),
                "source": _SOURCE,
            })
            return events

        # Also match the shorter "Published attestation slot=X validator_id=Y"
        m = re.search(
            r"ethlambda_blockchain: Published attestation slot=(\d+) validator_id=(\d+)",
            line,
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

        # --- receive_block ---
        m = re.search(
            r"Received block from gossip "
            r"slot=(\d+)\s+proposer=(\d+)\s+block_root=([0-9a-fA-F]+)\s+"
            r"parent_root=([0-9a-fA-F]+)\s+attestation_count=(\d+)",
            line,
        )
        if m:
            events.append({
                "_kind": "receive_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "block_root": m.group(3).lower(),
                "parent_root": m.group(4).lower(),
                "attestation_count": int(m.group(5)),
                "source": _SOURCE,
            })
            return events

        # --- publish_block ---
        m = re.search(
            r"Published block to gossipsub "
            r"slot=(\d+)\s+proposer=(\d+)\s+block_root=([0-9a-fA-F]+)\s+"
            r"parent_root=([0-9a-fA-F]+)\s+attestation_count=(\d+)",
            line,
        )
        if m:
            events.append({
                "_kind": "publish_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "block_root": m.group(3).lower(),
                "parent_root": m.group(4).lower(),
                "attestation_count": int(m.group(5)),
                "source": _SOURCE,
            })
            return events

        # Also match "Published block slot=X validator_id=Y"
        m = re.search(
            r"ethlambda_blockchain: Published block slot=(\d+) validator_id=(\d+)",
            line,
        )
        if m:
            events.append({
                "_kind": "publish_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(1)),
                "proposer": int(m.group(2)),
                "source": _SOURCE,
            })
            return events

        return events

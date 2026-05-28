from __future__ import annotations

import re
from typing import Any

from .base import ClientParser

_SOURCE_STRUCTURED = "qlean_structured"
_SOURCE_TEXT = "qlean_text"


class QleanParser(ClientParser):
    name = "qlean"

    def match_host(self, host_name: str) -> bool:
        return host_name.startswith("qlean")

    def parse_line(self, line: str, ts_ms: float) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        if "LEAN-INTEROP-TEST" in line:
            events.extend(self._parse_structured(line))
            return events

        m = re.search(
            r"Received block 0x([0-9a-fA-F]+)\s+@\s+(\d+)\s+parent=0x([0-9a-fA-F]+)",
            line,
        )
        if m:
            events.append({
                "_kind": "receive_block",
                "ts": ts_ms / 1000,
                "slot": int(m.group(2)),
                "block_hash": m.group(1).lower(),
                "parent": m.group(3).lower(),
                "source": _SOURCE_TEXT,
            })

        return events

    def _parse_structured(self, line: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        if "RECEIVE-ATTESTATION" in line:
            evt = self._parse_interop_attestation(line)
            if evt:
                evt["_kind"] = "receive_attestation"
                events.append(evt)
        elif "PUBLISH-BLOCK" in line:
            evt = self._parse_interop_publish_block(line)
            if evt:
                evt["_kind"] = "publish_block"
                events.append(evt)
        elif "PUBLISH-ATTESTATION" in line:
            evt = self._parse_interop_publish_attestation(line)
            if evt:
                evt["_kind"] = "publish_attestation"
                events.append(evt)

        return events

    @staticmethod
    def _parse_interop_attestation(line: str) -> dict[str, Any] | None:
        m = re.search(
            r'\["LEAN-INTEROP-TEST",\s*(\d+),\s*"RECEIVE-ATTESTATION",\s*\[(\d+),\s*\[([^\]]+)\]',
            line,
        )
        if not m:
            return None
        ts_ms = int(m.group(1))
        validator_id = int(m.group(2))
        inner = m.group(3).strip()
        parts = [p.strip().strip('"') for p in inner.split(",")]
        if len(parts) < 5:
            return None
        return {
            "ts_ms": ts_ms,
            "validator_id": validator_id,
            "source_slot": int(parts[0]),
            "target_slot": int(parts[1]),
            "head_slot": int(parts[2]),
            "slot": int(parts[3]),
            "block_hash": parts[4],
            "source": _SOURCE_STRUCTURED,
        }

    @staticmethod
    def _parse_interop_publish_block(line: str) -> dict[str, Any] | None:
        m = re.search(
            r'\["LEAN-INTEROP-TEST",\s*(\d+),\s*"PUBLISH-BLOCK",\s*(\{.+\})\]', line
        )
        if not m:
            return None
        ts_ms = int(m.group(1))
        payload = m.group(2)
        slot_m = re.search(r'"slot":\s*(\d+)', payload)
        hash_m = re.search(r'"hash":\s*"([0-9a-f]+)"', payload)
        proposer_m = re.search(r'"proposer":\s*(\d+)', payload)
        if not slot_m:
            return None
        return {
            "ts_ms": ts_ms,
            "slot": int(slot_m.group(1)),
            "block_hash": hash_m.group(1) if hash_m else "",
            "proposer": int(proposer_m.group(1)) if proposer_m else 0,
            "source": _SOURCE_STRUCTURED,
        }

    @staticmethod
    def _parse_interop_publish_attestation(line: str) -> dict[str, Any] | None:
        m = re.search(
            r'\["LEAN-INTEROP-TEST",\s*(\d+),\s*"PUBLISH-ATTESTATION",\s*\[(\d+),\s*\[([^\]]+)\]',
            line,
        )
        if not m:
            return None
        ts_ms = int(m.group(1))
        validator_id = int(m.group(2))
        inner = m.group(3).strip()
        parts = [p.strip().strip('"') for p in inner.split(",")]
        if len(parts) < 4:
            return None
        return {
            "ts_ms": ts_ms,
            "validator_id": validator_id,
            "slot": int(parts[3]),
            "source": _SOURCE_STRUCTURED,
        }

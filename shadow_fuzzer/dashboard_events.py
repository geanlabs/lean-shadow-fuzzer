"""Dashboard event extraction helpers for Shadow fuzzer runs.

This module wraps the existing stats-shadow.py parser and normalizes its
internal event names into the public dashboard event taxonomy.
"""

from __future__ import annotations

import hashlib
import contextlib
import io
import json
import re
from pathlib import Path
from typing import Any

from . import stats_shadow as _STATS_SHADOW


KIND_MAP = {
    "publish_attestation": "attestation_sent",
    "receive_attestation": "attestation_received",
    "publish_block": "block_published",
    "receive_block": "block_received",
    "chain_status": "chain_status",
}


def _hosts_dir_for_run(run_dir: Path) -> Path | None:
    candidates = [
        run_dir / "shadow.data" / "hosts",
        run_dir / "hosts",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def event_ts_ms(event: dict[str, Any]) -> float:
    return float(_STATS_SHADOW._event_ts_ms(event))


def event_key(run_id: str, event: dict[str, Any]) -> str:
    payload = {
        "run_id": run_id,
        "kind": event.get("kind"),
        "host": event.get("host"),
        "slot": event.get("slot"),
        "ts_ms": round(float(event.get("ts_ms", 0.0)), 3),
        "message": event.get("message"),
        "payload": event.get("payload", {}),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha1(encoded).hexdigest()


def _block_label(event: dict[str, Any]) -> str:
    block_hash = str(event.get("block_hash") or "")
    if block_hash:
        return f"0x{block_hash[:10]}"
    proposer = event.get("proposer")
    if proposer is not None:
        return f"proposer {proposer}"
    return "block"


def _event_message(kind: str, host: str, event: dict[str, Any]) -> str:
    slot = event.get("slot")
    if kind == "attestation_sent":
        validator = event.get("validator_id")
        suffix = f" by validator {validator}" if validator is not None else ""
        return f"{host} sent attestation for slot {slot}{suffix}."
    if kind == "attestation_received":
        validator = event.get("validator_id")
        suffix = f" from validator {validator}" if validator is not None else ""
        return f"{host} received attestation for slot {slot}{suffix}."
    if kind == "block_published":
        return f"{host} published {_block_label(event)} at slot {slot}."
    if kind == "block_received":
        return f"{host} received {_block_label(event)} at slot {slot}."
    if kind == "chain_status":
        return (
            f"{host} reported head {event.get('head_slot')}, "
            f"justified {event.get('latest_justified_slot')}, "
            f"finalized {event.get('latest_finalized_slot')}."
        )
    return f"{host} emitted {kind}."


def _normalize_event(raw_kind: str, host: str, event: dict[str, Any]) -> dict[str, Any]:
    kind = KIND_MAP[raw_kind]
    slot = event.get("slot")
    if slot is None and raw_kind == "chain_status":
        slot = event.get("head_slot")
    payload = dict(event)
    payload.pop("host", None)
    return {
        "kind": kind,
        "host": host,
        "slot": int(slot) if slot is not None else None,
        "ts_ms": round(event_ts_ms(event), 3),
        "message": _event_message(kind, host, event),
        "payload": payload,
    }


def _derive_chain_delta_events(host: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    derived: list[dict[str, Any]] = []
    previous_justified = -1
    previous_finalized = -1

    for event in sorted(events, key=event_ts_ms):
        ts_ms = round(event_ts_ms(event), 3)
        justified = int(event.get("latest_justified_slot", -1))
        finalized = int(event.get("latest_finalized_slot", -1))

        if justified > previous_justified:
            derived.append(
                {
                    "kind": "justified",
                    "host": host,
                    "slot": justified,
                    "ts_ms": ts_ms,
                    "message": f"{host} advanced justified checkpoint to slot {justified}.",
                    "payload": {
                        "source_chain_slot": event.get("slot"),
                        "root": event.get("latest_justified_root"),
                        "head_slot": event.get("head_slot"),
                    },
                }
            )
            previous_justified = justified

        if finalized > previous_finalized:
            derived.append(
                {
                    "kind": "finalized",
                    "host": host,
                    "slot": finalized,
                    "ts_ms": ts_ms,
                    "message": f"{host} advanced finalized checkpoint to slot {finalized}.",
                    "payload": {
                        "source_chain_slot": event.get("slot"),
                        "root": event.get("latest_finalized_root"),
                        "head_slot": event.get("head_slot"),
                    },
                }
            )
            previous_finalized = finalized

    return derived


AGGREGATION_SLOT_RE = re.compile(r"\bslot[=:]\s*(\d+)")


def _aggregation_events_from_logs(hosts_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for host_dir in sorted(hosts_dir.iterdir()):
        if not host_dir.is_dir():
            continue
        host = host_dir.name
        files = [
            *sorted(host_dir.glob("*.stdout")),
            *sorted(host_dir.glob("*.stderr")),
            *sorted(host_dir.glob("**/consensus.log")),
        ]
        for file_path in files:
            with open(file_path, errors="replace") as f:
                for line in f:
                    lower = line.lower()
                    if "aggregation" not in lower and "aggregate" not in lower:
                        continue
                    if "receive" not in lower and "received" not in lower:
                        continue
                    ts_ms = round(float(_STATS_SHADOW.parse_shadow_timestamp(line)) * 1000, 3)
                    slot_m = AGGREGATION_SLOT_RE.search(line)
                    slot = int(slot_m.group(1)) if slot_m else None
                    clean = _STATS_SHADOW.ANSI_RE.sub("", line).strip()
                    events.append(
                        {
                            "kind": "aggregation_received",
                            "host": host,
                            "slot": slot,
                            "ts_ms": ts_ms,
                            "message": clean[:240] or f"{host} received aggregation.",
                            "payload": {
                                "source": "text_pattern",
                                "file": str(file_path.relative_to(hosts_dir)),
                            },
                        }
                    )
    return events


def _aggregation_event_from_line(hosts_dir: Path, host: str, file_path: Path, line: str) -> dict[str, Any] | None:
    lower = line.lower()
    if "aggregation" not in lower and "aggregate" not in lower:
        return None
    if "receive" not in lower and "received" not in lower:
        return None
    ts_ms = round(float(_STATS_SHADOW.parse_shadow_timestamp(line)) * 1000, 3)
    slot_m = AGGREGATION_SLOT_RE.search(line)
    slot = int(slot_m.group(1)) if slot_m else None
    clean = _STATS_SHADOW.ANSI_RE.sub("", line).strip()
    return {
        "kind": "aggregation_received",
        "host": host,
        "slot": slot,
        "ts_ms": ts_ms,
        "message": clean[:240] or f"{host} received aggregation.",
        "payload": {
            "source": "text_pattern",
            "file": str(file_path.relative_to(hosts_dir)),
        },
    }


def _chain_delta_events_from_previous(
    host: str,
    event: dict[str, Any],
    previous_justified: int,
    previous_finalized: int,
) -> tuple[list[dict[str, Any]], int, int]:
    derived: list[dict[str, Any]] = []
    ts_ms = round(event_ts_ms(event), 3)
    justified = int(event.get("latest_justified_slot", -1))
    finalized = int(event.get("latest_finalized_slot", -1))

    if justified > previous_justified:
        derived.append(
            {
                "kind": "justified",
                "host": host,
                "slot": justified,
                "ts_ms": ts_ms,
                "message": f"{host} advanced justified checkpoint to slot {justified}.",
                "payload": {
                    "source_chain_slot": event.get("slot"),
                    "root": event.get("latest_justified_root"),
                    "head_slot": event.get("head_slot"),
                },
            }
        )
        previous_justified = justified

    if finalized > previous_finalized:
        derived.append(
            {
                "kind": "finalized",
                "host": host,
                "slot": finalized,
                "ts_ms": ts_ms,
                "message": f"{host} advanced finalized checkpoint to slot {finalized}.",
                "payload": {
                    "source_chain_slot": event.get("slot"),
                    "root": event.get("latest_finalized_root"),
                    "head_slot": event.get("head_slot"),
                },
            }
        )
        previous_finalized = finalized

    return derived, previous_justified, previous_finalized


class IncrementalEventReader:
    """Read only newly appended Shadow host-log lines."""

    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir)
        self._offsets: dict[Path, int] = {}
        self._pending_chain_status: dict[str, dict[str, Any]] = {}
        self._last_ts_ms: dict[str, float] = {}
        self._previous_justified: dict[str, int] = {}
        self._previous_finalized: dict[str, int] = {}
        self.max_ts_ms = 0.0

    def _files(self, hosts_dir: Path) -> list[tuple[str, Path]]:
        files: list[tuple[str, Path]] = []
        for host_dir in sorted(hosts_dir.iterdir()):
            if not host_dir.is_dir():
                continue
            host = host_dir.name
            for pattern in ("*.stdout", "*.stderr", "**/consensus.log"):
                for file_path in sorted(host_dir.glob(pattern)):
                    files.append((host, file_path))
        return files

    def read_new_events(self) -> list[dict[str, Any]]:
        hosts_dir = _hosts_dir_for_run(self.run_dir)
        if hosts_dir is None:
            return []

        events: list[dict[str, Any]] = []
        for host, file_path in self._files(hosts_dir):
            try:
                size = file_path.stat().st_size
            except FileNotFoundError:
                continue
            offset = self._offsets.get(file_path, 0)
            if size < offset:
                offset = 0
            if size == offset:
                continue

            parser = _STATS_SHADOW.get_parser_for_host(host)
            with open(file_path, errors="replace") as f:
                f.seek(offset)
                for line in f:
                    events.extend(
                        self._events_from_line(
                            hosts_dir,
                            host,
                            file_path,
                            parser,
                            line.rstrip("\n"),
                        )
                    )
                self._offsets[file_path] = f.tell()

        return sorted(events, key=lambda e: (float(e.get("ts_ms") or 0.0), e.get("host") or ""))

    def _events_from_line(
        self,
        hosts_dir: Path,
        host: str,
        file_path: Path,
        parser: Any,
        line: str,
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        shadow_ts_ms = _STATS_SHADOW.parse_shadow_timestamp(line) * 1000
        if shadow_ts_ms > 0:
            self._last_ts_ms[host] = shadow_ts_ms

        ts_ms = parser.parse_timestamp(line, shadow_ts_ms or self._last_ts_ms.get(host, 0.0))
        if ts_ms == 0.0:
            ts_ms = shadow_ts_ms or self._last_ts_ms.get(host, 0.0)

        pending = self._pending_chain_status.get(host)
        if pending is not None:
            done = _STATS_SHADOW._parse_chain_status_line(line, pending)
            if done and _STATS_SHADOW._chain_status_complete(pending):
                if pending["slot"] >= 0:
                    normalized = _normalize_event("chain_status", host, pending)
                    events.append(normalized)
                    derived, prev_j, prev_f = _chain_delta_events_from_previous(
                        host,
                        pending,
                        self._previous_justified.get(host, -1),
                        self._previous_finalized.get(host, -1),
                    )
                    events.extend(derived)
                    self._previous_justified[host] = prev_j
                    self._previous_finalized[host] = prev_f
                self._pending_chain_status.pop(host, None)

        if "CHAIN STATUS" in line:
            pending = {
                "ts_ms": round(ts_ms, 1),
                "source": f"{parser.name}_text",
            }
            _STATS_SHADOW._parse_chain_status_line(line, pending)
            self._pending_chain_status[host] = pending
        else:
            for event in parser.parse_line(line, ts_ms):
                raw_kind = event.pop("_kind", None)
                if raw_kind and raw_kind in KIND_MAP:
                    events.append(_normalize_event(raw_kind, host, event))

        aggregation = _aggregation_event_from_line(hosts_dir, host, file_path, line)
        if aggregation:
            events.append(aggregation)

        for event in events:
            self.max_ts_ms = max(self.max_ts_ms, float(event.get("ts_ms") or 0.0))
        return events


def events_from_run(run_dir: str | Path) -> list[dict[str, Any]]:
    run_path = Path(run_dir)
    hosts_dir = _hosts_dir_for_run(run_path)
    if hosts_dir is None:
        return []

    nested = _STATS_SHADOW._read_host_events(hosts_dir)
    events: list[dict[str, Any]] = []
    for raw_kind, by_host in nested.items():
        for host, host_events in by_host.items():
            for event in host_events:
                events.append(_normalize_event(raw_kind, host, event))
            if raw_kind == "chain_status":
                events.extend(_derive_chain_delta_events(host, host_events))

    events.extend(_aggregation_events_from_logs(hosts_dir))
    return sorted(events, key=lambda e: (float(e.get("ts_ms") or 0.0), e.get("host") or ""))


def max_simulated_seconds_from_run(run_dir: str | Path) -> float:
    max_ms = 0.0
    for event in events_from_run(run_dir):
        max_ms = max(max_ms, float(event.get("ts_ms") or 0.0))
    return max_ms / 1000


def stats_from_run(run_dir: str | Path, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    run_path = Path(run_dir)
    if metadata is None:
        metadata_path = run_path / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
    with contextlib.redirect_stdout(io.StringIO()):
        return _STATS_SHADOW.collect_stats(str(run_path), metadata)

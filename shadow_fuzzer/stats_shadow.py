#!/usr/bin/env python3
"""Parse Shadow simulation output and emit stats.json with propagation data.

Reads shadow.data host stdout/stderr logs, plus regions.json, bandwidths.json,
and run-metadata.json (passed via --metadata-json), then writes a single stats.json
with the resolved run configuration embedded.

Client-specific log parsing is delegated to ClientParser implementations
registered in shadow_fuzzer.clients.

Usage:
  python3 stats-shadow.py <run_dir> --metadata-json <path>
"""

import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

# Ensure repository root is in sys.path when run as a standalone script
fuzzer_root = Path(__file__).resolve().parent.parent
if str(fuzzer_root) not in sys.path:
    sys.path.insert(0, str(fuzzer_root))

from shadow_fuzzer.clients import all_parsers, get_parser_for_host

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SHADOW_TS_RE = re.compile(
    r"\d+\.\d+\.\d+\s+(\d+):(\d+):(\d+)\.(\d+)"
)
SHADOW_EPOCH_MS = 946684800000


def parse_shadow_timestamp(line: str) -> float:
    line = ANSI_RE.sub("", line)
    m = SHADOW_TS_RE.search(line)
    if m:
        h, mi, s, us = m.groups()
        return int(h) * 3600 + int(mi) * 60 + int(s) + int(us) / 1_000_000
    return 0.0


def _event_ts_ms(evt: dict[str, Any]) -> float:
    ts_ms = float(evt.get("ts_ms", evt.get("ts", 0) * 1000))
    if ts_ms >= SHADOW_EPOCH_MS:
        return ts_ms - SHADOW_EPOCH_MS
    return ts_ms


def _nearest_rank(values: list[float], percentile: float, denominator: int | None = None) -> float | None:
    if not values:
        return None
    n = denominator if denominator is not None else len(values)
    idx = max(0, math.ceil(percentile * n) - 1)
    if idx >= len(values):
        return None
    return sorted(values)[idx]


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[len(s) // 2]


def _parse_chain_status_line(line: str, status: dict[str, Any]) -> bool:
    clean = ANSI_RE.sub("", line)

    m = re.search(r"Current Slot:\s*(-?\d+).*Head Slot:\s*(\d+)", clean)
    if m:
        status["slot"] = int(m.group(1))
        status["head_slot"] = int(m.group(2))
        return False

    m = re.search(r"Head Block Root:\s*0x([0-9a-fA-F]+)", clean)
    if m:
        status["head_root"] = m.group(1).lower()
        return False

    # ethlambda fork choice tree: "Head:      slot X | root Y"
    m = re.search(r"Head:\s+slot\s+(\d+)\s+\|\s+root\s+([0-9a-fA-F]+)", clean)
    if m:
        status["head_slot"] = int(m.group(1))
        status["head_root"] = m.group(2).lower()
        if "slot" not in status:
            status["slot"] = int(m.group(1))
        return True

    m = re.search(
        r"Latest Justified:\s*Slot\s*(\d+)\s*\|\s*Root:\s*0x([0-9a-fA-F]+)",
        clean,
    )
    if not m:
        m = re.search(
            r"Latest Justified:\s*0x([0-9a-fA-F]+)\s*@\s*(\d+)", clean
        )
        if m:
            status["latest_justified_root"] = m.group(1).lower()
            status["latest_justified_slot"] = int(m.group(2))
            return False
        # ethlambda fork choice tree: "Justified: slot X | root Y"
        m = re.search(
            r"Justified:\s+slot\s+(\d+)\s+\|\s+root\s+([0-9a-fA-F]+)", clean
        )
        if m:
            status["latest_justified_slot"] = int(m.group(1))
            status["latest_justified_root"] = m.group(2).lower()
            return False
    if m:
        status["latest_justified_slot"] = int(m.group(1))
        status["latest_justified_root"] = m.group(2).lower()
        return False

    m = re.search(
        r"Latest Finalized:\s*Slot\s*(\d+)\s*\|\s*Root:\s*0x([0-9a-fA-F]+)",
        clean,
    )
    if not m:
        m = re.search(
            r"Latest Finalized:\s*0x([0-9a-fA-F]+)\s*@\s*(\d+)", clean
        )
        if m:
            status["latest_finalized_root"] = m.group(1).lower()
            status["latest_finalized_slot"] = int(m.group(2))
            return True
        # ethlambda fork choice tree: "Finalized: slot X | root Y"
        m = re.search(
            r"Finalized:\s+slot\s+(\d+)\s+\|\s+root\s+([0-9a-fA-F]+)", clean
        )
        if m:
            status["latest_finalized_slot"] = int(m.group(1))
            status["latest_finalized_root"] = m.group(2).lower()
            return True
    if m:
        status["latest_finalized_slot"] = int(m.group(1))
        status["latest_finalized_root"] = m.group(2).lower()
        return True

    return False


def _chain_status_complete(status: dict[str, Any]) -> bool:
    return all(
        k in status
        for k in (
            "slot",
            "head_slot",
            "head_root",
            "latest_justified_slot",
            "latest_justified_root",
            "latest_finalized_slot",
            "latest_finalized_root",
        )
    )


def _read_host_events(
    hosts_dir: Path,
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    def _host_file_lines(host_name: str):
        host_dir = hosts_dir / host_name
        for stdout_file in sorted(host_dir.glob("*.stdout")):
            with open(stdout_file, errors="replace") as f:
                for line in f:
                    yield host_name, line.rstrip("\n")
        for stderr_file in sorted(host_dir.glob("*.stderr")):
            with open(stderr_file, errors="replace") as f:
                for line in f:
                    yield host_name, line.rstrip("\n")
        for consensus_log in sorted(host_dir.glob("**/consensus.log")):
            with open(consensus_log, errors="replace") as f:
                for line in f:
                    yield host_name, line.rstrip("\n")

    def _append(kind: str, host: str, evt: dict[str, Any]):
        evt["host"] = host
        events[kind][host].append(evt)

    events: dict[str, dict[str, list[dict[str, Any]]]] = {
        "receive_attestation": defaultdict(list),
        "receive_block": defaultdict(list),
        "publish_block": defaultdict(list),
        "publish_attestation": defaultdict(list),
        "chain_status": defaultdict(list),
        "bandwidth": defaultdict(list),
    }

    for host_dir in sorted(hosts_dir.iterdir()):
        if not host_dir.is_dir():
            continue
        pending_chain_status: dict[str, Any] | None = None
        last_ts_ms = 0.0
        parser = get_parser_for_host(host_dir.name)
        for host_name, line in _host_file_lines(host_dir.name):
            shadow_ts_ms = parse_shadow_timestamp(line) * 1000
            if shadow_ts_ms > 0:
                last_ts_ms = shadow_ts_ms

            ts_ms = parser.parse_timestamp(line, shadow_ts_ms or last_ts_ms)
            if ts_ms == 0.0:
                ts_ms = shadow_ts_ms or last_ts_ms

            if pending_chain_status is not None:
                done = _parse_chain_status_line(line, pending_chain_status)
                if done and _chain_status_complete(pending_chain_status):
                    if pending_chain_status["slot"] >= 0:
                        _append("chain_status", host_name, pending_chain_status)
                    pending_chain_status = None

            chain_status_trigger = (
                "CHAIN STATUS" in line or "Fork Choice Tree:" in line
            )
            if chain_status_trigger:
                pending_chain_status = {
                    "ts_ms": round(ts_ms, 1),
                    "source": f"{parser.name}_text",
                }
                _parse_chain_status_line(line, pending_chain_status)
                continue

            parsed = parser.parse_line(line, ts_ms)
            for evt in parsed:
                kind = evt.pop("_kind", None)
                if kind and kind in events:
                    _append(kind, host_name, evt)

    return events


def _compute_attestation_slot_stats(
    events: dict[str, dict[str, list[dict[str, Any]]]],
    genesis_ms: int,
) -> dict[str, Any]:
    ra = events["receive_attestation"]
    if not ra:
        return {"slots": [], "summary": {"warning": "No attestation receive events found"}}

    slot_publishers: dict[int, set[int]] = defaultdict(set)
    for host_events in ra.values():
        for evt in host_events:
            n_parts = int(evt.get("num_participants", 0))
            if n_parts > 0:
                for vid in range(n_parts):
                    slot_publishers[evt["slot"]].add(vid)
            else:
                slot_publishers[evt["slot"]].add(evt.get("validator_id", 0))

    slot_stats_list: list[dict[str, Any]] = []

    for slot in sorted(slot_publishers.keys()):
        n_publishers = len(slot_publishers[slot])
        if n_publishers < 2:
            continue

        node_times_ms: list[float] = []
        for host_name, host_events in ra.items():
            received: dict[int, float] = {}
            for evt in host_events:
                if evt["slot"] != slot:
                    continue
                ts_val = _event_ts_ms(evt)
                offset = ts_val - genesis_ms
                n_parts = int(evt.get("num_participants", 0))
                if n_parts > 0:
                    for vid in range(n_parts):
                        if vid not in received or offset < received[vid]:
                            received[vid] = offset
                else:
                    vid = evt.get("validator_id", 0)
                    if vid not in received or offset < received[vid]:
                        received[vid] = offset

            if len(received) < 2:
                continue

            times = sorted(received.values())
            idx = min(len(times) - 1, int(0.95 * n_publishers) - 1)
            node_times_ms.append(times[idx] - times[0])

        if node_times_ms:
            s = sorted(node_times_ms)
            n = len(s)
            slot_stats_list.append(
                {
                    "slot": slot,
                    "n_publishers": n_publishers,
                    "n_measurements": n,
                    "p50_ms": round(s[n // 2], 1),
                    "p95_ms": round(s[int(0.95 * (n - 1))], 1) if n > 1 else round(s[0], 1),
                    "p99_ms": round(s[int(0.99 * (n - 1))], 1) if n > 1 else round(s[0], 1),
                    "max_ms": round(s[-1], 1),
                    "mean_ms": round(sum(s) / n, 1),
                }
            )

    summary: dict[str, Any] = {}
    if slot_stats_list:
        all_p99 = [s["p99_ms"] for s in slot_stats_list]
        all_p99.sort()
        summary["slots_with_data"] = len(slot_stats_list)
        summary["aggregate_p99_ms"] = round(
            all_p99[min(int(0.99 * len(all_p99)), len(all_p99) - 1)], 1
        )
        summary["aggregate_p50_ms"] = round(all_p99[len(all_p99) // 2], 1)
    else:
        summary["warning"] = "Insufficient data for per-slot attestation stats"

    return {"slots": slot_stats_list, "summary": summary}


def _compute_attestation_coverage_stats(
    events: dict[str, dict[str, list[dict[str, Any]]]],
    host_names: list[str],
) -> dict[str, Any]:
    target_attestation_coverage = 0.95
    node_percentiles = [0.5, 0.9, 0.95]
    pa = events["publish_attestation"]
    ra = events["receive_attestation"]
    warnings: list[str] = []

    published_by_slot: dict[int, set[tuple[int, int]]] = defaultdict(set)
    first_publish_ms_by_slot: dict[int, float] = {}
    known_times: dict[int, dict[str, dict[tuple[int, int], float]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    sources_seen: set[str] = set()

    for host_name, host_events in pa.items():
        for evt in host_events:
            slot = int(evt["slot"])
            att_id = (slot, int(evt.get("validator_id", 0)))
            ts_ms = _event_ts_ms(evt)
            published_by_slot[slot].add(att_id)
            if slot not in first_publish_ms_by_slot or ts_ms < first_publish_ms_by_slot[slot]:
                first_publish_ms_by_slot[slot] = ts_ms
            previous = known_times[slot][host_name].get(att_id)
            if previous is None or ts_ms < previous:
                known_times[slot][host_name][att_id] = ts_ms
            sources_seen.add(evt.get("source", "unknown"))

    for host_name, host_events in ra.items():
        for evt in host_events:
            slot = int(evt["slot"])
            # Aggregated attestation covering all validators in the slot
            n_participants = int(evt.get("num_participants", 0))
            if n_participants > 0 and slot in published_by_slot:
                ts_ms = _event_ts_ms(evt)
                for att_id in published_by_slot[slot]:
                    previous = known_times[slot][host_name].get(att_id)
                    if previous is None or ts_ms < previous:
                        known_times[slot][host_name][att_id] = ts_ms
            else:
                att_id = (slot, int(evt.get("validator_id", 0)))
                ts_ms = _event_ts_ms(evt)
                previous = known_times[slot][host_name].get(att_id)
                if previous is None or ts_ms < previous:
                    known_times[slot][host_name][att_id] = ts_ms
            sources_seen.add(evt.get("source", "unknown"))

    slot_stats: list[dict[str, Any]] = []
    n_nodes = len(host_names)
    for slot in sorted(published_by_slot.keys()):
        published = published_by_slot[slot]
        n_published = len(published)
        if n_published == 0:
            warnings.append(f"slot {slot}: no published attestations")
            continue
        if n_nodes == 0:
            warnings.append(f"slot {slot}: no hosts found")
            continue

        threshold = math.ceil(target_attestation_coverage * n_published)
        first_publish_ms = first_publish_ms_by_slot[slot]
        node_threshold_times: list[float] = []

        for host_name in host_names:
            host_known = known_times[slot].get(host_name, {})
            times = sorted(
                ts for att_id, ts in host_known.items() if att_id in published
            )
            if len(times) >= threshold:
                node_threshold_times.append(times[threshold - 1] - first_publish_ms)

        node_threshold_times.sort()
        n_reached = len(node_threshold_times)
        slot_d: dict[str, Any] = {
            "slot": slot,
            "n_published_attestations": n_published,
            "n_nodes": n_nodes,
            "attestation_threshold": threshold,
            "n_nodes_reached_threshold": n_reached,
        }

        percentile_fields = {
            0.5: "p50_nodes_to_95_attestations_ms",
            0.9: "p90_nodes_to_95_attestations_ms",
            0.95: "p95_nodes_to_95_attestations_ms",
        }
        for percentile, field_name in percentile_fields.items():
            val = _nearest_rank(node_threshold_times, percentile, denominator=len(node_threshold_times))
            if val is not None:
                slot_d[field_name] = round(val, 1)

        if node_threshold_times:
            slot_d["max_nodes_to_95_attestations_ms"] = round(node_threshold_times[-1], 1)
        if n_reached < math.ceil(0.95 * n_nodes):
            slot_d["warning"] = (
                f"only {n_reached}/{n_nodes} nodes reached 95% attestation coverage"
            )
            warnings.append(f"slot {slot}: {slot_d['warning']}")

        slot_stats.append(slot_d)

    if not published_by_slot:
        warnings.append("No attestation publish events found")

    for parser in all_parsers():
        if parser.attestation_id_warning and f"{parser.name}_text" in sources_seen:
            warnings.append(parser.attestation_id_warning)

    summary: dict[str, Any] = {}
    slots_with_all_fields = [
        s for s in slot_stats
        if "p50_nodes_to_95_attestations_ms" in s
        and "p90_nodes_to_95_attestations_ms" in s
        and "p95_nodes_to_95_attestations_ms" in s
    ]
    if slots_with_all_fields:
        summary["slots_with_data"] = len(slots_with_all_fields)
        fields = [
            "p50_nodes_to_95_attestations_ms",
            "p90_nodes_to_95_attestations_ms",
            "p95_nodes_to_95_attestations_ms",
        ]
        for field in fields:
            vals = [float(s[field]) for s in slots_with_all_fields]
            median_val = _median(vals)
            if median_val is not None:
                summary[f"median_slot_{field}"] = round(median_val, 1)
    else:
        summary["warning"] = "Insufficient data for attestation coverage stats"

    if warnings:
        summary["warnings"] = warnings

    return {
        "target_attestation_coverage": target_attestation_coverage,
        "node_percentiles": node_percentiles,
        "slots": slot_stats,
        "summary": summary,
    }


def _compute_block_slot_stats(
    events: dict[str, dict[str, list[dict[str, Any]]]],
    genesis_ms: int,
) -> dict[str, Any]:
    pb = events["publish_block"]
    rb = events["receive_block"]

    block_slots: dict[int, dict[str, Any]] = {}
    for host_events in pb.values():
        for evt in host_events:
            slot = evt["slot"]
            publish_ms = round(_event_ts_ms(evt) - genesis_ms, 1)
            if slot not in block_slots:
                block_slots[slot] = {
                    "slot": slot,
                    "proposer": evt.get("proposer", 0),
                    "block_hash": evt.get("block_hash", ""),
                    "receive_timestamps_ms": {},
                }
            block_slots[slot]["proposer"] = evt.get("proposer", 0)
            block_slots[slot]["block_hash"] = evt.get("block_hash", "")
            if "size_bytes" in evt:
                block_slots[slot]["block_size_bytes"] = evt["size_bytes"]
            if (
                "published_ms" not in block_slots[slot]
                or publish_ms < block_slots[slot]["published_ms"]
            ):
                block_slots[slot]["published_ms"] = publish_ms

    if rb:
        for host_name, host_events in rb.items():
            for evt in host_events:
                slot = evt["slot"]
                if slot not in block_slots:
                    block_slots[slot] = {
                        "slot": slot,
                        "proposer": evt.get("proposer", 0),
                        "block_hash": "",
                        "receive_timestamps_ms": {},
                    }
                ts_val = _event_ts_ms(evt)
                offset = round(ts_val - genesis_ms, 1)
                reception = block_slots[slot]["receive_timestamps_ms"]
                if host_name not in reception or offset < reception[host_name]:
                    reception[host_name] = offset
                if "size_bytes" in evt and "block_size_bytes" not in block_slots[slot]:
                    block_slots[slot]["block_size_bytes"] = evt["size_bytes"]

    slot_list: list[dict[str, Any]] = []
    for slot in sorted(block_slots.keys()):
        s = block_slots[slot]
        reception = s.get("receive_timestamps_ms", {})
        slot_d = {
            "slot": slot,
            "proposer": s["proposer"],
        }
        if "published_ms" in s:
            slot_d["published_ms"] = s["published_ms"]
        if "block_size_bytes" in s:
            slot_d["block_size_bytes"] = s["block_size_bytes"]
        if reception:
            times = sorted(reception.values())
            slot_d["first_receive_ms"] = times[0]
            slot_d["last_receive_ms"] = times[-1]
            slot_d["n_received"] = len(times)
            slot_d["receive_timestamps_ms"] = reception
        slot_list.append(slot_d)

    summary: dict[str, Any] = {}
    if slot_list:
        published = [s for s in slot_list if "published_ms" in s]
        received = [s for s in slot_list if "first_receive_ms" in s]
        summary["n_published"] = len(published)
        summary["n_received"] = len(received)
        summary["n_with_block_size"] = sum(1 for s in slot_list if "block_size_bytes" in s)
    else:
        summary["warning"] = "No block events found"

    return {"slots": slot_list, "summary": summary}


def _compute_chain_status_stats(
    events: dict[str, dict[str, list[dict[str, Any]]]],
    genesis_ms: int,
) -> dict[str, Any]:
    cs = events["chain_status"]
    by_slot: dict[int, dict[str, dict[str, Any]]] = defaultdict(dict)

    for host_name, host_events in cs.items():
        for evt in host_events:
            slot = int(evt["slot"])
            ts_ms = _event_ts_ms(evt)
            host_status = {
                "head_slot": int(evt["head_slot"]),
                "head_root": evt["head_root"],
                "latest_justified_slot": int(evt["latest_justified_slot"]),
                "latest_justified_root": evt["latest_justified_root"],
                "latest_finalized_slot": int(evt["latest_finalized_slot"]),
                "latest_finalized_root": evt["latest_finalized_root"],
                "ts_ms": round(ts_ms - genesis_ms, 1),
                "source": evt.get("source", "unknown"),
            }
            previous = by_slot[slot].get(host_name)
            if previous is None or host_status["ts_ms"] >= previous["ts_ms"]:
                by_slot[slot][host_name] = host_status

    slot_list = [
        {"slot": slot, "hosts": dict(sorted(hosts.items()))}
        for slot, hosts in sorted(by_slot.items())
    ]
    hosts_with_data = sorted({host for hosts in by_slot.values() for host in hosts})

    summary: dict[str, Any] = {
        "slots_with_data": len(slot_list),
        "hosts_with_data": len(hosts_with_data),
    }
    if not slot_list:
        summary["warning"] = "No chain status events found"

    return {"slots": slot_list, "summary": summary}


def _compute_bandwidth_stats(
    events: dict[str, dict[str, list[dict[str, Any]]]],
    genesis_ms: int,
) -> dict[str, Any]:
    bandwidth_events = events.get("bandwidth", {})
    event_rows: list[dict[str, Any]] = []
    totals_by_slot: dict[tuple[int, str, str, str, str, str], int] = defaultdict(int)

    for host_name, host_events in bandwidth_events.items():
        for evt in host_events:
            ts_ms = _event_ts_ms(evt)
            offset_ms = ts_ms - genesis_ms
            slot = math.floor(offset_ms / 4000)
            slot_offset_ms = round(offset_ms - slot * 4000, 1)
            row = {
                "host": host_name,
                "ts_ms": round(offset_ms, 1),
                "slot": slot,
                "slot_offset_ms": slot_offset_ms,
                "direction": str(evt["direction"]),
                "protocol": str(evt["protocol"]),
                "message_kind": str(evt["message_kind"]),
                "bytes": int(evt["bytes"]),
                "delivery": str(evt["delivery"]),
                "source": evt.get("source", "unknown"),
            }
            if "consensus_slot" in evt:
                row["consensus_slot"] = int(evt["consensus_slot"])
            event_rows.append(row)

            key = (
                slot,
                host_name,
                row["direction"],
                row["protocol"],
                row["message_kind"],
                row["delivery"],
            )
            totals_by_slot[key] += row["bytes"]

    event_rows.sort(
        key=lambda row: (
            row["slot"],
            row["slot_offset_ms"],
            row["host"],
            row["direction"],
            row["protocol"],
            row["message_kind"],
            row["delivery"],
        )
    )
    slot_rows = [
        {
            "slot": slot,
            "host": host,
            "direction": direction,
            "protocol": protocol,
            "message_kind": message_kind,
            "delivery": delivery,
            "bytes": bytes_total,
        }
        for (
            slot,
            host,
            direction,
            protocol,
            message_kind,
            delivery,
        ), bytes_total in sorted(totals_by_slot.items())
    ]

    total_bytes = sum(row["bytes"] for row in event_rows)
    inbound_bytes = sum(row["bytes"] for row in event_rows if row["direction"] == "in")
    outbound_bytes = sum(row["bytes"] for row in event_rows if row["direction"] == "out")
    duplicate_inclusive_gossip_bytes = sum(
        row["bytes"]
        for row in event_rows
        if row["direction"] == "in"
        and row["protocol"] == "gossip"
        and row["delivery"] == "unfiltered"
    )

    summary: dict[str, Any] = {
        "total_bytes": total_bytes,
        "inbound_bytes": inbound_bytes,
        "outbound_bytes": outbound_bytes,
        "duplicate_inclusive_gossip_bytes": duplicate_inclusive_gossip_bytes,
        "event_count": len(event_rows),
        "slots_with_data": len({row["slot"] for row in event_rows}),
    }
    if not event_rows:
        summary["warning"] = "No bandwidth events found"

    return {"events": event_rows, "slots": slot_rows, "summary": summary}


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_file():
        return json.loads(path.read_text())
    return {}


def _load_genesis_ms(run_path: Path) -> int | None:
    genesis_config_path = run_path / "genesis" / "config.yaml"
    if not genesis_config_path.is_file():
        return None
    try:
        config = yaml.safe_load(genesis_config_path.read_text()) or {}
    except yaml.YAMLError:
        return None
    genesis_time = config.get("GENESIS_TIME", config.get("genesis_time"))
    if genesis_time is None:
        return None
    genesis_ms = int(genesis_time) * 1000
    if genesis_ms >= SHADOW_EPOCH_MS:
        genesis_ms -= SHADOW_EPOCH_MS
    return genesis_ms


def _infer_genesis_ms_from_events(
    events: dict[str, dict[str, list[dict[str, Any]]]],
) -> int:
    genesis_ms = 0
    for host_events in events["receive_attestation"].values():
        for evt in host_events:
            ts_val = _event_ts_ms(evt)
            if genesis_ms == 0 or ts_val < genesis_ms:
                genesis_ms = ts_val
    return int((genesis_ms // 1_000_000) * 1_000_000)


def _summarize_event_counts(
    events: dict[str, dict[str, list[dict[str, Any]]]],
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for kind, by_host in events.items():
        total = 0
        by_source: dict[str, int] = {}
        by_host_counts: dict[str, int] = {}
        for host_name, host_events in by_host.items():
            if not host_events:
                continue
            by_host_counts[host_name] = len(host_events)
            total += len(host_events)
            for evt in host_events:
                source = str(evt.get("source", "unknown"))
                by_source[source] = by_source.get(source, 0) + 1
        summary[kind] = {
            "total": total,
            "by_source": dict(sorted(by_source.items())),
            "by_host": dict(sorted(by_host_counts.items())),
        }
    return summary


def collect_stats(run_dir: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    run_path = Path(run_dir)
    if not run_path.is_dir():
        print(f"ERROR: {run_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    if metadata is None:
        metadata = {}

    warnings: list[str] = []

    regions = _load_json(run_path / "regions.json")
    bandwidths = _load_json(run_path / "bandwidths.json")

    hosts_dir = run_path / "shadow.data" / "hosts"
    if not hosts_dir.is_dir():
        hosts_dir = run_path / "hosts"
    if not hosts_dir.is_dir():
        warnings.append("shadow.data/hosts directory not found; no propagation stats available")
        result: dict[str, Any] = {
            "node_distribution": {
                "regions": {},
                "bandwidths": {},
                "clients": metadata.get("node_counts", {}),
            },
            "blocks": {"slots": [], "summary": {"warning": warnings[0]}},
            "chain_status": {"slots": [], "summary": {"warning": warnings[0]}},
            "bandwidth": {
                "events": [],
                "slots": [],
                "summary": {"warning": warnings[0]},
            },
            "attestations": {
                "slots": [],
                "summary": {"warning": warnings[0]},
                "coverage": {
                    "target_attestation_coverage": 0.95,
                    "node_percentiles": [0.5, 0.9, 0.95],
                    "slots": [],
                    "summary": {"warning": warnings[0]},
                },
            },
            "event_counts": {},
            "warnings": warnings,
        }
        for key in (
            "run_id", "run_index", "fuzzer", "simulation", "clients", "node_counts",
            "docker_arm", "client_images", "client_runtime",
        ):
            if key in metadata:
                result[key] = metadata[key]
        return result

    host_names = sorted(p.name for p in hosts_dir.iterdir() if p.is_dir())
    events = _read_host_events(hosts_dir)

    total_receive_att = sum(len(v) for v in events["receive_attestation"].values())
    total_receive_block = sum(len(v) for v in events["receive_block"].values())
    print(
        f"Events: {total_receive_att} attestation receives, "
        f"{total_receive_block} block receives"
    )

    if total_receive_att == 0 and total_receive_block == 0:
        warnings.append("No propagation events found in any host stdout/stderr")

    genesis_ms = _load_genesis_ms(run_path)
    if genesis_ms is None:
        genesis_ms = _infer_genesis_ms_from_events(events)

    attestation_stats = _compute_attestation_slot_stats(events, int(genesis_ms))
    attestation_stats["coverage"] = _compute_attestation_coverage_stats(
        events, host_names
    )
    block_stats = _compute_block_slot_stats(events, int(genesis_ms))
    chain_status_stats = _compute_chain_status_stats(events, int(genesis_ms))
    bandwidth_stats = _compute_bandwidth_stats(events, int(genesis_ms))

    region_counts: dict[str, int] = {}
    for r in regions.values():
        region_counts[r] = region_counts.get(r, 0) + 1

    bw_counts: dict[str, int] = {}
    for b in bandwidths.values():
        bw_counts[b] = bw_counts.get(b, 0) + 1

    node_counts = metadata.get("node_counts", {})

    result: dict[str, Any] = {
        "blocks": block_stats,
        "chain_status": chain_status_stats,
        "bandwidth": bandwidth_stats,
        "attestations": attestation_stats,
        "event_counts": _summarize_event_counts(events),
        "node_distribution": {
            "clients": node_counts,
            "regions": region_counts,
            "bandwidths": bw_counts,
        },
        "warnings": warnings,
    }

    for key in (
        "run_id", "run_index", "fuzzer", "simulation", "clients", "node_counts",
        "docker_arm", "client_images", "client_runtime",
    ):
        if key in metadata:
            result[key] = metadata[key]

    return result


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <run_dir> [--metadata-json <path>]", file=sys.stderr)
        sys.exit(1)

    run_dir = sys.argv[1]
    metadata: dict[str, Any] = {}
    try:
        idx = sys.argv.index("--metadata-json")
        metadata_path = Path(sys.argv[idx + 1])
        if metadata_path.is_file():
            metadata = json.loads(metadata_path.read_text())
    except (ValueError, IndexError):
        pass

    stats = collect_stats(run_dir, metadata)

    stats_path = Path(run_dir) / "stats.json"
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"Wrote {stats_path}")


if __name__ == "__main__":
    main()

from shadow_fuzzer.clients.ethlambda import EthlambdaParser
from shadow_fuzzer.stats_shadow import _compute_bandwidth_stats, _load_genesis_ms


def test_ethlambda_parser_extracts_bandwidth_event():
    events = EthlambdaParser().parse_line(
        '2026-06-07T00:00:01.234Z INFO P2P bandwidth event '
        'direction="in" protocol="gossip" message_kind="attestation" '
        'bytes=1234 delivery="unfiltered"',
        ts_ms=1234,
    )

    assert events == [{
        "_kind": "bandwidth",
        "ts": 1.234,
        "direction": "in",
        "protocol": "gossip",
        "message_kind": "attestation",
        "bytes": 1234,
        "delivery": "unfiltered",
        "source": "ethlambda_text",
    }]


def test_ethlambda_parser_extracts_optional_consensus_slot():
    events = EthlambdaParser().parse_line(
        "P2P bandwidth event direction=out protocol=gossip "
        "message_kind=block bytes=2048 delivery=sent consensus_slot=7",
        ts_ms=2000,
    )

    assert events[0]["consensus_slot"] == 7


def test_bandwidth_stats_slot_offsets_and_duplicate_inclusive_gossip():
    events = {
        "bandwidth": {
            "ethlambda-0": [
                {
                    "ts": 60.100,
                    "direction": "in",
                    "protocol": "gossip",
                    "message_kind": "attestation",
                    "bytes": 100,
                    "delivery": "unfiltered",
                    "source": "ethlambda_text",
                },
                {
                    "ts": 60.200,
                    "direction": "in",
                    "protocol": "gossip",
                    "message_kind": "attestation",
                    "bytes": 100,
                    "delivery": "unfiltered",
                    "source": "ethlambda_text",
                },
                {
                    "ts": 60.300,
                    "direction": "out",
                    "protocol": "gossip",
                    "message_kind": "attestation",
                    "bytes": 50,
                    "delivery": "sent",
                    "source": "ethlambda_text",
                    "consensus_slot": 0,
                },
                {
                    "ts": 64.005,
                    "direction": "in",
                    "protocol": "reqresp",
                    "message_kind": "status_response",
                    "bytes": 20,
                    "delivery": "decoded",
                    "source": "ethlambda_text",
                },
            ],
        },
    }

    stats = _compute_bandwidth_stats(events, genesis_ms=60_000)

    assert stats["events"][0]["slot"] == 0
    assert stats["events"][0]["slot_offset_ms"] == 100.0
    assert stats["events"][-1]["slot"] == 1
    assert stats["events"][-1]["slot_offset_ms"] == 5.0
    assert stats["summary"]["total_bytes"] == 270
    assert stats["summary"]["inbound_bytes"] == 220
    assert stats["summary"]["outbound_bytes"] == 50
    assert stats["summary"]["duplicate_inclusive_gossip_bytes"] == 200
    assert stats["summary"]["event_count"] == 4
    assert stats["summary"]["slots_with_data"] == 2
    assert any(
        row["slot"] == 0
        and row["host"] == "ethlambda-0"
        and row["direction"] == "in"
        and row["protocol"] == "gossip"
        and row["message_kind"] == "attestation"
        and row["delivery"] == "unfiltered"
        and row["bytes"] == 200
        for row in stats["slots"]
    )


def test_load_genesis_ms_uses_shadow_epoch(tmp_path):
    genesis_dir = tmp_path / "genesis"
    genesis_dir.mkdir()
    (genesis_dir / "config.yaml").write_text("GENESIS_TIME: 946684860\n")

    assert _load_genesis_ms(tmp_path) == 60_000

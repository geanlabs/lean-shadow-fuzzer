from shadow_fuzzer.clients.ethlambda import EthlambdaParser
from shadow_fuzzer.stats_shadow import (
    _compute_attestation_validator_slot_stats,
    _compute_aggregation_propagation_stats,
)


def test_ethlambda_parser_extracts_individual_receive_attestation():
    events = EthlambdaParser().parse_line(
        "2000-01-01T00:01:00.822077Z INFO ethlambda_p2p::gossipsub::handler: "
        "Received attestation from gossip slot=0 validator=7 "
        "head_root=2addab0c target_slot=0 target_root=2addab0c "
        "source_slot=0 source_root=2addab0c",
        ts_ms=60822.077,
    )

    assert events == [{
        "_kind": "receive_attestation",
        "ts": 60.822077,
        "slot": 0,
        "validator_id": 7,
        "head_root": "2addab0c",
        "target_slot": 0,
        "target_root": "2addab0c",
        "source_slot": 0,
        "source_root": "2addab0c",
        "source": "ethlambda_text",
    }]


def test_validator_slot_stats_computes_propagation_times():
    events = {
        "publish_attestation": {
            "ethlambda-0": [
                {"ts_ms": 10000.0, "slot": 1, "validator_id": 0, "source": "ethlambda_text"},
                {"ts_ms": 10000.0, "slot": 2, "validator_id": 0, "source": "ethlambda_text"},
            ],
            "ethlambda-1": [
                {"ts_ms": 10100.0, "slot": 1, "validator_id": 1, "source": "ethlambda_text"},
            ],
        },
        "receive_attestation": {
            "ethlambda-0": [
                # Own publish is immediate
                {"ts_ms": 10000.0, "slot": 1, "validator_id": 0, "source": "ethlambda_text"},
                {"ts_ms": 10000.0, "slot": 2, "validator_id": 0, "source": "ethlambda_text"},
                # Receives from validator 1 during slot 1
                {"ts_ms": 10200.0, "slot": 1, "validator_id": 1, "source": "ethlambda_text"},
            ],
            "ethlambda-1": [
                # Own publish is immediate
                {"ts_ms": 10100.0, "slot": 1, "validator_id": 1, "source": "ethlambda_text"},
                # Receives validator 0 attestation individually during slot 2
                {"ts_ms": 10220.0, "slot": 2, "validator_id": 0, "source": "ethlambda_text"},
                # Receives aggregated attestation for slot 2 (covers all validators in slot)
                {"ts_ms": 10300.0, "slot": 2, "num_participants": 2, "source": "ethlambda_text"},
            ],
        },
    }

    stats = _compute_attestation_validator_slot_stats(events, genesis_ms=0)

    # Should have 3 entries: (slot=1, v=0), (slot=2, v=0), (slot=1, v=1)
    assert len(stats) == 3

    by_id = {(s["slot"], s["validator_id"]): s for s in stats}

    # Validator 0, slot 1: published by ethlambda-0 at 10000.0;
    # ethlambda-0 receives its own at 10000.0; ethlambda-1 has no receive for validator 0 slot 1
    s = by_id[(1, 0)]
    assert s["published_ms"] == 10000.0
    assert s["propagation_times_ms"] == [0.0]

    # Validator 0, slot 2: published at 10000.0, received by ethlambda-0 at 10000.0,
    # by ethlambda-1 at 10220.0 (individual) — the aggregated event at 10300.0 is ignored
    # because the individual receive is earlier.
    s = by_id[(2, 0)]
    assert s["published_ms"] == 10000.0
    assert s["propagation_times_ms"] == [0.0, 220.0]

    # Validator 1, slot 1: published at 10100.0, received by ethlambda-1 at 10100.0, by ethlambda-0 at 10200.0
    s = by_id[(1, 1)]
    assert s["published_ms"] == 10100.0
    assert s["propagation_times_ms"] == [0.0, 100.0]


def test_validator_slot_stats_empty_when_no_publishes():
    events = {
        "publish_attestation": {},
        "receive_attestation": {
            "ethlambda-0": [
                {"ts_ms": 10000.0, "slot": 1, "validator_id": 0, "source": "ethlambda_text"},
            ],
        },
    }

    stats = _compute_attestation_validator_slot_stats(events, genesis_ms=0)
    assert stats == []


def test_ethlambda_parser_extracts_new_format_aggregation_publish():
    events = EthlambdaParser().parse_line(
        "2000-01-01T00:01:00.822077Z INFO ethlambda_p2p::gossipsub::handler: "
        "Published aggregated attestation to gossipsub slot=0 message_id=msg.abc "
        "local_peer_id=12D3 target_slot=0 target_root=2addab0c "
        "source_slot=0 source_root=2addab0c participant_count=16",
        ts_ms=60822.077,
    )

    assert events == [{
        "_kind": "publish_aggregation",
        "ts": 60.822077,
        "slot": 0,
        "message_id": "msg.abc",
        "target_slot": 0,
        "target_root": "2addab0c",
        "source_slot": 0,
        "source_root": "2addab0c",
        "participant_count": 16,
        "source": "ethlambda_text",
    }]


def test_ethlambda_parser_extracts_new_format_aggregation_receive():
    events = EthlambdaParser().parse_line(
        "2000-01-01T00:01:00.822077Z INFO ethlambda_p2p::gossipsub::handler: "
        "Received aggregated attestation from gossip slot=0 message_id=msg.abc "
        "local_peer_id=12D3 propagation_source=12D4 target_slot=0 "
        "target_root=2addab0c source_slot=0 source_root=2addab0c "
        "participant_count=16",
        ts_ms=60822.077,
    )

    assert events == [{
        "_kind": "receive_aggregation",
        "ts": 60.822077,
        "slot": 0,
        "message_id": "msg.abc",
        "target_slot": 0,
        "target_root": "2addab0c",
        "source_slot": 0,
        "source_root": "2addab0c",
        "participant_count": 16,
        "source": "ethlambda_text",
    }]


def test_aggregation_propagation_stats_computes_times():
    events = {
        "publish_aggregation": {
            "ethlambda-0": [
                {"ts_ms": 10000.0, "slot": 1, "message_id": "msg.a", "source": "ethlambda_text"},
            ],
            "ethlambda-1": [
                {"ts_ms": 10100.0, "slot": 2, "message_id": "msg.b", "source": "ethlambda_text"},
            ],
        },
        "receive_aggregation": {
            "ethlambda-0": [
                # Own publish is immediate
                {"ts_ms": 10000.0, "slot": 1, "message_id": "msg.a", "source": "ethlambda_text"},
            ],
            "ethlambda-1": [
                # Receives msg.a from ethlambda-0
                {"ts_ms": 10200.0, "slot": 1, "message_id": "msg.a", "source": "ethlambda_text"},
                # Own publish is immediate
                {"ts_ms": 10100.0, "slot": 2, "message_id": "msg.b", "source": "ethlambda_text"},
            ],
        },
    }

    stats = _compute_aggregation_propagation_stats(events, genesis_ms=0)

    assert len(stats) == 2
    by_id = {(s["slot"], s["message_id"]): s for s in stats}

    s = by_id[(1, "msg.a")]
    assert s["published_ms"] == 10000.0
    assert s["propagation_times_ms"] == [0.0, 200.0]

    s = by_id[(2, "msg.b")]
    assert s["published_ms"] == 10100.0
    assert s["propagation_times_ms"] == [0.0]


def test_aggregation_propagation_stats_empty_when_no_publishes():
    events = {
        "publish_aggregation": {},
        "receive_aggregation": {
            "ethlambda-0": [
                {"ts_ms": 10000.0, "slot": 1, "message_id": "msg.a", "source": "ethlambda_text"},
            ],
        },
    }

    stats = _compute_aggregation_propagation_stats(events, genesis_ms=0)
    assert stats == []

from shadow_fuzzer.clients import get_parser_for_host
from shadow_fuzzer.clients.lantern import LanternParser


def test_lantern_parser_is_registered_before_zeam_fallback():
    assert get_parser_for_host("lantern-2").name == "lantern"


def test_lantern_parser_extracts_publish_attestation():
    line = (
        "2000-01-01T00:01:00.801Z  INFO   [attest]     slot 0, "
        "validator 2, target "
        "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2 "
        "@ 0, source "
        "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2 @ 0"
    )

    parser = LanternParser()
    events = parser.parse_line(line, parser.parse_timestamp(line, 0))

    assert events == [{
        "_kind": "publish_attestation",
        "ts": 60.801,
        "slot": 0,
        "validator_id": 2,
        "target_root": "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2",
        "target_slot": 0,
        "source_root": "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2",
        "source_slot": 0,
        "source": "lantern_text",
    }]


def test_lantern_parser_extracts_receive_attestation():
    line = (
        "2000-01-01T00:01:00.828Z  INFO   [gossip]     processed vote "
        "validator=0 slot=0 "
        "head=0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2 "
        "target=0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2@0 "
        "source=0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2@0"
    )

    parser = LanternParser()
    events = parser.parse_line(line, parser.parse_timestamp(line, 0))

    assert events == [{
        "_kind": "receive_attestation",
        "ts": 60.828,
        "validator_id": 0,
        "slot": 0,
        "head_root": "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2",
        "target_root": "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2",
        "target_slot": 0,
        "source_root": "0xfe86cd5bea40d4000186a22634c2ca71d6fcabd950ecbcc7956280fdd03ecdc2",
        "source_slot": 0,
        "source": "lantern_text",
    }]


def test_lantern_parser_extracts_receive_block():
    line = (
        "2000-01-01T00:01:04.434Z  INFO   [gossip]     received block "
        "slot=1 proposer=1 "
        "root=0xac81ff837f8f94869ca460fb385658ecc4003635175c7c93f56a928dc7299028 "
        "source=gossip"
    )

    parser = LanternParser()
    events = parser.parse_line(line, parser.parse_timestamp(line, 0))

    assert events == [{
        "_kind": "receive_block",
        "ts": 64.434,
        "slot": 1,
        "proposer": 1,
        "block_hash": "0xac81ff837f8f94869ca460fb385658ecc4003635175c7c93f56a928dc7299028",
        "block_root": "0xac81ff837f8f94869ca460fb385658ecc4003635175c7c93f56a928dc7299028",
        "block_source": "gossip",
        "source": "lantern_text",
    }]


def test_lantern_parser_extracts_publish_block_from_local_block_log():
    line = (
        "2000-01-01T00:01:08.242Z  INFO   [gossip]     received block "
        "slot=2 proposer=2 "
        "root=0x26157929223477cd2c9eddd06b657776fdf4619b6d0bcef1d24c8108e2a6a96f "
        "source=local"
    )

    parser = LanternParser()
    events = parser.parse_line(line, parser.parse_timestamp(line, 0))

    assert events == [{
        "_kind": "publish_block",
        "ts": 68.242,
        "slot": 2,
        "proposer": 2,
        "block_hash": "0x26157929223477cd2c9eddd06b657776fdf4619b6d0bcef1d24c8108e2a6a96f",
        "block_root": "0x26157929223477cd2c9eddd06b657776fdf4619b6d0bcef1d24c8108e2a6a96f",
        "block_source": "local",
        "source": "lantern_text",
    }]

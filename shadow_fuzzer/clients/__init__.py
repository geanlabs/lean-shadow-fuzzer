from __future__ import annotations

from .base import ClientParser
from .qlean import QleanParser
from .zeam import ZeamParser

_PARSERS: list[ClientParser] = [QleanParser(), ZeamParser()]


def get_parser_for_host(host_name: str) -> ClientParser:
    for parser in _PARSERS:
        if parser.match_host(host_name):
            return parser
    return _PARSERS[-1]


def all_parsers() -> list[ClientParser]:
    return list(_PARSERS)


def register(parser: ClientParser) -> None:
    _PARSERS.insert(len(_PARSERS) - 1, parser)

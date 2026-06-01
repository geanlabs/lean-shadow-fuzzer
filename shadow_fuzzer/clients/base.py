from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any


def parse_block_size_bytes(line: str) -> int | None:
    """Extract an integer block size from common log field formats."""
    for pattern in (
        r'"?\braw\b"?\s*[:=]\s*(\d+)\s*(?:bytes?|B)?\b',
        r'"?\b(?:block[_ -]?)?size(?:_bytes)?\b"?\s*[:=]\s*(\d+)\s*(?:bytes?|B)?\b',
        r'"?\bbytes\b"?\s*[:=]\s*(\d+)\b',
        r"\b(\d+)\s*(?:bytes?|B)\b",
    ):
        m = re.search(pattern, line, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None


class ClientParser(ABC):
    """Base class for client-specific log parsers.

    Each client (zeam, qlean, etc.) subclasses this to provide its own log
    format parsing.  Parsers are registered in ``shadow_fuzzer.clients`` and
    looked up per host by :func:`~shadow_fuzzer.clients.get_parser_for_host`.

    To add a new client:

    1. Create ``shadow_fuzzer/clients/<name>.py`` with a ``ClientParser``
       subclass.
    2. Register an instance in ``shadow_fuzzer/clients/__init__.py`` (insert
       before the fallback zeam parser so it takes priority).
    3. Add ``scripts/client-cmds/<name>-cmd.sh`` and config TOML entries
       (existing conventions, no Python changes needed).

    Events returned by :meth:`parse_line` must include a ``"_kind"`` key whose
    value is one of the canonical event categories:

    - ``"receive_attestation"``
    - ``"receive_block"``
    - ``"publish_block"``
    - ``"publish_attestation"``

    The ``"_kind"`` key is consumed (popped) by the event reader in
    ``stats_shadow.py`` and must not appear in the final event dict.

    All events must also include a ``"source"`` key (e.g. ``"zeam_text"``,
    ``"qlean_structured"``) used for source-level aggregation and warnings.
    """

    name: str
    """Unique identifier for this client (e.g. ``"zeam"``, ``"qlean"``)."""

    attestation_id_warning: str | None = None
    """If set, this warning is emitted when events with ``"<name>_text"`` as
    source appear in attestation coverage stats.  Use this for clients whose
    text-based attestation events use ``(slot, validator_id)`` as an
    identifier rather than a cryptographic attestation ID."""

    @abstractmethod
    def match_host(self, host_name: str) -> bool:
        """Return ``True`` if this parser should handle *host_name*.

        Called once per host directory.  The first parser (in registration
        order) whose ``match_host`` returns ``True`` wins.  The last parser
        in the registry (zeam) acts as the fallback and always returns
        ``True``.
        """
        ...

    def parse_timestamp(self, line: str, default_ts_ms: float) -> float:
        """Extract a timestamp in **milliseconds** from *line*.

        Override this if the client uses a non-standard log timestamp format.
        The default implementation returns *default_ts_ms* (the Shadow
        timestamp or last-seen timestamp) unchanged.
        """
        return default_ts_ms

    @abstractmethod
    def parse_line(self, line: str, ts_ms: float) -> list[dict[str, Any]]:
        """Parse a single log line and return zero or more event dicts.

        *ts_ms* is the resolved timestamp for this line in milliseconds,
        combining the Shadow timestamp with any client-specific override from
        :meth:`parse_timestamp`.

        Each returned event **must** include:

        - ``"_kind"`` – one of ``"receive_attestation"``, ``"receive_block"``,
          ``"publish_block"``, ``"publish_attestation"``.
        - ``"source"`` – a string identifying the parse source (e.g.
          ``"zeam_text"``, ``"qlean_structured"``).
        - Event-specific fields (``"slot"``, ``"validator_id"``, etc.).

        Return an empty list if the line does not match any known pattern.
        """
        ...

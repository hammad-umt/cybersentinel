from __future__ import annotations

import json
import shlex
from collections import deque
from typing import Deque, Dict, Iterable, Mapping

import pandas as pd

from config import PipelineConfig


class RealtimeFirewallLogBuffer:
    """Accepts live firewall events and exposes a recent scoring window."""

    def __init__(self, config: PipelineConfig | None = None, max_events: int | None = None):
        self.config = config or PipelineConfig()
        self.max_events = int(max_events or self.config.realtime_max_events)
        self._events: Deque[Dict[str, object]] = deque(maxlen=self.max_events)

    def add(self, event: Mapping[str, object] | str) -> Dict[str, object]:
        normalized = parse_firewall_event(event)
        normalized = self._apply_aliases(normalized)
        self._events.append(normalized)
        return normalized

    def extend(self, events: Iterable[Mapping[str, object] | str]) -> list[Dict[str, object]]:
        return [self.add(event) for event in events]

    def clear(self) -> None:
        self._events.clear()

    def to_frame(self, current_only: bool = True) -> pd.DataFrame:
        df = pd.DataFrame(list(self._events))
        if df.empty or not current_only or "timestamp" not in df.columns:
            return df

        timestamps = _parse_timestamps(df["timestamp"])
        if timestamps.notna().any():
            latest_window = timestamps.max().floor(self.config.timestamp_floor)
            return df.loc[timestamps.dt.floor(self.config.timestamp_floor) == latest_window].reset_index(drop=True)
        return df

    def __len__(self) -> int:
        return len(self._events)

    def _apply_aliases(self, event: Dict[str, object]) -> Dict[str, object]:
        lowered = {str(key).lower(): key for key in event}
        for canonical, aliases in self.config.column_aliases.items():
            if canonical in event:
                continue
            for alias in aliases:
                source = lowered.get(alias.lower())
                if source is not None:
                    event[canonical] = event[source]
                    break
        return event


def parse_firewall_event(event: Mapping[str, object] | str) -> Dict[str, object]:
    """Parse dict, JSON-line, or key=value firewall logs into a flat event dict."""
    if isinstance(event, Mapping):
        return dict(event)
    if not isinstance(event, str):
        raise TypeError("Realtime firewall events must be dict-like objects or strings.")

    text = event.strip()
    if not text:
        raise ValueError("Realtime firewall event cannot be empty.")

    parsed = _parse_json_line(text)
    if parsed is None:
        parsed = _parse_key_value_line(text)
    if parsed is None:
        raise ValueError("Unsupported firewall log string. Expected JSON or key=value fields.")

    return parsed


def _parse_json_line(text: str) -> Dict[str, object] | None:
    if not text.startswith("{"):
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON firewall log: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON firewall log must decode to an object.")
    return value


def _parse_key_value_line(text: str) -> Dict[str, object] | None:
    fields: Dict[str, object] = {}
    try:
        parts = shlex.split(text)
    except ValueError:
        parts = text.split()

    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        if not key:
            continue
        fields[key] = value.strip().strip('"')

    if not fields:
        return None

    # Fortinet-style logs often split date and time into separate fields.
    if "timestamp" not in fields and "date" in fields and "time" in fields:
        fields["timestamp"] = f"{fields['date']} {fields['time']}"

    return fields


def _parse_timestamps(series: pd.Series) -> pd.Series:
    try:
        return pd.to_datetime(series, errors="coerce", format="mixed")
    except TypeError:
        return pd.to_datetime(series, errors="coerce")

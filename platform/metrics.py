"""Small in-process metrics helpers with Prometheus text rendering."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from threading import Lock


MetricLabels = tuple[tuple[str, str], ...]


def _labels(labels: Mapping[str, object]) -> MetricLabels:
    return tuple(sorted((str(key), str(value)) for key, value in labels.items()))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class MetricsRegistry:
    """Thread-safe counter registry for low-cardinality operational metrics."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: Counter[tuple[str, MetricLabels]] = Counter()

    def increment(
        self, name: str, labels: Mapping[str, object] | None = None, value: int = 1
    ) -> None:
        if value <= 0:
            raise ValueError("metric increment value must be positive")
        with self._lock:
            self._counters[(name, _labels(labels or {}))] += value

    def snapshot(self) -> dict[tuple[str, MetricLabels], int]:
        with self._lock:
            return dict(self._counters)

    def render_prometheus(self, extra: Mapping[str, Mapping[str, int]] | None = None) -> str:
        lines: list[str] = []
        for (name, labels), value in sorted(self.snapshot().items()):
            lines.append(_render_metric_line(name, labels, value))
        for name, series in sorted((extra or {}).items()):
            for label_value, value in sorted(series.items()):
                lines.append(
                    _render_metric_line(name, (("status", str(label_value)),), value)
                )
        lines.append("")
        return "\n".join(lines)


def _render_metric_line(name: str, labels: MetricLabels, value: int) -> str:
    if not labels:
        return f"{name} {value}"
    label_text = ",".join(
        f'{key}="{_escape(label_value)}"' for key, label_value in labels
    )
    return f"{name}{{{label_text}}} {value}"

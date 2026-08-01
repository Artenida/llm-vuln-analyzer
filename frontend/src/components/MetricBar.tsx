import "./MetricBar.css";

export interface Segment {
  label: string;
  value: number;
  /** Any CSS colour, but always passed as a token: var(--sev-high). */
  color: string;
}

interface MetricBarProps {
  segments: Segment[];
  /** Shown when every segment is zero — e.g. "no findings". */
  emptyLabel?: string;
  /** Renders a label row under the bar. */
  showLegend?: boolean;
  height?: number;
}

/**
 * Horizontal proportion bar. Used for coverage, severity mix and the
 * confusion split. Deliberately CSS-only — see docs/frontend-plan.md §7 on why
 * no chart library is pulled in for shapes this simple.
 */
export function MetricBar({
  segments,
  emptyLabel = "no data",
  showLegend = false,
  height = 6,
}: MetricBarProps) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);

  if (total <= 0) {
    return <div className="metricbar__empty">{emptyLabel}</div>;
  }

  return (
    <div className="metricbar">
      <div
        className="metricbar__track"
        style={{ height }}
        role="img"
        aria-label={segments
          .filter((s) => s.value > 0)
          .map((s) => `${s.label}: ${s.value}`)
          .join(", ")}
      >
        {segments
          .filter((segment) => segment.value > 0)
          .map((segment) => (
            <div
              key={segment.label}
              className="metricbar__segment"
              style={{
                width: `${(segment.value / total) * 100}%`,
                background: segment.color,
              }}
              title={`${segment.label}: ${segment.value}`}
            />
          ))}
      </div>
      {showLegend && (
        <ul className="metricbar__legend">
          {segments
            .filter((segment) => segment.value > 0)
            .map((segment) => (
              <li key={segment.label}>
                <span
                  className="metricbar__swatch"
                  style={{ background: segment.color }}
                />
                {segment.label}
                <span className="metricbar__count num">{segment.value}</span>
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}

/** Severity mix in the order the eye should read it: worst first. */
export function SeverityBar({
  counts,
  showLegend = false,
}: {
  counts: Record<string, number>;
  showLegend?: boolean;
}) {
  const order = ["critical", "high", "medium", "low"];
  const segments: Segment[] = order.map((level) => ({
    label: level,
    value: counts[level] ?? 0,
    color: `var(--sev-${level})`,
  }));
  // An unrecognised severity string is still a finding — fold it in rather than
  // dropping it, so the bar's total always matches the run's finding count.
  const other = Object.entries(counts)
    .filter(([level]) => !order.includes(level))
    .reduce((sum, [, value]) => sum + value, 0);
  if (other > 0) {
    segments.push({ label: "other", value: other, color: "var(--sev-none)" });
  }
  return (
    <MetricBar segments={segments} emptyLabel="no findings" showLegend={showLegend} />
  );
}

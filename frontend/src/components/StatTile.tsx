import type { ReactNode } from "react";
import "./StatTile.css";

interface StatTileProps {
  label: string;
  value: ReactNode;
  /** Secondary line under the value — a denominator, a unit, a caveat. */
  hint?: ReactNode;
  /** Tints the value. Used sparingly: findings and failures, not every tile. */
  tone?: "default" | "accent" | "ok" | "warn" | "err" | "muted";
  /** Renders the value in a smaller size, for long strings like a model name. */
  compact?: boolean;
}

export function StatTile({
  label,
  value,
  hint,
  tone = "default",
  compact = false,
}: StatTileProps) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <div
        className={`stat__value stat__value--${tone}${compact ? " stat__value--compact" : ""}`}
      >
        {value}
      </div>
      {hint && <div className="stat__hint">{hint}</div>}
    </div>
  );
}

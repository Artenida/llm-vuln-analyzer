import type { ReactNode } from "react";
import "./Badge.css";

export type BadgeVariant =
  | "neutral"
  | "accent"
  | "ok"
  | "warn"
  | "err"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "none";

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  /** Outline instead of filled — for secondary metadata like a language tag. */
  subtle?: boolean;
  title?: string;
}

export function Badge({
  children,
  variant = "neutral",
  subtle = false,
  title,
}: BadgeProps) {
  return (
    <span
      className={`badge badge--${variant}${subtle ? " badge--subtle" : ""}`}
      title={title}
    >
      {children}
    </span>
  );
}

/** Severity strings come straight from the LLM output, so normalise defensively. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return <span className="faint">—</span>;
  const key = severity.toLowerCase();
  const variant: BadgeVariant = (
    ["critical", "high", "medium", "low"].includes(key) ? key : "none"
  ) as BadgeVariant;
  return <Badge variant={variant}>{key}</Badge>;
}

/** TP / FP / FN / TN, coloured by whether the tool got it right. */
export function OutcomeBadge({ outcome }: { outcome: string | null | undefined }) {
  if (!outcome) return <span className="faint">—</span>;
  const variant: BadgeVariant =
    outcome === "TP" ? "ok" : outcome === "FN" ? "err" : outcome === "FP" ? "warn" : "neutral";
  return <Badge variant={variant}>{outcome}</Badge>;
}

/** Agentic vs semantic — the thesis's central comparison, so it gets the accent. */
export function ModeBadge({ mode }: { mode: string | null | undefined }) {
  if (!mode) return <span className="faint">—</span>;
  return (
    <Badge variant={mode === "react_loop" ? "accent" : "neutral"} subtle title={mode}>
      {mode === "react_loop"
        ? "agentic"
        : mode === "call_graph_context"
          ? "semantic"
          : mode}
    </Badge>
  );
}

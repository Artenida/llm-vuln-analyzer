/**
 * Display formatting.
 *
 * The central rule: an absent value renders as `n/a`, never as `0`. A run from
 * before Sprint 7 has no cost data; showing `$0.00` would read as "this run was
 * free", which is a different and wrong claim. Every formatter here takes
 * `null | undefined` and returns the placeholder.
 */

export const NA = "n/a";

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return NA;
  return value.toLocaleString("en-US");
}

export function formatCost(value: number | null | undefined): string {
  if (value === null || value === undefined) return NA;
  if (value === 0) return "$0.00";
  // Sub-cent figures are common per function; two decimals would show them all
  // as $0.00 and make a per-function cost column useless.
  return value < 0.01 ? `$${value.toFixed(4)}` : `$${value.toFixed(2)}`;
}

export function formatPercent(
  value: number | null | undefined,
  digits = 1,
): string {
  if (value === null || value === undefined) return NA;
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatRatio(value: number | null | undefined): string {
  if (value === null || value === undefined) return NA;
  return value.toFixed(3);
}

export function formatTokens(value: number | null | undefined): string {
  if (value === null || value === undefined) return NA;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return String(value);
}

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return NA;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return NA;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-GB", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return NA;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const seconds = (Date.now() - date.getTime()) / 1000;
  const units: [number, Intl.RelativeTimeFormatUnit][] = [
    [60, "second"],
    [3600, "minute"],
    [86400, "hour"],
    [2592000, "day"],
    [31536000, "month"],
  ];
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  let previous = 1;
  for (const [limit, unit] of units) {
    if (seconds < limit) return formatter.format(-Math.round(seconds / previous), unit);
    previous = limit;
  }
  return formatter.format(-Math.round(seconds / 31536000), "year");
}

/** Collapses a long path to its last `keep` segments, prefixed with an ellipsis. */
export function shortPath(value: string | null | undefined, keep = 2): string {
  if (!value) return NA;
  const parts = value.replace(/\\/g, "/").split("/").filter(Boolean);
  if (parts.length <= keep) return parts.join("/");
  return `…/${parts.slice(-keep).join("/")}`;
}

/** Human label for an analysis mode tag from the run artifacts. */
export function modeLabel(mode: string | null | undefined): string {
  switch (mode) {
    case "react_loop":
      return "Agentic";
    case "call_graph_context":
      return "Semantic";
    case null:
    case undefined:
      return "—";
    default:
      return mode;
  }
}

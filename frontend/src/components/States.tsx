import type { ReactNode } from "react";
import { ApiError } from "@/api/client";
import "./States.css";

/**
 * The three states every async view must handle. Shipped as primitives in
 * Sprint 8 so no later page has an excuse to render a blank div while loading
 * or to swallow an error silently.
 */

export function EmptyState({
  title = "Nothing here",
  detail,
  icon = "∅",
}: {
  title?: string;
  detail?: ReactNode;
  icon?: string;
}) {
  return (
    <div className="state">
      <div className="state__icon" aria-hidden="true">
        {icon}
      </div>
      <div className="state__title">{title}</div>
      {detail && <div className="state__detail">{detail}</div>}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const status = error instanceof ApiError ? error.status : null;
  const message =
    error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div className="state state--error" role="alert">
      <div className="state__icon" aria-hidden="true">
        !
      </div>
      <div className="state__title">
        {status === 404 ? "Not found" : "Could not load this"}
      </div>
      <div className="state__detail mono">{message}</div>
    </div>
  );
}

export function Skeleton({
  rows = 3,
  height = 18,
}: {
  rows?: number;
  height?: number;
}) {
  return (
    <div className="skeleton" aria-busy="true" aria-live="polite">
      <span className="sr-only">Loading…</span>
      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          className="skeleton__row"
          style={{ height, width: `${100 - index * 7}%` }}
        />
      ))}
    </div>
  );
}

/**
 * Wraps the loading / error / empty branches so pages read as one expression.
 * `data` is narrowed to non-null inside `children`.
 */
export function QueryBoundary<T>({
  isLoading,
  error,
  data,
  skeletonRows,
  children,
}: {
  isLoading: boolean;
  error: unknown;
  data: T | undefined;
  skeletonRows?: number;
  children: (data: T) => ReactNode;
}) {
  if (isLoading) return <Skeleton rows={skeletonRows} />;
  if (error) return <ErrorState error={error} />;
  if (data === undefined) return <EmptyState />;
  return <>{children(data)}</>;
}

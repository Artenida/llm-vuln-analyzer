import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForgetHistory, useHistory, useOpenResultsFolder } from "@/api/hooks";
import type { HistoryEntry } from "@/api/types";
import {
  Badge,
  Button,
  Card,
  DataTable,
  DirectoryPicker,
  EmptyState,
  QueryBoundary,
} from "@/components";
import type { Column } from "@/components";
import { formatCost, formatDate, formatNumber } from "@/lib/format";
import "./shared/shared.css";

export function HistoryPage() {
  const { data, isLoading, error } = useHistory();
  const forget = useForgetHistory();
  const openFolder = useOpenResultsFolder();
  const navigate = useNavigate();
  const [picking, setPicking] = useState(false);

  const columns: Column<HistoryEntry>[] = [
    {
      id: "label",
      header: "Analysis",
      sortValue: (entry) => entry.label,
      cell: (entry) => (
        <div className="runcell">
          <span className="runcell__name">{entry.label}</span>
          <span className="runcell__note" title={entry.source_path ?? undefined}>
            {entry.source_path ?? "—"}
          </span>
        </div>
      ),
    },
    {
      id: "state",
      header: "State",
      sortValue: (entry) => entry.state,
      cell: (entry) => (
        <div className="row">
          <Badge
            variant={
              entry.state === "succeeded" ? "ok"
              : entry.state === "cancelled" ? "warn"
              : entry.state === "running" ? "accent"
              : "err"
            }
          >
            {entry.state}
          </Badge>
          {entry.partial && <Badge variant="warn">partial</Badge>}
        </div>
      ),
    },
    {
      id: "model",
      header: "Model",
      secondary: true,
      sortValue: (entry) => entry.model,
      cell: (entry) => <span className="mono dim">{entry.model ?? "—"}</span>,
    },
    {
      id: "functions",
      header: "Functions",
      align: "right",
      sortValue: (entry) => entry.total_functions,
      cell: (entry) => <span className="num">{formatNumber(entry.total_functions)}</span>,
    },
    {
      id: "findings",
      header: "Findings",
      align: "right",
      sortValue: (entry) => entry.vulnerabilities_found,
      cell: (entry) => (
        <span className="num" style={{ color: entry.vulnerabilities_found ? "var(--sev-high)" : undefined }}>
          {formatNumber(entry.vulnerabilities_found)}
        </span>
      ),
    },
    {
      id: "cost",
      header: "Cost",
      align: "right",
      sortValue: (entry) => entry.total_cost_usd,
      cell: (entry) => <span className="num">{formatCost(entry.total_cost_usd)}</span>,
    },
    {
      id: "when",
      header: "When",
      align: "right",
      secondary: true,
      sortValue: (entry) => entry.timestamp,
      cell: (entry) => <span className="faint nowrap">{formatDate(entry.timestamp)}</span>,
    },
    {
      id: "actions",
      header: "",
      align: "right",
      cell: (entry) => (
        <div className="row">
          {!entry.exists && (
            <Badge variant="err" title={entry.output_dir}>
              folder missing
            </Badge>
          )}
          <Button
            variant="ghost"
            onClick={() => forget.mutate(entry.id)}
            title="Remove from this list. The result files are not deleted."
          >
            Forget
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="stack">
      <div className="page-title">
        <h1>History</h1>
        <span className="page-subtitle">
          Analyses you have run, wherever their results were saved.
        </span>
      </div>

      {openFolder.error && (
        <div className="note note--error">
          <span className="note__label">Could not open that folder</span>
          {(openFolder.error as Error).message}
        </div>
      )}

      <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={5}>
        {(entries) => (
          <Card
            flush
            actions={
              <Button onClick={() => setPicking(true)} disabled={openFolder.isPending}>
                {openFolder.isPending ? "Opening…" : "Open a results folder…"}
              </Button>
            }
          >
            <DataTable
              columns={columns}
              rows={entries}
              rowKey={(entry) => entry.id}
              onRowClick={(entry) =>
                entry.exists &&
                navigate(`/results?path=${encodeURIComponent(entry.output_dir)}`)
              }
              initialSort={{ columnId: "when", direction: "desc" }}
              empty={
                <EmptyState
                  icon="▶"
                  title="Nothing here yet"
                  detail="Analyses you run appear here automatically. You can also open a results folder produced somewhere else."
                />
              }
            />
          </Card>
        )}
      </QueryBoundary>

      {picking && (
        <DirectoryPicker
          title="Open a results folder"
          confirmLabel="Open"
          onCancel={() => setPicking(false)}
          onPick={(path) => {
            setPicking(false);
            openFolder.mutate(path, {
              onSuccess: (entry) =>
                navigate(`/results?path=${encodeURIComponent(entry.output_dir)}`),
            });
          }}
        />
      )}
    </div>
  );
}

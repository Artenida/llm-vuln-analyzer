import { useCost, useCostByRun, useHistory } from "@/api/hooks";
import type { CostGroup } from "@/api/types";
import {
  Card,
  DataTable,
  EmptyState,
  MetricBar,
  QueryBoundary,
  StatTile,
} from "@/components";
import type { Column, Segment } from "@/components";
import { formatCost, formatNumber, formatTokens } from "@/lib/format";
import "./shared/shared.css";

/** The CLI's own phase tags, spelled out. */
const PHASE_LABELS: Record<string, string> = {
  edge_resolution: "Call-graph edge resolution",
  react_loop: "Analysis — agentic",
  call_graph_context: "Analysis — semantic",
  analysis: "Analysis",
  patch_generation: "Patch generation",
};

const PHASE_COLORS: Record<string, string> = {
  edge_resolution: "var(--sev-medium)",
  react_loop: "var(--accent)",
  call_graph_context: "var(--sev-low)",
  analysis: "var(--accent)",
  patch_generation: "var(--sev-high)",
};

export function CostsPage() {
  const { data, isLoading, error } = useCost();
  const { data: runs } = useCostByRun(25);
  const { data: history } = useHistory();

  return (
    <div className="stack">
      <div className="page-title">
        <h1>Costs</h1>
        <span className="page-subtitle">
          Everything spent on this machine, from the cost ledger.
        </span>
      </div>

      <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={4}>
        {(cost) =>
          !cost.available ? (
            <EmptyState
              icon="$"
              title="No spending recorded yet"
              detail={
                <>
                  The cost ledger is created by the first run that makes a real
                  API call. Nothing has been billed from{" "}
                  <code>{cost.ledger_path}</code> yet.
                </>
              }
            />
          ) : (
            <div className="stack">
              <div className="grid-stats">
                <StatTile
                  label="Total spend"
                  value={formatCost(cost.total?.cost_usd)}
                  tone="accent"
                  hint={
                    cost.total?.cost_usd === null
                      ? "some calls used an unpriced model"
                      : "all runs, all phases"
                  }
                />
                <StatTile label="API calls" value={formatNumber(cost.total?.calls)} />
                <StatTile
                  label="Tokens"
                  value={formatTokens(cost.total?.total_tokens)}
                  hint={`${formatTokens(cost.total?.prompt_tokens)} in · ${formatTokens(cost.total?.completion_tokens)} out`}
                />
                <StatTile label="Analyses run" value={formatNumber(history?.length ?? 0)} />
              </div>

              <Card
                title="Spend by phase"
                description="Which part of the pipeline the money went to."
              >
                <div className="stack">
                  <MetricBar
                    segments={phaseSegments(cost.by_phase)}
                    showLegend
                    height={10}
                    emptyLabel="nothing recorded"
                  />
                  <GroupTable groups={cost.by_phase} label="Phase" labels={PHASE_LABELS} />
                </div>
              </Card>

              <div className="grid-2">
                <Card title="By model">
                  <GroupTable groups={cost.by_model} label="Model" />
                </Card>
                <Card
                  title="By API key"
                  description="Attributed by alias. Key values are never stored in the ledger."
                >
                  <GroupTable groups={cost.by_api_key} label="Alias" />
                </Card>
              </div>

              <Card
                title="By run"
                description="Most recently active first."
                flush
              >
                <GroupTable groups={runs ?? []} label="Run id" flush />
              </Card>
            </div>
          )
        }
      </QueryBoundary>
    </div>
  );
}

function phaseSegments(groups: CostGroup[]): Segment[] {
  return groups
    .filter((group) => group.cost_usd)
    .map((group) => ({
      label: PHASE_LABELS[group.group_key] ?? group.group_key,
      value: group.cost_usd ?? 0,
      color: PHASE_COLORS[group.group_key] ?? "var(--sev-none)",
    }));
}

function GroupTable({
  groups,
  label,
  labels,
  flush = false,
}: {
  groups: CostGroup[];
  label: string;
  labels?: Record<string, string>;
  flush?: boolean;
}) {
  const columns: Column<CostGroup>[] = [
    {
      id: "key",
      header: label,
      sortValue: (g) => g.group_key,
      cell: (g) => (
        <span className={labels ? undefined : "mono"}>
          {labels?.[g.group_key] ?? g.group_key}
        </span>
      ),
    },
    {
      id: "calls",
      header: "Calls",
      align: "right",
      sortValue: (g) => g.calls,
      cell: (g) => <span className="num">{formatNumber(g.calls)}</span>,
    },
    {
      id: "prompt",
      header: "Prompt",
      align: "right",
      secondary: true,
      sortValue: (g) => g.prompt_tokens,
      cell: (g) => <span className="num">{formatTokens(g.prompt_tokens)}</span>,
    },
    {
      id: "completion",
      header: "Completion",
      align: "right",
      secondary: true,
      sortValue: (g) => g.completion_tokens,
      cell: (g) => <span className="num">{formatTokens(g.completion_tokens)}</span>,
    },
    {
      id: "cost",
      header: "Cost",
      align: "right",
      sortValue: (g) => g.cost_usd,
      cell: (g) => (
        <span
          className="num"
          title={
            g.cost_usd === null
              ? "At least one call in this group used a model missing from the pricing table. The whole group reports as unknown rather than a partial sum that would understate spend."
              : undefined
          }
        >
          {formatCost(g.cost_usd)}
        </span>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={groups}
      rowKey={(g) => g.group_key}
      dense={!flush}
      initialSort={{ columnId: "cost", direction: "desc" }}
      empty={<EmptyState title="Nothing recorded" />}
    />
  );
}

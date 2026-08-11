import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  useComparison,
  useEvaluationReport,
  useEvaluations,
  useEvaluationsForRun,
  useGroundTruthDatasets,
  useResult,
  useRunEvaluation,
} from "@/api/hooks";
import type {
  ComparisonEntry,
  CurationStatus,
  CweBreakdownRow,
  EvaluationInstance,
  EvaluationReport,
  ResultSummary,
  UnmatchedFinding,
  UnresolvedFinding,
} from "@/api/types";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  Field,
  FilterBar,
  FilterChips,
  MetricBar,
  ModeBadge,
  OutcomeBadge,
  QueryBoundary,
  Select,
  Skeleton,
  StatTile,
  Tabs,
} from "@/components";
import type { Column, Segment, TabItem } from "@/components";
import {
  formatCost,
  formatDate,
  formatNumber,
  formatPercent,
  formatRatio,
  formatRelative,
  formatTokens,
  shortPath,
} from "@/lib/format";
import { useAnalyzeForm } from "@/state/AnalyzeForm";
import "./shared/shared.css";
import "./EvaluationsPage.css";

// The confusion quadrants, in the order they are always shown. Colour carries
// the meaning: the two the tool got right are cool, the two it got wrong are
// the severity palette's alarm colours.
const CONFUSION: { key: "tp" | "fp" | "fn" | "tn"; label: string; color: string }[] = [
  { key: "tp", label: "TP — caught", color: "var(--ok)" },
  { key: "fn", label: "FN — missed", color: "var(--err)" },
  { key: "fp", label: "FP — false alarm", color: "var(--warn)" },
  { key: "tn", label: "TN — correctly clean", color: "var(--sev-none)" },
];

/**
 * Scoped to one run, not to the whole experiments tree.
 *
 * Addressed by the run's output directory, the same way Results is, so the two
 * pages stay in step and "the run I am looking at" survives a refresh. With no
 * `?path` it opens the run this session is working on. There is no run picker:
 * the UI keeps no list of past runs, so there is nothing to pick between.
 */
export function EvaluationsPage() {
  const [params] = useSearchParams();
  const explicitPath = params.get("path");
  const { form } = useAnalyzeForm();
  const path = explicitPath ?? form.lastResultDir;

  const { data: result, isLoading, error } = useResult(path);

  if (!path) {
    return (
      <EmptyState
        icon="±"
        title="No runs to score"
        detail={
          <>
            An evaluation scores a finished run against a ground truth dataset.{" "}
            <Link to="/">Run an analysis →</Link>
          </>
        }
      />
    );
  }

  return (
    <div className="stack">
      <div className="page-title">
        <h1>Evaluations</h1>
        <span className="page-subtitle">
          How one run scored against a ground truth dataset.
        </span>
      </div>

      <QueryBoundary isLoading={isLoading} error={error} data={result} skeletonRows={5}>
        {(run) => (
          <>
            <Card>
              <div className="eval__picker">
                <span className="dim">
                  Scoring <span className="mono">{shortPath(path, 2)}</span>
                </span>
                <Link
                  className="eval__crosslink"
                  to={`/results?path=${encodeURIComponent(path)}`}
                >
                  Open in Results ↗
                </Link>
              </div>
            </Card>
            <RunEvaluations path={path} run={run} />
          </>
        )}
      </QueryBoundary>
    </div>
  );
}

/** Everything on this page for the selected run, and nothing from any other. */
function RunEvaluations({ path, run }: { path: string; run: ResultSummary }) {
  const [params, setParams] = useSearchParams();
  const { data: reports, isLoading } = useEvaluationsForRun(run.run_id);
  const comparison = params.get("comparison");

  function select(key: "report" | "comparison", value: string | null) {
    const next = new URLSearchParams(params);
    next.delete("report");
    next.delete("comparison");
    if (value) next.set(key, value);
    setParams(next, { replace: true });
  }

  if (!run.run_id) {
    return (
      <EmptyState
        icon="±"
        title="This run cannot be scored"
        detail="It has no analysis.json, so there are no findings to match against a dataset."
      />
    );
  }

  if (isLoading || !reports) return <Skeleton rows={5} />;

  const selected =
    reports.find((report) => report.path === params.get("report"))?.path ??
    reports[0]?.path ??
    null;

  return (
    <div className="stack">
      {reports.length === 0 ? (
        <EmptyState
          icon="±"
          title="This run has not been scored"
          detail={
            <>
              Pick a ground truth dataset below to score it, or run{" "}
              <code>evaluate</code> from the terminal.
            </>
          }
        />
      ) : (
        <>
          {/* Only when the same run was scored against several datasets. */}
          {reports.length > 1 && (
            <div className="eval__reportchips">
              {reports.map((report) => (
                <button
                  key={report.path}
                  type="button"
                  className={report.path === selected ? "chip chip--active" : "chip"}
                  aria-pressed={report.path === selected}
                  onClick={() => select("report", report.path)}
                >
                  {report.dataset ?? report.name}
                </button>
              ))}
            </div>
          )}
          {selected && <ReportDetail path={selected} />}
        </>
      )}

      <ScoreRunCard
        runPath={path}
        runLabel={run.display_dir.split(/[\\/]/).pop() ?? path}
        scored={reports.map((report) => report.dataset)}
      />

      {comparison ? (
        <ComparisonView path={comparison} onClose={() => select("comparison", null)} />
      ) : (
        <RunComparisons datasets={reports.map((report) => report.dataset)}
                        onOpen={(target) => select("comparison", target)} />
      )}
    </div>
  );
}

// ── one report ───────────────────────────────────────────────────────────────

function ReportDetail({ path }: { path: string }) {
  const { data, isLoading, error } = useEvaluationReport(path);

  return (
    <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={6}>
      {(report) => (
        <div className="stack">
          <Card
            title={report.run_id ?? report.name}
            description={
              <span className="eval__subhead">
                <ModeBadge mode={report.analysis_mode} />
                {report.model && <Badge variant="neutral" subtle>{report.model}</Badge>}
                <span className="dim">
                  {report.dataset} · scored {formatDate(report.generated_at)}
                </span>
              </span>
            }
          >
            <div className="stack">
              <CurationNote curation={report.curation} />
              <Scorecard report={report} />
              <ConfusionSplit report={report} />
            </div>
          </Card>

          <ReportTabs report={report} />
        </div>
      )}
    </QueryBoundary>
  );
}

/**
 * The warning has to travel with the numbers. A scaffolded ground truth defaults
 * every row to clean, so a run scored against one gets a plausible precision and
 * a meaningless one — and nothing else on the page reveals the difference.
 */
function CurationNote({ curation }: { curation: CurationStatus }) {
  if (!curation.known) {
    return (
      <div className="note">
        <span className="note__label">Ground truth not on this machine</span>
        The dataset these numbers were scored against could not be found, so
        whether it was curated cannot be verified here.
      </div>
    );
  }
  if (!curation.needs_curation) return null;
  return (
    <div className="note">
      <span className="note__label">These numbers are not valid</span>
      The ground truth is an uncurated skeleton —{" "}
      {formatNumber(curation.functions_unreviewed)} row(s) default to clean and{" "}
      {formatNumber(curation.functions_prefilled_vulnerable)} are unconfirmed.
      Curate <code>{shortPath(curation.ground_truth_path, 3)}</code> and re-score
      before quoting anything below.
    </div>
  );
}

function Scorecard({ report }: { report: EvaluationReport }) {
  const m = report.detection_metrics;
  const unique = report.unique_vulnerability_recall;
  return (
    <div className="grid-stats">
      <StatTile
        label="Precision"
        value={formatRatio(m.precision)}
        hint={`${m.tp} of ${m.tp + m.fp} flagged were real`}
      />
      <StatTile
        label="Recall"
        value={formatRatio(m.recall)}
        hint={`${m.tp} of ${m.tp + m.fn} planted were caught`}
      />
      <StatTile label="F1" value={formatRatio(m.f1)} tone="accent" hint="harmonic mean" />
      <StatTile
        label="Unique recall"
        value={formatRatio(unique.recall)}
        hint={`${unique.detected} of ${unique.planted} distinct bugs`}
      />
      <StatTile
        label="CWE accuracy"
        value={formatPercent(report.cwe_accuracy_on_true_positives)}
        hint="exact CWE, among true positives"
      />
      <StatTile
        label="Hallucination rate"
        value={formatPercent(report.hallucination_rate_on_flagged)}
        tone={report.hallucination_rate_on_flagged ? "warn" : "default"}
        hint="among everything it flagged"
      />
      <StatTile
        label="Run cost"
        value={formatCost(report.total_cost_usd)}
        hint={
          report.total_cost_usd === null
            ? "not recorded for this run"
            : `${formatTokens(report.total_tokens)} tokens`
        }
      />
      <StatTile
        label="$ per true positive"
        value={formatCost(report.cost_per_tp_usd)}
        hint={
          report.cost_per_tp_usd === null
            ? "no cost recorded, or no true positives"
            : "what one real finding cost"
        }
      />
    </div>
  );
}

function ConfusionSplit({ report }: { report: EvaluationReport }) {
  const m = report.detection_metrics;
  const segments: Segment[] = CONFUSION.map((q) => ({
    label: q.label,
    value: m[q.key] ?? 0,
    color: q.color,
  }));
  return (
    <div className="stack">
      <MetricBar segments={segments} showLegend height={10} emptyLabel="nothing scored" />
      <p className="faint eval__footnote">
        One row per ground truth function, not per finding. Functions the run
        never analysed count as missed, not as skipped — a partial run scores as
        the recall it actually delivered.
      </p>
    </div>
  );
}

// ── instances, per-CWE, unscored ─────────────────────────────────────────────

function ReportTabs({ report }: { report: EvaluationReport }) {
  const unscored = report.unmatched_findings.length + report.unresolved_findings.length;
  const tabs: TabItem[] = [
    { id: "instances", label: "Scored functions", count: report.instances.length },
    { id: "cwe", label: "Per-CWE", count: report.cwe_breakdown.length },
    { id: "unscored", label: "Unscored", count: unscored || null },
  ];

  return (
    <Tabs items={tabs} param="etab">
      {(active) => {
        if (active === "cwe") return <CweBreakdown rows={report.cwe_breakdown} />;
        if (active === "unscored") return <Unscored report={report} />;
        return <Instances instances={report.instances} />;
      }}
    </Tabs>
  );
}

const OUTCOME_FACETS = ["TP", "FP", "FN", "TN", "wrong CWE", "hallucinated"];

function Instances({ instances }: { instances: EvaluationInstance[] }) {
  const [search, setSearch] = useState("");
  const [facets, setFacets] = useState<string[]>([]);

  const rows = useMemo(() => {
    const needle = search.toLowerCase();
    const outcomes = facets.filter((f) => ["TP", "FP", "FN", "TN"].includes(f));
    return instances.filter((row) => {
      if (outcomes.length && !outcomes.includes(row.outcome)) return false;
      if (facets.includes("wrong CWE") && (row.outcome !== "TP" || row.cwe_correct)) return false;
      if (facets.includes("hallucinated") && !row.hallucination_flag) return false;
      if (!needle) return true;
      return (
        row.function_name.toLowerCase().includes(needle) ||
        (row.file ?? "").toLowerCase().includes(needle) ||
        (row.gt_cwe ?? "").toLowerCase().includes(needle) ||
        (row.predicted_cwe ?? "").toLowerCase().includes(needle)
      );
    });
  }, [instances, search, facets]);

  const columns: Column<EvaluationInstance>[] = [
    {
      id: "outcome",
      header: "Outcome",
      width: "88px",
      sortValue: (i) => i.outcome,
      cell: (i) => <OutcomeBadge outcome={i.outcome} />,
    },
    {
      id: "function",
      header: "Function",
      sortValue: (i) => i.function_name,
      cell: (i) => (
        <div className="runcell">
          <span className="runcell__name">{i.function_name}</span>
          <span className="runcell__note" title={i.file}>{shortPath(i.file, 2)}</span>
        </div>
      ),
    },
    {
      id: "expected",
      header: "Ground truth",
      sortValue: (i) => (i.gt_vulnerable ? 1 : 0),
      cell: (i) =>
        i.gt_vulnerable ? (
          <span className="mono">{i.gt_cwe ?? "vulnerable"}</span>
        ) : (
          <span className="faint">clean</span>
        ),
    },
    {
      id: "predicted",
      header: "Predicted",
      sortValue: (i) => (i.predicted_vulnerable ? 1 : 0),
      cell: (i) =>
        !i.analyzed ? (
          <span className="faint" title="This function was never analysed by the run.">
            not analysed
          </span>
        ) : i.predicted_vulnerable ? (
          <span className="mono">{i.predicted_cwe ?? "vulnerable"}</span>
        ) : (
          <span className="faint">clean</span>
        ),
    },
    {
      id: "flags",
      header: "",
      cell: (i) => (
        <div className="row wrap">
          {i.outcome === "TP" && !i.cwe_correct && (
            <Badge variant="medium" subtle title="Right function, wrong CWE.">
              wrong CWE
            </Badge>
          )}
          {i.hallucination_flag && (
            <Badge variant="warn" subtle title="Flagged with no supporting ground truth.">
              hallucinated
            </Badge>
          )}
        </div>
      ),
    },
  ];

  return (
    <Card flush title="Scored functions" description="Every ground truth row and how the run called it.">
      <FilterBar
        search={search}
        onSearch={setSearch}
        placeholder="Search function, file or CWE…"
        count={`${rows.length} of ${instances.length}`}
        onReset={search || facets.length ? () => { setSearch(""); setFacets([]); } : undefined}
      >
        <FilterChips options={OUTCOME_FACETS} selected={facets} onChange={setFacets} />
      </FilterBar>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(i) => i.instance_id}
        dense
        initialSort={{ columnId: "outcome", direction: "asc" }}
        empty={<EmptyState title="Nothing matches that filter" />}
      />
    </Card>
  );
}

function CweBreakdown({ rows }: { rows: CweBreakdownRow[] }) {
  const columns: Column<CweBreakdownRow>[] = [
    {
      id: "cwe",
      header: "CWE",
      sortValue: (r) => r.cwe_id,
      cell: (r) => <span className="mono">{r.cwe_id}</span>,
    },
    {
      id: "planted",
      header: "Planted",
      align: "right",
      sortValue: (r) => r.planted,
      cell: (r) => <span className="num">{r.planted}</span>,
    },
    {
      id: "detected",
      header: "Detected",
      align: "right",
      sortValue: (r) => r.detected,
      cell: (r) => <span className="num">{r.detected}</span>,
    },
    {
      id: "correct",
      header: "Correct CWE",
      align: "right",
      sortValue: (r) => r.cwe_correct,
      cell: (r) => <span className="num">{r.cwe_correct}</span>,
    },
    {
      id: "rate",
      header: "Detection",
      width: "180px",
      sortValue: (r) => (r.planted ? r.detected / r.planted : null),
      cell: (r) => (
        <MetricBar
          segments={[
            { label: "correct CWE", value: r.cwe_correct, color: "var(--ok)" },
            {
              label: "detected, wrong CWE",
              value: Math.max(0, r.detected - r.cwe_correct),
              color: "var(--sev-medium)",
            },
            { label: "missed", value: Math.max(0, r.planted - r.detected), color: "var(--err)" },
          ]}
        />
      ),
    },
  ];

  return (
    <Card
      flush
      title="Per-CWE breakdown"
      description="Deduplicated: counted per distinct planted vulnerability, not per function it appears in."
    >
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.cwe_id}
        dense
        initialSort={{ columnId: "planted", direction: "desc" }}
        empty={<EmptyState title="No vulnerabilities in this dataset" />}
      />
    </Card>
  );
}

/** Neither list is keyed by anything unique — the same function name in the same
 *  file legitimately appears twice — so rows carry their position as an id. */
type Indexed<T> = T & { rowId: string };

function indexed<T>(rows: T[]): Indexed<T>[] {
  return rows.map((row, i) => ({ ...row, rowId: String(i) }));
}

function Unscored({ report }: { report: EvaluationReport }) {
  const unmatched: Column<Indexed<UnmatchedFinding>>[] = [
    {
      id: "function",
      header: "Function",
      sortValue: (f) => f.function_name,
      cell: (f) => <span className="mono">{f.function_name ?? "—"}</span>,
    },
    {
      id: "file",
      header: "File",
      cell: (f) => (
        <span className="mono dim" title={f.file_path ?? ""}>
          {shortPath(f.file_path, 2)}
        </span>
      ),
    },
    {
      id: "verdict",
      header: "Verdict",
      cell: (f) =>
        f.vulnerability_found ? (
          <span className="mono">{f.cwe_id ?? "vulnerable"}</span>
        ) : (
          <span className="faint">clean</span>
        ),
    },
  ];

  const unresolved: Column<Indexed<UnresolvedFinding>>[] = [
    {
      id: "function",
      header: "Function",
      sortValue: (f) => f.function_name,
      cell: (f) => <span className="mono">{f.function_name}</span>,
    },
    {
      id: "expected",
      header: "Expected file",
      cell: (f) => (
        <span className="mono dim" title={f.expected_file}>
          {shortPath(f.expected_file, 2)}
        </span>
      ),
    },
    {
      id: "candidates",
      header: "Candidates",
      cell: (f) => (
        <span className="mono dim">
          {f.candidate_files.filter(Boolean).map((c) => shortPath(c, 2)).join(", ") || "—"}
        </span>
      ),
    },
  ];

  return (
    <div className="stack">
      <Card
        flush
        title="Findings with no ground truth row"
        description="Reported by the run against a function the dataset does not cover — neither credited nor penalised."
      >
        <DataTable
          columns={unmatched}
          rows={indexed(report.unmatched_findings)}
          rowKey={(f) => f.rowId}
          dense
          empty={<EmptyState title="Every finding matched a ground truth row" />}
        />
      </Card>

      <Card
        flush
        title="Ambiguous matches"
        description="The same function name in several files, and the file path could not disambiguate. Scored as unanalysed."
      >
        <DataTable
          columns={unresolved}
          rows={indexed(report.unresolved_findings)}
          rowKey={(f) => f.rowId}
          dense
          empty={<EmptyState title="Nothing ambiguous" />}
        />
      </Card>
    </div>
  );
}

// ── saved comparisons for this run's dataset ─────────────────────────────────

/**
 * The one place another run's numbers can still appear, and only as a document
 * the user deliberately produced: `evaluate` with several `--results` writes a
 * markdown table comparing them. Filtered to the dataset this run was scored
 * against, so it is context for what is on screen rather than a directory dump.
 */
function RunComparisons({
  datasets,
  onOpen,
}: {
  datasets: (string | null)[];
  onOpen: (path: string) => void;
}) {
  const { data } = useEvaluations();
  const wanted = new Set(datasets.filter(Boolean) as string[]);
  const entries = (data?.comparisons ?? []).filter((entry) =>
    entry.dataset ? wanted.has(entry.dataset) : false,
  );
  if (entries.length === 0) return null;

  const columns: Column<ComparisonEntry>[] = [
    {
      id: "name",
      header: "Comparison",
      sortValue: (c) => c.name,
      cell: (c) => <span className="mono">{c.name}</span>,
    },
    { id: "dataset", header: "Dataset", sortValue: (c) => c.dataset, cell: (c) => c.dataset ?? "—" },
    {
      id: "when",
      header: "Written",
      align: "right",
      sortValue: (c) => c.modified_at,
      cell: (c) => <span className="dim">{formatRelative(c.modified_at)}</span>,
    },
  ];

  return (
    <Card
      flush
      title="Saved comparisons"
      description="Multi-run tables written by evaluate, for the dataset this run was scored against."
    >
      <DataTable
        columns={columns}
        rows={entries}
        rowKey={(c) => c.path}
        dense
        onRowClick={(c) => onOpen(c.path)}
        initialSort={{ columnId: "when", direction: "desc" }}
      />
    </Card>
  );
}

function ComparisonView({ path, onClose }: { path: string; onClose: () => void }) {
  const { data, isLoading, error } = useComparison(path);
  return (
    <Card
      title="Comparison"
      description={shortPath(path, 3)}
      actions={<Button variant="ghost" onClick={onClose}>Close</Button>}
    >
      <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={6}>
        {(text) => <pre className="rawblock eval__markdown">{text}</pre>}
      </QueryBoundary>
    </Card>
  );
}

// ── scoring the selected run ─────────────────────────────────────────────────

/** The run is whatever the page is showing — only the dataset is a choice. */
function ScoreRunCard({
  runPath,
  runLabel,
  scored,
}: {
  runPath: string;
  runLabel: string;
  scored: (string | null)[];
}) {
  const { data: datasets } = useGroundTruthDatasets();
  const score = useRunEvaluation();
  const [dataset, setDataset] = useState("");

  if (!datasets) return <Skeleton rows={3} />;

  if (datasets.length === 0) {
    return (
      <Card title="Score this run" description="Nothing to score against yet.">
        <p className="prose">
          Evaluation needs a ground truth dataset in{" "}
          <code>experiments/datasets/</code>. Create one with{" "}
          <code>bootstrap-ground-truth</code>, then curate it — the scaffold
          defaults every function to clean.
        </p>
      </Card>
    );
  }

  const chosen = datasets.find((d) => d.path === dataset);
  const already = new Set(scored.filter(Boolean) as string[]);

  return (
    <Card
      title="Score this run"
      description={`Match ${runLabel}'s findings against a dataset. Local, read-only and free — no API calls.`}
    >
      <div className="stack">
        <Field label="Ground truth" hint={chosen?.description || "From experiments/datasets/."}>
          <Select
            value={dataset}
            onChange={setDataset}
            options={[
              { value: "", label: "Choose a dataset…" },
              ...datasets.map((d) => ({
                value: d.path,
                // Says which datasets this run already has a score against, so
                // re-scoring is a deliberate act rather than an accident.
                label: `${d.name} — ${d.vulnerable_count} of ${d.function_count} vulnerable${already.has(d.name) ? " (already scored)" : ""}`,
              })),
            ]}
          />
        </Field>

        {chosen?.curation.needs_curation && (
          <div className="note">
            <span className="note__label">Uncurated dataset</span>
            {chosen.name} is a scaffold that has not been reviewed. It will score
            without error, and the result will not mean anything.
          </div>
        )}

        <div className="row">
          <Button
            variant="primary"
            disabled={!dataset || score.isPending}
            onClick={() => score.mutate({ path: runPath, ground_truth: dataset })}
          >
            {score.isPending
              ? "Scoring…"
              : chosen && already.has(chosen.name)
                ? "Re-score run"
                : "Score run"}
          </Button>
          {score.error != null && (
            <span className="eval__error">{(score.error as Error).message}</span>
          )}
        </div>

        <p className="faint eval__footnote">
          The report is written to{" "}
          <code>experiments/datasets/&lt;dataset&gt;/evaluations/</code>, the same
          place the <code>evaluate</code> command writes it. Nothing else is
          modified. Re-scoring overwrites this run's existing report.
        </p>
      </div>
    </Card>
  );
}

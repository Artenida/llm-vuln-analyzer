import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { apiUrl } from "@/api/client";
import {
  useActiveJob,
  useAppliedPatches,
  useApplyPatch,
  useArtifact,
  useEvaluationsForRun,
  useExtraction,
  useFindings,
  useGraph,
  useHistory,
  usePatches,
  useResult,
  useRevertPatch,
  useStartPatch,
} from "@/api/hooks";
import type {
  AppliedPatch,
  ExtractedFunction,
  Finding,
  GraphNode,
  PatchRecord,
  ResultSummary,
  SkippedFunction,
} from "@/api/types";
import {
  Badge,
  Button,
  Card,
  CodeBlock,
  DataTable,
  DiffView,
  Drawer,
  EmptyState,
  FilterBar,
  FilterChips,
  JsonViewer,
  MetricBar,
  ModeBadge,
  QueryBoundary,
  SeverityBadge,
  SeverityBar,
  Skeleton,
  StatTile,
  Tabs,
} from "@/components";
import type { Column, TabItem } from "@/components";
import {
  formatBytes,
  formatCost,
  formatDate,
  formatNumber,
  formatPercent,
  formatRatio,
  formatTokens,
} from "@/lib/format";
import "./ResultsPage.css";

export function ResultsPage() {
  const [params] = useSearchParams();
  const explicitPath = params.get("path");
  const { data: history, isLoading: historyLoading } = useHistory();

  // With no ?path, open the most recent result that still exists on disk, so
  // "Results" in the sidebar is a one-click route to what you just ran.
  const latest = useMemo(
    () => history?.find((entry) => entry.exists)?.output_dir ?? null,
    [history],
  );
  const path = explicitPath ?? latest;

  const { data, isLoading, error } = useResult(path);

  if (!path) {
    if (historyLoading) return <Skeleton rows={5} />;
    return (
      <EmptyState
        icon="▶"
        title="No results yet"
        detail={
          <>
            Run an analysis and it will show up here.{" "}
            <Link to="/">Go to Analyze →</Link>
          </>
        }
      />
    );
  }

  return (
    <div className="stack">
      <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={6}>
        {(result) => <ResultBody result={result} path={path} />}
      </QueryBoundary>
    </div>
  );
}

function ResultBody({ result, path }: { result: ResultSummary; path: string }) {
  const tabs: TabItem[] = [
    { id: "summary", label: "Summary" },
    {
      id: "findings",
      label: "Findings",
      count: result.totals.vulnerabilities_found ?? null,
      disabled: !result.has_analysis,
      disabledReason: "This run produced no analysis.json",
    },
    {
      id: "graph",
      label: "Call graph",
      count: result.graph_nodes || null,
      disabled: !result.has_graph && !result.has_graph_html,
      disabledReason: "No call graph in this run",
    },
    {
      id: "extraction",
      label: "Extraction",
      count: result.extraction_totals.functions_found ?? null,
      disabled: !result.has_extraction,
      disabledReason: "No extraction.json in this run",
    },
    { id: "patches", label: "Patches", count: result.patch_summary?.total_patches ?? null },
    { id: "raw", label: "Raw", count: result.artifacts.length },
  ];

  return (
    <>
      <div className="page-title">
        <h1 className="title-mono">{result.display_dir.split(/[\\/]/).pop()}</h1>
        <ModeBadge mode={result.analysis_mode} />
        {result.model && <Badge variant="neutral" subtle>{result.model}</Badge>}
        {result.partial && <Badge variant="warn">partial run</Badge>}
      </div>

      {result.partial && (
        <div className="note">
          <span className="note__label">This run did not finish</span>
          {result.partial_reason ??
            "It was cancelled or hit its budget ceiling."}{" "}
          Only {formatNumber(result.totals.total_functions)} function(s) were
          analysed — do not read the counts below as coverage of the whole
          project.
        </div>
      )}

      <Tabs items={tabs}>
        {(active) => {
          if (active === "findings") return <FindingsTab path={path} />;
          if (active === "graph") return <GraphTab path={path} result={result} />;
          if (active === "extraction") return <ExtractionTab path={path} />;
          if (active === "patches") return <PatchesTab path={path} result={result} />;
          if (active === "raw") return <RawTab path={path} result={result} />;
          return <SummaryTab result={result} />;
        }}
      </Tabs>
    </>
  );
}

// ── summary ──────────────────────────────────────────────────────────────────

function SummaryTab({ result }: { result: ResultSummary }) {
  const totals = result.totals;
  const extraction = result.extraction_totals;

  return (
    <div className="stack">
      <div className="grid-stats">
        <StatTile label="Functions analysed" value={formatNumber(totals.total_functions)} />
        <StatTile
          label="Findings"
          value={formatNumber(totals.vulnerabilities_found)}
          tone={totals.vulnerabilities_found ? "warn" : "default"}
        />
        <StatTile label="Clean" value={formatNumber(totals.clean)} tone="ok" />
        <StatTile
          label="Errors"
          value={formatNumber(totals.errors)}
          tone={totals.errors ? "err" : "muted"}
        />
        <StatTile
          label="Cost"
          value={formatCost(totals.total_cost_usd)}
          tone="accent"
          hint={
            totals.total_cost_usd === null || totals.total_cost_usd === undefined
              ? "not recorded for this run"
              : `${formatTokens(totals.total_tokens)} tokens`
          }
        />
      </div>

      <EvaluationLink result={result} />

      <div className="grid-2">
        <Card title="Severity mix">
          <SeverityBar counts={result.severity_counts} showLegend />
        </Card>

        <Card
          title="Coverage"
          description="Functions extracted versus functions seen. Anything skipped was never analysed."
        >
          {result.has_extraction ? (
            <div className="stack-sm">
              <MetricBar
                segments={[
                  {
                    label: "analysed",
                    value: extraction.functions_found ?? 0,
                    color: "var(--accent)",
                  },
                  {
                    label: "skipped — too long",
                    value: extraction.functions_skipped_oversized ?? 0,
                    color: "var(--warn)",
                  },
                ]}
                showLegend
                height={8}
              />
              <div className="row-between">
                <span className="dim">Coverage</span>
                <span className="num">{formatPercent(extraction.coverage, 2)}</span>
              </div>
            </div>
          ) : (
            <p className="faint">No extraction.json in this run.</p>
          )}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Run details">
          <dl className="kv">
            <dt>Analysed</dt>
            <dd>{result.source_path ?? "n/a"}</dd>
            <dt>Results in</dt>
            <dd>{result.output_dir}</dd>
            <dt>Run id</dt>
            <dd>{result.run_id ?? "n/a"}</dd>
            <dt>Model</dt>
            <dd>{result.model ?? "n/a"}</dd>
            <dt>Mode</dt>
            <dd>{result.analysis_mode ?? "n/a"}</dd>
            <dt>When</dt>
            <dd>{formatDate(result.timestamp ?? result.modified_at)}</dd>
            <dt>Graph nodes</dt>
            <dd>{formatNumber(result.graph_nodes)}</dd>
          </dl>
        </Card>

        <Card title="Tokens and phases">
          <dl className="kv">
            <dt>Prompt</dt>
            <dd>{formatNumber(totals.total_prompt_tokens)}</dd>
            <dt>Completion</dt>
            <dd>{formatNumber(totals.total_completion_tokens)}</dd>
            <dt>Total</dt>
            <dd>{formatNumber(totals.total_tokens)}</dd>
          </dl>
          {Object.keys(result.meta).length > 0 && (
            <>
              <p className="faint results__metanote">
                Call-graph edge resolution is reported separately — the graph is
                built once and cached, so folding it into the per-run total
                would double-count it on every later run.
              </p>
              <dl className="kv">
                {Object.entries(result.meta).map(([field, value]) => (
                  <span key={field} style={{ display: "contents" }}>
                    <dt>{field.replace(/_/g, " ")}</dt>
                    <dd>
                      {typeof value === "number"
                        ? field.endsWith("cost_usd")
                          ? formatCost(value)
                          : formatNumber(value)
                        : String(value)}
                    </dd>
                  </span>
                ))}
              </dl>
            </>
          )}
        </Card>
      </div>

      {Object.keys(result.cwe_counts).length > 0 && (
        <Card title="CWEs flagged">
          <div className="row wrap">
            {Object.entries(result.cwe_counts)
              .sort((a, b) => b[1] - a[1])
              .map(([cwe, count]) => (
                <Badge key={cwe} variant="neutral">
                  {cwe} <span className="faint">×{count}</span>
                </Badge>
              ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── findings ─────────────────────────────────────────────────────────────────

function FindingsTab({ path }: { path: string }) {
  const { data, isLoading, error } = useFindings(path);
  const [search, setSearch] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [onlyFlagged, setOnlyFlagged] = useState(true);
  const [selected, setSelected] = useState<Finding | null>(null);

  const all = data ?? [];
  const rows = useMemo(() => {
    const needle = search.toLowerCase();
    return all.filter((finding) => {
      if (onlyFlagged && !finding.vulnerability_found) return false;
      if (severities.length > 0 && !severities.includes(finding.severity ?? "none")) {
        return false;
      }
      if (!needle) return true;
      return [
        finding.function_name,
        finding.file_path,
        finding.cwe_id,
        finding.explanation,
      ]
        .filter(Boolean)
        .some((field) => field!.toLowerCase().includes(needle));
    });
  }, [all, search, severities, onlyFlagged]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of all) {
      if (!finding.vulnerability_found) continue;
      const key = finding.severity ?? "none";
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return counts;
  }, [all]);

  const columns: Column<Finding>[] = [
    {
      id: "severity",
      header: "Severity",
      width: "96px",
      sortValue: (f) => SEVERITY_ORDER[f.severity ?? "none"] ?? 0,
      cell: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      id: "function",
      header: "Function",
      sortValue: (f) => f.function_name,
      cell: (f) => <span className="mono">{f.function_name}</span>,
    },
    {
      id: "file",
      header: "File",
      sortValue: (f) => f.file_path,
      cell: (f) => (
        <span className="mono dim results__file" title={f.file_path}>
          {f.file_path}
        </span>
      ),
    },
    {
      id: "cwe",
      header: "CWE",
      sortValue: (f) => f.cwe_id,
      cell: (f) => (f.cwe_id ? <Badge variant="neutral">{f.cwe_id}</Badge> : <span className="faint">—</span>),
    },
    {
      id: "lines",
      header: "Lines",
      align: "right",
      secondary: true,
      sortValue: (f) => f.affected_lines?.[0] ?? null,
      cell: (f) =>
        f.affected_lines?.length ? (
          <span className="num faint">{f.affected_lines.join(", ")}</span>
        ) : (
          <span className="faint">—</span>
        ),
    },
    {
      id: "confidence",
      header: "Conf.",
      align: "right",
      sortValue: (f) => f.confidence,
      cell: (f) => (
        <span className="num">{f.confidence !== null ? f.confidence.toFixed(2) : "—"}</span>
      ),
    },
    {
      id: "flags",
      header: "Flags",
      secondary: true,
      cell: (f) => (
        <div className="row">
          {f.hallucination_flag && <Badge variant="warn">hallucinated</Badge>}
          {f.error && <Badge variant="err">error</Badge>}
          {f.duplicate_group !== null && (
            <Badge variant="neutral" subtle title="Same function+CWE flagged in more than one file">
              dup {f.duplicate_group}
            </Badge>
          )}
          {f.patch_valid === true && <Badge variant="ok">patch</Badge>}
        </div>
      ),
    },
    {
      id: "cost",
      header: "Cost",
      align: "right",
      secondary: true,
      sortValue: (f) => f.cost_usd ?? null,
      cell: (f) => <span className="num">{formatCost(f.cost_usd)}</span>,
    },
  ];

  return (
    <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={8}>
      {() => (
        <>
          <Card flush>
            <FilterBar
              search={search}
              onSearch={setSearch}
              placeholder="Search function, file, CWE, explanation…"
              count={`${rows.length} of ${onlyFlagged ? Object.values(severityCounts).reduce((a, b) => a + b, 0) : all.length}`}
              onReset={
                search || severities.length || !onlyFlagged
                  ? () => {
                      setSearch("");
                      setSeverities([]);
                      setOnlyFlagged(true);
                    }
                  : undefined
              }
            >
              <FilterChips
                options={["critical", "high", "medium", "low"]}
                selected={severities}
                onChange={setSeverities}
                counts={severityCounts}
              />
              <FilterChips
                options={["include clean"]}
                selected={onlyFlagged ? [] : ["include clean"]}
                onChange={(next) => setOnlyFlagged(next.length === 0)}
                counts={{ "include clean": all.length - Object.values(severityCounts).reduce((a, b) => a + b, 0) }}
              />
            </FilterBar>
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(f) => `${f.file_path}::${f.function_name}`}
              onRowClick={setSelected}
              isActive={(f) => selected === f}
              initialSort={{ columnId: "severity", direction: "desc" }}
              empty={
                <EmptyState
                  title="No findings match"
                  detail="Clear the filters, or include clean functions."
                />
              }
            />
          </Card>

          <FindingDrawer
            path={path}
            finding={selected}
            onClose={() => setSelected(null)}
          />
        </>
      )}
    </QueryBoundary>
  );
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

function FindingDrawer({
  path,
  finding,
  onClose,
}: {
  path: string;
  finding: Finding | null;
  onClose: () => void;
}) {
  // Source comes from this run's extraction.json — exactly what was sent to the
  // model, even if the project has changed since.
  const { data: extraction } = useExtraction(path, finding !== null);
  const source = useMemo(() => {
    if (!finding || !extraction?.results) return null;
    const normalised = finding.file_path?.replace(/\\/g, "/") ?? "";
    return (
      extraction.results.find(
        (entry) =>
          entry.function_name === finding.function_name &&
          entry.file_path.replace(/\\/g, "/").endsWith(normalised),
      ) ??
      extraction.results.find((entry) => entry.function_name === finding.function_name) ??
      null
    );
  }, [finding, extraction]);

  if (!finding) return null;

  return (
    <Drawer
      open
      onClose={onClose}
      title={finding.function_name}
      subtitle={
        <>
          <SeverityBadge severity={finding.severity} />
          {finding.cwe_id && <Badge variant="neutral">{finding.cwe_id}</Badge>}
          <span className="mono">{finding.file_path}</span>
        </>
      }
    >
      {finding.error && (
        <div className="note note--error">
          <span className="note__label">Analysis error</span>
          {finding.error}
        </div>
      )}

      {finding.explanation && (
        <section>
          <h4 className="results__h4">Explanation</h4>
          <p className="prose">{finding.explanation}</p>
        </section>
      )}

      {source && (
        <section>
          <h4 className="results__h4">
            Source
            <span className="faint">
              {" "}
              lines {source.start_line}–{source.end_line}
              {finding.affected_lines?.length
                ? ` · flagged ${finding.affected_lines.join(", ")}`
                : ""}
            </span>
          </h4>
          <CodeBlock
            code={source.code}
            startLine={source.start_line}
            highlight={finding.affected_lines ?? []}
          />
        </section>
      )}

      {finding.patch_suggestion && (
        <section>
          <h4 className="results__h4">Suggested fix</h4>
          <p className="prose">{finding.patch_suggestion}</p>
        </section>
      )}

      {finding.unified_diff && (
        <section>
          <h4 className="results__h4">
            Generated patch{" "}
            {finding.patch_valid === true ? (
              <Badge variant="ok">valid</Badge>
            ) : finding.patch_valid === false ? (
              <Badge variant="err">invalid</Badge>
            ) : null}
          </h4>
          {finding.patch_error && <p className="faint">{finding.patch_error}</p>}
          <DiffView diff={finding.unified_diff} />
        </section>
      )}

      <section>
        <h4 className="results__h4">Details</h4>
        <dl className="kv">
          <dt>Confidence</dt>
          <dd>{finding.confidence !== null ? finding.confidence.toFixed(2) : "n/a"}</dd>
          <dt>Mode</dt>
          <dd>{finding.analysis_mode ?? "n/a"}</dd>
          <dt>Language</dt>
          <dd>{finding.language ?? "n/a"}</dd>
          <dt>Hallucination flag</dt>
          <dd>{String(finding.hallucination_flag)}</dd>
          <dt>Duplicate group</dt>
          <dd>{finding.duplicate_group ?? "none"}</dd>
          <dt>Prompt tokens</dt>
          <dd>{formatNumber(finding.prompt_tokens ?? null)}</dd>
          <dt>Completion tokens</dt>
          <dd>{formatNumber(finding.completion_tokens ?? null)}</dd>
          <dt>Cost</dt>
          <dd>{formatCost(finding.cost_usd)}</dd>
        </dl>
      </section>
    </Drawer>
  );
}

/**
 * A run's findings mean nothing on their own — "14 vulnerabilities" is a count,
 * not a result, until it is scored against a ground truth. So the summary says
 * whether that has happened, and links to the score if it has.
 */
function EvaluationLink({ result }: { result: ResultSummary }) {
  const { data } = useEvaluationsForRun(result.run_id);
  if (!result.run_id || !data) return null;

  if (data.length === 0) {
    return (
      <div className="note">
        <span className="note__label">Not scored</span>
        These counts have not been checked against a ground truth dataset, so
        they say what the tool reported, not what it got right.{" "}
        <Link to={`/evaluations?path=${encodeURIComponent(result.output_dir)}`}>
          Score this run →
        </Link>
      </div>
    );
  }

  return (
    <div className="results__evalrow">
      {data.map((report) => (
        <Link
          key={report.path}
          to={`/evaluations?path=${encodeURIComponent(result.output_dir)}&report=${encodeURIComponent(report.path)}`}
          className="results__evallink"
        >
          <StatTile
            label={`Scored against ${report.dataset}`}
            value={`F1 ${formatRatio(report.detection_metrics.f1)}`}
            tone="accent"
            hint={
              report.curation.needs_curation
                ? "uncurated ground truth — not valid"
                : `precision ${formatRatio(report.detection_metrics.precision)} · recall ${formatRatio(report.detection_metrics.recall)}`
            }
          />
        </Link>
      ))}
    </div>
  );
}

// ── call graph ───────────────────────────────────────────────────────────────

function GraphTab({ path, result }: { path: string; result: ResultSummary }) {
  const { data } = useGraph(path, result.has_graph);
  const [search, setSearch] = useState("");
  const [facets, setFacets] = useState<string[]>([]);

  // Versioned by the file's mtime: re-running into the same directory rewrites
  // the graph, and a URL the browser has already cached would keep showing the
  // old one no matter what the response headers say.
  const graphUrl = apiUrl("/results/graph.html", {
    path,
    v: result.graph_html_version ?? undefined,
  });

  const nodes = useMemo(() => Object.values(data?.graph ?? {}), [data]);
  const rows = useMemo(() => {
    const needle = search.toLowerCase();
    return nodes.filter((node) => {
      if (facets.includes("entry") && !node.is_entry_point) return false;
      if (facets.includes("taint source") && !node.is_taint_source) return false;
      if (facets.includes("taint sink") && !node.is_taint_sink) return false;
      if (facets.includes("infrastructure") && !node.is_infrastructure) return false;
      if (facets.includes("external") && !node.is_external) return false;
      if (!needle) return true;
      return (
        node.function_name.toLowerCase().includes(needle) ||
        (node.file_path ?? "").toLowerCase().includes(needle)
      );
    });
  }, [nodes, search, facets]);

  const columns: Column<GraphNode>[] = [
    {
      id: "function",
      header: "Function",
      sortValue: (n) => n.function_name,
      cell: (n) => <span className="mono">{n.function_name}</span>,
    },
    {
      id: "file",
      header: "File",
      sortValue: (n) => n.file_path,
      cell: (n) => (
        <span className="mono dim results__file" title={n.file_path}>
          {n.file_path || "—"}
        </span>
      ),
    },
    {
      id: "callers",
      header: "Callers",
      align: "right",
      sortValue: (n) => n.callers?.length ?? 0,
      cell: (n) => <span className="num">{n.callers?.length ?? 0}</span>,
    },
    {
      id: "callees",
      header: "Callees",
      align: "right",
      sortValue: (n) => n.callees?.length ?? 0,
      cell: (n) => <span className="num">{n.callees?.length ?? 0}</span>,
    },
    {
      id: "roles",
      header: "Role",
      cell: (n) => (
        <div className="row wrap">
          {n.is_entry_point && <Badge variant="accent">entry</Badge>}
          {n.is_taint_source && <Badge variant="low">source</Badge>}
          {n.is_taint_sink && <Badge variant="critical">sink</Badge>}
          {n.is_infrastructure && <Badge variant="medium" subtle>infra</Badge>}
          {n.is_external && <Badge variant="neutral" subtle>external</Badge>}
        </div>
      ),
    },
  ];

  return (
    <div className="stack">
      {result.has_graph_html ? (
        <Card
          title="Interactive call graph"
          description="Drag nodes, scroll to zoom, click to highlight connections. Colours mark taint roles and finding severity."
          flush
          actions={
            <a href={graphUrl} target="_blank" rel="noreferrer">
              Open full screen ↗
            </a>
          }
        >
          {/* The CLI already emits a self-contained interactive graph; embedding
              it beats re-implementing one in React. */}
          <iframe
            className="results__graph"
            src={graphUrl}
            title="Call graph"
          />
        </Card>
      ) : (
        <div className="note">
          <span className="note__label">No graph view</span>
          This run was made without the call graph view enabled. The graph data
          is still below — re-run with “Build the call graph view” ticked to get
          the interactive version.
        </div>
      )}

      <Card flush title="Nodes" description="What the graph is bad at: finding every taint sink.">
        <FilterBar
          search={search}
          onSearch={setSearch}
          placeholder="Search node or file…"
          count={`${rows.length} of ${nodes.length}`}
          onReset={search || facets.length ? () => { setSearch(""); setFacets([]); } : undefined}
        >
          <FilterChips
            options={["entry", "taint source", "taint sink", "infrastructure", "external"]}
            selected={facets}
            onChange={setFacets}
          />
        </FilterBar>
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(n) => `${n.file_path}::${n.function_name}`}
          dense
          initialSort={{ columnId: "callees", direction: "desc" }}
        />
      </Card>
    </div>
  );
}

// ── extraction ───────────────────────────────────────────────────────────────

function ExtractionTab({ path }: { path: string }) {
  const { data, isLoading, error } = useExtraction(path);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ExtractedFunction | null>(null);

  const functions = data?.results ?? [];
  const skipped = data?.skipped_oversized ?? [];
  const rows = useMemo(() => {
    const needle = search.toLowerCase();
    if (!needle) return functions;
    return functions.filter(
      (entry) =>
        entry.function_name.toLowerCase().includes(needle) ||
        entry.file_path.toLowerCase().includes(needle),
    );
  }, [functions, search]);

  const columns: Column<ExtractedFunction>[] = [
    {
      id: "function",
      header: "Function",
      sortValue: (e) => e.function_name,
      cell: (e) => <span className="mono">{e.function_name}</span>,
    },
    {
      id: "file",
      header: "File",
      sortValue: (e) => e.file_path,
      cell: (e) => <span className="mono dim results__file" title={e.file_path}>{e.file_path}</span>,
    },
    {
      id: "language",
      header: "Language",
      sortValue: (e) => e.language,
      cell: (e) => <Badge variant="neutral" subtle>{e.language}</Badge>,
    },
    {
      id: "lines",
      header: "Lines",
      align: "right",
      sortValue: (e) => e.end_line - e.start_line,
      cell: (e) => (
        <span className="num faint">
          {e.start_line}–{e.end_line}
          <span className="dim"> ({e.end_line - e.start_line + 1})</span>
        </span>
      ),
    },
  ];

  const skippedColumns: Column<SkippedFunction>[] = [
    {
      id: "function",
      header: "Function",
      sortValue: (s) => s.function_name,
      cell: (s) => <span className="mono">{s.function_name}</span>,
    },
    {
      id: "file",
      header: "File",
      cell: (s) => <span className="mono dim">{s.file_path}</span>,
    },
    {
      id: "size",
      header: "Lines",
      align: "right",
      sortValue: (s) => s.line_count,
      cell: (s) => <span className="num" style={{ color: "var(--warn)" }}>{s.line_count}</span>,
    },
  ];

  return (
    <QueryBoundary isLoading={isLoading} error={error} data={data} skeletonRows={8}>
      {() => (
        <div className="stack">
          {skipped.length > 0 && (
            <Card
              title="Skipped — too long to analyse"
              description="These were never sent to the model. Any recall number for this run is over the analysed set, not the whole project."
              flush
            >
              <DataTable
                columns={skippedColumns}
                rows={skipped}
                rowKey={(s) => `${s.file_path}::${s.function_name}`}
                dense
                initialSort={{ columnId: "size", direction: "desc" }}
              />
            </Card>
          )}

          <Card flush title="Extracted functions">
            <FilterBar
              search={search}
              onSearch={setSearch}
              placeholder="Search function or file…"
              count={`${rows.length} of ${functions.length}`}
              onReset={search ? () => setSearch("") : undefined}
            />
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(e) => `${e.file_path}::${e.function_name}::${e.start_line}`}
              dense
              onRowClick={setSelected}
              initialSort={{ columnId: "file", direction: "asc" }}
            />
          </Card>

          {selected && (
            <Drawer
              open
              onClose={() => setSelected(null)}
              title={selected.function_name}
              subtitle={
                <>
                  <Badge variant="neutral" subtle>{selected.language}</Badge>
                  <span className="mono">{selected.file_path}</span>
                </>
              }
            >
              <CodeBlock code={selected.code} startLine={selected.start_line} maxHeight={640} />
            </Drawer>
          )}
        </div>
      )}
    </QueryBoundary>
  );
}

// ── patches ──────────────────────────────────────────────────────────────────

/** Same key the backend journals under, so a row and its applied state line up. */
function patchKey(file: string, fn: string) {
  return `${file.replace(/\\/g, "/")}::${fn}`;
}

function PatchesTab({ path, result }: { path: string; result: ResultSummary }) {
  const { data, isLoading, error } = usePatches(path);
  const { data: applied } = useAppliedPatches(path);
  const startPatch = useStartPatch();
  const { data: activeJob } = useActiveJob();
  const [selected, setSelected] = useState<PatchRecord | null>(null);

  const running = activeJob?.kind === "patch" && activeJob.state === "running";
  const patches = data?.patches ?? [];
  const flagged = result.totals.vulnerabilities_found ?? 0;

  const appliedByKey = useMemo(() => {
    const map = new Map<string, AppliedPatch>();
    for (const entry of applied?.entries ?? []) {
      map.set(patchKey(entry.file_path, entry.function_name), entry);
    }
    return map;
  }, [applied]);

  const stateOf = (p: PatchRecord) => appliedByKey.get(patchKey(p.file_path, p.function_name));

  const columns: Column<PatchRecord>[] = [
    {
      id: "function",
      header: "Function",
      sortValue: (p) => p.function_name,
      cell: (p) => <span className="mono">{p.function_name}</span>,
    },
    {
      id: "file",
      header: "File",
      cell: (p) => <span className="mono dim results__file" title={p.file_path}>{p.file_path}</span>,
    },
    {
      id: "cwe",
      header: "CWE",
      sortValue: (p) => p.cwe_id ?? null,
      cell: (p) => (p.cwe_id ? <Badge variant="neutral">{p.cwe_id}</Badge> : <span className="faint">—</span>),
    },
    {
      id: "valid",
      header: "Validity",
      sortValue: (p) => (p.patch_valid ? 1 : 0),
      cell: (p) =>
        p.patch_valid === true ? (
          <Badge variant="ok">valid</Badge>
        ) : p.patch_valid === false ? (
          <Badge variant="err" title={p.patch_error ?? undefined}>invalid</Badge>
        ) : (
          <span className="faint">—</span>
        ),
    },
    {
      id: "applied",
      header: "Source file",
      sortValue: (p) => (stateOf(p)?.state === "applied" ? 1 : 0),
      cell: (p) => {
        const entry = stateOf(p);
        if (entry?.state === "applied") return <Badge variant="ok">applied</Badge>;
        if (entry?.state === "reverted") return <Badge variant="neutral">reverted</Badge>;
        return <span className="faint">unchanged</span>;
      },
    },
    {
      id: "cost",
      header: "Cost",
      align: "right",
      secondary: true,
      sortValue: (p) => p.cost_usd ?? null,
      cell: (p) => <span className="num">{formatCost(p.cost_usd)}</span>,
    },
  ];

  return (
    <div className="stack">
      <Card
        title="Patch generation"
        description="Asks the model for a unified diff per flagged function, then checks each one parses. Generating changes nothing on disk — open a diff and choose Apply to write that one fix into your source file."
        actions={
          <Button
            variant="primary"
            disabled={running || flagged === 0 || !result.has_analysis}
            onClick={() => startPatch.mutate({ output_dir: path })}
          >
            {running
              ? "Generating…"
              : data
                ? "Regenerate patches"
                : `Generate patches (${flagged})`}
          </Button>
        }
      >
        {flagged === 0 ? (
          <p className="faint">Nothing was flagged in this run, so there is nothing to patch.</p>
        ) : startPatch.error ? (
          <div className="note note--error">
            <span className="note__label">Could not start</span>
            {(startPatch.error as Error).message}
          </div>
        ) : running ? (
          <p className="dim">
            Running — {activeJob?.current ?? 0} of {activeJob?.total ?? flagged}.
            Watch the full log on the Analyze page.
          </p>
        ) : data?.summary ? (
          <div className="grid-stats">
            <StatTile label="Patches" value={formatNumber(data.summary.total_patches)} />
            <StatTile label="Valid" value={formatNumber(data.summary.valid)} tone="ok" />
            <StatTile
              label="Invalid"
              value={formatNumber(data.summary.invalid)}
              tone={data.summary.invalid ? "err" : "muted"}
            />
            <StatTile
              label="Applied to source"
              value={formatNumber(applied?.applied_count ?? 0)}
              tone={applied?.applied_count ? "ok" : "muted"}
            />
            <StatTile
              label="Cost"
              value={formatCost(data.summary.total_cost_usd)}
              tone="accent"
            />
          </div>
        ) : (
          <p className="dim">
            No patches generated yet. This makes one API call per flagged
            function.
          </p>
        )}
      </Card>

      <QueryBoundary isLoading={isLoading} error={error} data={data ?? null} skeletonRows={4}>
        {() =>
          patches.length > 0 ? (
            <>
              <Card flush title="Generated diffs">
                <DataTable
                  columns={columns}
                  rows={patches}
                  rowKey={(p) => `${p.file_path}::${p.function_name}`}
                  onRowClick={setSelected}
                  initialSort={{ columnId: "valid", direction: "asc" }}
                />
              </Card>
              {selected && (
                <Drawer
                  open
                  onClose={() => setSelected(null)}
                  title={selected.function_name}
                  subtitle={
                    <>
                      {selected.cwe_id && <Badge variant="neutral">{selected.cwe_id}</Badge>}
                      <span className="mono">{selected.file_path}</span>
                    </>
                  }
                >
                  {selected.patch_error && (
                    <div className="note note--error">
                      <span className="note__label">Validation failed</span>
                      {selected.patch_error}
                    </div>
                  )}
                  <ApplyControl
                    key={patchKey(selected.file_path, selected.function_name)}
                    path={path}
                    patch={selected}
                    applied={stateOf(selected) ?? null}
                  />
                  {selected.unified_diff ? (
                    <DiffView diff={selected.unified_diff} maxHeight={640} />
                  ) : (
                    <p className="faint">No diff was produced for this function.</p>
                  )}
                </Drawer>
              )}
            </>
          ) : (
            <EmptyState title="No patch artifact yet" detail="Generate patches to see diffs here." />
          )
        }
      </QueryBoundary>
    </div>
  );
}

/**
 * Apply one diff to the analysed project, or take it back out.
 *
 * Two-step on the way in: this is the only control in the app that edits a file
 * the user did not ask it to write, and the confirm step names the file it is
 * about to overwrite. Applying is per-finding by design — there is no bulk
 * button here, and the confirm state resets whenever a different patch is
 * opened (the caller keys this component by patch).
 */
function ApplyControl({
  path,
  patch,
  applied,
}: {
  path: string;
  patch: PatchRecord;
  applied: AppliedPatch | null;
}) {
  const [confirming, setConfirming] = useState(false);
  const apply = useApplyPatch();
  const revert = useRevertPatch();
  const target = { path, file_path: patch.file_path, function_name: patch.function_name };
  const busy = apply.isPending || revert.isPending;
  const failure = (apply.error ?? revert.error) as Error | null;

  if (patch.patch_valid !== true) {
    return (
      <div className="note">
        <span className="note__label">Not applicable</span>
        Only a patch that passed the syntax check can be written to your source
        file. Fix this one by hand using the diff below.
      </div>
    );
  }

  const isApplied = applied?.state === "applied";

  return (
    <div className="stack-sm">
      {failure && (
        <div className="note note--error">
          <span className="note__label">
            {apply.error ? "Not applied" : "Not reverted"}
          </span>
          {failure.message}
        </div>
      )}

      {isApplied ? (
        <div className="note note--ok">
          <span className="note__label">Applied</span>
          Written into <span className="mono">{applied?.file_path}</span>
          {applied?.line ? ` at line ${applied.line}` : ""}
          {applied?.applied_at ? ` on ${formatDate(applied.applied_at)}` : ""}.
          <div className="row-actions">
            <Button variant="default" disabled={busy} onClick={() => revert.mutate(target)}>
              {revert.isPending ? "Reverting…" : "Revert this change"}
            </Button>
          </div>
        </div>
      ) : confirming ? (
        <div className="note">
          <span className="note__label">Overwrite this function?</span>
          <span className="mono">{patch.file_path}</span> will be modified in
          place. {applied?.state === "reverted" && "You reverted this patch before. "}
          Nothing else in the file changes, and you can revert it from here
          afterwards.
          <div className="row-actions">
            <Button
              variant="danger"
              disabled={busy}
              onClick={() => apply.mutate(target, { onSuccess: () => setConfirming(false) })}
            >
              {apply.isPending ? "Writing…" : "Yes, write it"}
            </Button>
            <Button variant="ghost" disabled={busy} onClick={() => setConfirming(false)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <div className="row-actions">
          <Button variant="primary" onClick={() => setConfirming(true)}>
            Apply to source file
          </Button>
          <span className="faint">
            Rewrites just this function in{" "}
            <span className="mono">{patch.file_path}</span>.
          </span>
        </div>
      )}
    </div>
  );
}

// ── raw ──────────────────────────────────────────────────────────────────────

function RawTab({ path, result }: { path: string; result: ResultSummary }) {
  const [open, setOpen] = useState<string | null>(null);
  // Fetches only once a file is opened — the hook is disabled while `open` is null.
  const { data, isLoading } = useArtifact(path, open);

  const columns: Column<ResultSummary["artifacts"][number]>[] = [
    {
      id: "name",
      header: "File",
      sortValue: (a) => a.name,
      cell: (a) => <span className="mono">{a.name}</span>,
    },
    {
      id: "size",
      header: "Size",
      align: "right",
      sortValue: (a) => a.size_bytes,
      cell: (a) => <span className="num">{formatBytes(a.size_bytes)}</span>,
    },
    {
      id: "modified",
      header: "Modified",
      align: "right",
      secondary: true,
      sortValue: (a) => a.modified_at,
      cell: (a) => <span className="faint nowrap">{formatDate(a.modified_at)}</span>,
    },
    {
      id: "open",
      header: "",
      align: "right",
      cell: (a) =>
        a.readable ? (
          <Button variant="ghost" onClick={() => setOpen(a.name)}>
            View
          </Button>
        ) : (
          <span className="faint">not JSON</span>
        ),
    },
  ];

  return (
    <div className="stack">
      <Card flush title="Files in this result" description={result.output_dir}>
        <DataTable
          columns={columns}
          rows={result.artifacts}
          rowKey={(a) => a.name}
          dense
          initialSort={{ columnId: "name", direction: "asc" }}
        />
      </Card>

      {open && (
        <Drawer open onClose={() => setOpen(null)} title={open} width={880}>
          {isLoading ? (
            <Skeleton rows={8} />
          ) : (
            <JsonViewer value={data} maxHeight={720} />
          )}
        </Drawer>
      )}
    </div>
  );
}

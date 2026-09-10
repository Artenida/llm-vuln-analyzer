import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  useActiveJob,
  useCancelJob,
  useConfigs,
  useEstimate,
  useInspect,
  useJob,
  useOpenResults,
  useSettings,
  useStartAnalyze,
} from "@/api/hooks";
import type { AnalysisConfig, CostEstimate, InspectResult } from "@/api/types";
import {
  Badge,
  Button,
  Card,
  DirectoryPicker,
  Field,
  LogStream,
  NumberInput,
  Select,
  StatTile,
  TextInput,
  Toggle,
} from "@/components";
import { useJobStream } from "@/lib/useJobStream";
import { useAnalyzeForm } from "@/state/AnalyzeForm";
import type { AnalyzeMode } from "@/state/AnalyzeForm";
import { formatCost, formatNumber } from "@/lib/format";
import "./AnalyzePage.css";

type Mode = AnalyzeMode;

export function AnalyzePage() {
  const navigate = useNavigate();
  const { data: settingsData } = useSettings();
  const settings = settingsData?.settings;

  // Held above the router so navigating away and back does not clear the form.
  const { form, update, reset } = useAnalyzeForm();
  const {
    sourcePath, outputDir, configPath, chunkOversized, mode, visualize, dryRun, resume, budget,
    inspection, estimate, jobId,
  } = form;

  // Genuinely transient — a half-open dialog should not survive navigation.
  const [picking, setPicking] = useState<"source" | "output" | "results" | null>(null);
  const [confirming, setConfirming] = useState(false);
  // Also transient: once a folder is opened its path lives on as
  // `lastResultDir`, so there is nothing here worth persisting.
  const [openPath, setOpenPath] = useState("");

  const { data: availableConfigs } = useConfigs();
  const inspect = useInspect();
  const openResults = useOpenResults();
  const estimateMutation = useEstimate();
  const startAnalyze = useStartAnalyze();
  const cancelJob = useCancelJob();
  const { data: activeJob } = useActiveJob();
  const { data: fetchedJob, error: jobError } = useJob(jobId);
  const stream = useJobStream(jobId);

  // Jobs live in the server's memory. If it restarted since, the remembered id
  // is gone — drop it rather than leaving a dead progress panel on the page.
  useEffect(() => {
    if (jobError) update({ jobId: null });
  }, [jobError, update]);

  // Settings supply the defaults exactly once. Re-applying them on every mount
  // would overwrite your own choices each time you came back to this page.
  useEffect(() => {
    if (!settings || form.seededFromSettings) return;
    update({
      mode: settings.react ? "react" : "semantic",
      visualize: settings.visualize,
      budget: settings.budget_usd,
      seededFromSettings: true,
    });
  }, [settings, form.seededFromSettings, update]);

  // A run started before this page was opened (or still going after a refresh)
  // is adopted rather than hidden — otherwise the UI would happily offer to
  // start a second one and be refused by the single-flight guard.
  useEffect(() => {
    if (!jobId && activeJob && activeJob.kind === "analyze") update({ jobId: activeJob.id });
  }, [activeJob, jobId, update]);

  // Three sources, most-live first: the SSE stream, then a direct fetch of the
  // remembered job, then the active-job poll. The fetch is what stops a
  // finished run from flashing as "Running…" when you navigate back here.
  const job =
    stream.job ?? fetchedJob ?? (activeJob?.id === jobId ? activeJob : null);
  const running = job?.state === "running";
  const finished = job !== null && job.state !== "running";

  // Remember where this run is writing, so Results and Evaluations open on it
  // with no `?path` — including after a refresh, and including a run adopted
  // from the active-job poll rather than started here. This is the whole of
  // what replaced the run history: one pointer, not a list.
  useEffect(() => {
    if (job?.output_dir && job.output_dir !== form.lastResultDir) {
      update({ lastResultDir: job.output_dir });
    }
  }, [job?.output_dir, form.lastResultDir, update]);

  const keyConfigured = settingsData?.api_keys.some(
    (k) => k.alias === (settings?.api_key_alias ?? "default") && k.configured,
  );

  // Nothing selected means the default config — the same one a run with no
  // `--config` gets — so there is always a named scope rather than an implicit
  // one nobody chose.
  const selectedConfig =
    availableConfigs?.find((c) => c.path === configPath) ??
    availableConfigs?.find((c) => c.is_default) ??
    null;

  // A scan taken under one scope must never be shown next to a run about to
  // execute under another: the count on screen is what the cost estimate and
  // the confirm dialog are built from. When they disagree the scan is stale,
  // and the page says so instead of quietly pricing the wrong tree.
  // The toggle's value: an explicit override if one was made, otherwise the
  // selected config's own setting. Switching scope therefore moves the toggle,
  // unless you have already overruled it for this run.
  const effectiveChunking =
    chunkOversized ?? selectedConfig?.chunk_oversized ?? true;

  const scopeStale =
    inspection !== null &&
    selectedConfig !== null &&
    inspection.config_path !== null &&
    (inspection.config_path !== selectedConfig.path ||
      inspection.chunk_oversized !== effectiveChunking);

  async function onInspect(path: string, config: string | null = configPath) {
    update({ estimate: null });
    const result = await inspect.mutateAsync({
      path,
      config_path: config,
      chunk_oversized: effectiveChunking,
    });
    update({ inspection: result });
    if (result.functions) {
      update({
        estimate: await estimateMutation.mutateAsync({
          functions: result.functions,
          react: mode === "react",
        }),
      });
    }
  }

  // Changing the scope re-counts rather than leaving the old number on screen.
  // A scan is a local tree-sitter parse: it costs nothing, and the alternative
  // is a stale figure sitting under a "Projected cost" heading.
  useEffect(() => {
    if (!scopeStale || inspect.isPending || running || !sourcePath.trim()) return;
    void onInspect(sourcePath, configPath);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeStale, configPath, effectiveChunking]);

  // Re-price when the mode changes: agentic costs several calls per function,
  // so a semantic estimate shown next to an agentic run would be badly wrong.
  useEffect(() => {
    if (!inspection?.functions) return;
    void estimateMutation
      .mutateAsync({ functions: inspection.functions, react: mode === "react" })
      .then((next) => update({ estimate: next }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, inspection?.functions]);

  async function launch() {
    setConfirming(false);
    const created = await startAnalyze.mutateAsync({
      source_path: sourcePath,
      output_dir: outputDir || undefined,
      react: mode === "react",
      visualize,
      dry_run: dryRun,
      resume,
      config_path: selectedConfig?.path ?? null,
      chunk_oversized: effectiveChunking,
      budget_usd: dryRun ? null : budget,
    });
    // The server may have auto-named the folder — show where results are going.
    update({ jobId: created.id, outputDir: created.output_dir ?? outputDir });
  }

  // Open a run this session did not produce: an earlier session, another
  // machine, or a plain `python -m src.cli analyze`. The server call is what
  // authorises the read — a folder this tool has never written to is not
  // readable until it is registered. The result then goes through the same
  // `lastResultDir` pointer the live flow uses, so Results and Evaluations both
  // follow it. Still one pointer and not a run history: docs/frontend-plan.md §10.
  async function openPrevious(path: string) {
    try {
      const opened = await openResults.mutateAsync(path);
      update({ lastResultDir: opened.output_dir });
      navigate(`/results?path=${encodeURIComponent(opened.output_dir)}`);
    } catch {
      // Surfaced from openResults.error below — rethrowing would only produce
      // an unhandled rejection in the console.
    }
  }

  const canStart =
    sourcePath.trim().length > 0 &&
    !running &&
    !scopeStale &&
    !inspect.isPending &&
    (dryRun || keyConfigured) &&
    (inspection === null || inspection.exists);

  return (
    <div className="stack">
      <div className="page-title">
        <h1>Analyze</h1>
        <span className="page-subtitle">
          Point the analyzer at a folder and run it.
        </span>
      </div>

      {settingsData && !keyConfigured && (
        <div className="note">
          <span className="note__label">No API key</span>
          Analysis makes OpenAI calls and no key is configured. Add one in{" "}
          <a href="/settings">Settings</a>, or tick <strong>Dry run</strong> below
          to build the call graph without spending anything.
        </div>
      )}

      <div className="analyze__grid">
        <div className="stack">
          <Card title="Target">
            <div className="stack">
              <Field
                label="Folder to analyse"
                hint="A project directory, or a single source file."
              >
                <div className="analyze__pathrow">
                  <TextInput
                    value={sourcePath}
                    onChange={(value) => update({ sourcePath: value })}
                    placeholder="C:\path\to\project"
                    disabled={running}
                  />
                  <Button onClick={() => setPicking("source")} disabled={running}>
                    Browse…
                  </Button>
                  <Button
                    onClick={() => void onInspect(sourcePath)}
                    disabled={!sourcePath.trim() || inspect.isPending || running}
                  >
                    {inspect.isPending ? "Scanning…" : "Scan"}
                  </Button>
                </div>
              </Field>

              <Field
                label="Analysis scope"
                hint={
                  selectedConfig
                    ? selectedConfig.description ||
                      `${selectedConfig.filename} — ${selectedConfig.skip_dirs.length} excluded paths.`
                    : "Which files the run opens. Loading…"
                }
              >
                <Select
                  value={selectedConfig?.path ?? ""}
                  onChange={(value) => update({ configPath: value || null })}
                  // Locked while a run is in flight, like every other control
                  // here: the job already has its scope, and a picker that
                  // disagreed with it would be describing the wrong run.
                  disabled={running}
                  options={(availableConfigs ?? []).map((config) => ({
                    value: config.path,
                    label: config.is_default
                      ? `${config.name} (default)`
                      : config.name,
                  }))}
                />
              </Field>

              <Toggle
                checked={effectiveChunking}
                onChange={(value) => update({ chunkOversized: value })}
                label="Analyse oversized functions in chunks"
                hint={
                  effectiveChunking
                    ? `A function over ${selectedConfig?.max_function_lines ?? 200} lines is split and its slices analysed separately, so it adds units to the count.`
                    : `A function over ${selectedConfig?.max_function_lines ?? 200} lines is dropped entirely — matching a ground truth that has no rows for it.`
                }
                disabled={running}
              />

              {inspection && (
                <InspectionPanel
                  inspection={inspection}
                  stale={scopeStale}
                  rescanning={inspect.isPending}
                />
              )}

              <Field
                label="Save results to"
                hint="Leave empty to use a timestamped folder under your results directory."
              >
                <div className="analyze__pathrow">
                  <TextInput
                    value={outputDir}
                    onChange={(value) => update({ outputDir: value })}
                    placeholder={settings?.results_root ?? "(default)"}
                    disabled={running}
                  />
                  <Button onClick={() => setPicking("output")} disabled={running}>
                    Browse…
                  </Button>
                </div>
              </Field>
            </div>
          </Card>

          <Card title="Options">
            <div className="analyze__options">
              <Field label="Analysis mode" hint={MODE_HINT[mode]}>
                <Select
                  value={mode}
                  onChange={(value) => update({ mode: value })}
                  options={[
                    { value: "react", label: "Agentic — ReAct loop" },
                    { value: "semantic", label: "Semantic — call graph context" },
                  ]}
                />
              </Field>

              <Field
                label="Budget (USD)"
                hint="Stops starting new functions once spend reaches this. Checked between functions."
              >
                <NumberInput
                  value={budget}
                  onChange={(value) => update({ budget: value })}
                  min={0}
                  step={0.5}
                  placeholder="no ceiling"
                />
              </Field>

              <div className="analyze__toggles">
                <Toggle
                  checked={visualize}
                  onChange={(value) => update({ visualize: value })}
                  label="Build the call graph view"
                  hint="Interactive HTML graph, with findings overlaid."
                  disabled={running}
                />
                <Toggle
                  checked={dryRun}
                  onChange={(value) => update({ dryRun: value })}
                  label="Dry run"
                  hint="Extract and build the graph only. Makes no API calls and costs nothing."
                  disabled={running}
                />
                <Toggle
                  checked={resume}
                  onChange={(value) => update({ resume: value })}
                  label="Resume"
                  hint="Continue an interrupted run in the output folder above."
                  disabled={running}
                />
              </div>
            </div>
          </Card>

          {startAnalyze.error && (
            <div className="note note--error">
              <span className="note__label">Could not start</span>
              {(startAnalyze.error as Error).message}
            </div>
          )}

          <div className="analyze__actions">
            <Button
              variant="primary"
              disabled={!canStart}
              onClick={() => (dryRun ? void launch() : setConfirming(true))}
            >
              {running ? "Running…" : dryRun ? "Run dry scan" : "Analyze"}
            </Button>
            {running && job && (
              <Button variant="danger" onClick={() => cancelJob.mutate(job.id)}>
                Cancel
              </Button>
            )}
            {finished && job?.output_dir && (
              <Button
                variant="primary"
                onClick={() =>
                  navigate(`/results?path=${encodeURIComponent(job.output_dir!)}`)
                }
              >
                Open results →
              </Button>
            )}
            {/* The form is remembered across navigation and restarts, so there
                has to be a way to deliberately empty it. */}
            {!running && (sourcePath || outputDir || inspection) && (
              <Button variant="ghost" onClick={reset} title="Empty this form">
                Clear
              </Button>
            )}
          </div>

          <Card
            title="Open previous results"
            description="Read a run that already finished — from an earlier session, another machine, or one started on the command line."
          >
            <div className="stack-sm">
              <div className="analyze__pathrow">
                <TextInput
                  value={openPath}
                  onChange={setOpenPath}
                  placeholder="C:\path\to\a\run\folder"
                />
                <Button onClick={() => setPicking("results")}>Browse…</Button>
                {/* Deliberately not `primary`: Analyze is the page's one primary
                    action, and this sits directly under it. */}
                <Button
                  onClick={() => void openPrevious(openPath)}
                  disabled={!openPath.trim() || openResults.isPending}
                >
                  {openResults.isPending ? "Opening…" : "Open"}
                </Button>
              </div>

              {openResults.error && (
                <div className="note note--error">
                  <span className="note__label">Could not open</span>
                  {(openResults.error as Error).message}
                </div>
              )}

              {form.lastResultDir && (
                <div className="row-between">
                  <span className="mono faint" style={{ fontSize: "var(--fs-xs)" }}>
                    Currently reading {form.lastResultDir}
                  </span>
                  <Button
                    variant="ghost"
                    onClick={() =>
                      navigate(
                        `/results?path=${encodeURIComponent(form.lastResultDir!)}`,
                      )
                    }
                  >
                    Open →
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </div>

        <div className="stack">
          <Card
            title="Cost estimate"
            description="Projected from measured spend on previous runs."
          >
            <EstimatePanel estimate={estimate} dryRun={dryRun} />
          </Card>

          {(running || finished) && job && (
            <Card
              title="Progress"
              actions={<StateBadge state={job.state} />}
              description={job.command}
            >
              {/* The job record is the fallback for every counter: the SSE
                  replay after a reconnect carries log lines only. */}
              <ProgressPanel
                current={Math.max(stream.current, job.current)}
                total={Math.max(stream.total, job.total)}
                currentFunction={stream.currentFunction}
                findings={Math.max(stream.findings, job.findings)}
                state={job.state}
                error={job.error}
                outputDir={job.output_dir}
                onOpenResults={() =>
                  job.output_dir &&
                  navigate(`/results?path=${encodeURIComponent(job.output_dir)}`)
                }
              />
            </Card>
          )}
        </div>
      </div>

      {(running || finished) && (
        <Card title="Output" description="Exactly what the analyzer prints on the terminal.">
          <LogStream lines={stream.lines} height={360} />
        </Card>
      )}

      {picking && (
        <DirectoryPicker
          title={PICKER_TITLE[picking]}
          initialPath={
            picking === "source"
              ? sourcePath || null
              : picking === "results"
                ? openPath || form.lastResultDir || settings?.results_root
                : outputDir || settings?.results_root
          }
          allowCreate={picking === "output"}
          // Opening results is the one case where the wrong folder is certain to
          // be refused by the server, so the dialog says so instead.
          requireResultDir={picking === "results"}
          confirmLabel={picking === "results" ? "Open these results" : undefined}
          onCancel={() => setPicking(null)}
          onPick={(path) => {
            if (picking === "source") {
              update({ sourcePath: path });
              void onInspect(path);
            } else if (picking === "results") {
              setOpenPath(path);
              void openPrevious(path);
            } else {
              update({ outputDir: path });
            }
            setPicking(null);
          }}
        />
      )}

      {confirming && (
        <ConfirmDialog
          sourcePath={sourcePath}
          outputDir={outputDir || `${settings?.results_root ?? ""} (auto-named)`}
          mode={mode}
          budget={budget}
          estimate={estimate}
          functions={inspection?.functions ?? null}
          config={selectedConfig}
          excludedFiles={inspection?.source_files_excluded ?? 0}
          chunking={effectiveChunking}
          wholeFunctions={inspection?.whole_functions ?? null}
          onCancel={() => setConfirming(false)}
          onConfirm={() => void launch()}
        />
      )}
    </div>
  );
}

const PICKER_TITLE: Record<"source" | "output" | "results", string> = {
  source: "Select a folder to analyse",
  output: "Select an output folder",
  results: "Select a results folder",
};

const MODE_HINT: Record<Mode, string> = {
  react:
    "The agent queries the call graph before each verdict. Most accurate, and several API calls per function.",
  semantic:
    "One pass per function with callers, callees and taint flags injected into the prompt. Cheaper.",
};

function InspectionPanel({
  inspection,
  stale,
  rescanning,
}: {
  inspection: InspectResult;
  stale: boolean;
  rescanning: boolean;
}) {
  if (!inspection.exists) {
    return (
      <div className="note note--error">
        <span className="note__label">Not found</span>
        {inspection.note ?? "That path does not exist."}
      </div>
    );
  }

  const excluded = Object.entries(inspection.excluded);
  const splitByChunking =
    inspection.whole_functions !== null &&
    inspection.functions !== null &&
    inspection.whole_functions !== inspection.functions;

  return (
    <div className={stale ? "analyze__inspect analyze__inspect--stale" : "analyze__inspect"}>
      {/* The counts are only meaningful attached to a scope, so the scope is
          named on the panel rather than left to be inferred from the picker
          above it — a screenshot of this panel has to be self-describing. */}
      {inspection.config_name && (
        <div className="row-between" style={{ marginBottom: "var(--s3)" }}>
          <span className="faint" style={{ fontSize: "var(--fs-xs)" }}>
            Counted under{" "}
            <span className="mono">{inspection.config_name}</span>
          </span>
          {stale && (
            <Badge variant="warn" subtle>
              {rescanning ? "re-counting…" : "scope changed"}
            </Badge>
          )}
        </div>
      )}

      <div className="grid-stats">
        <StatTile label="Source files" value={formatNumber(inspection.source_files)} hint="in scope" />
        <StatTile
          label="Functions"
          value={inspection.functions !== null ? formatNumber(inspection.functions) : "—"}
          tone="accent"
          hint={
            // When chunking is on the two counts diverge, and only one of them
            // is the number a ground truth has rows for. Showing the split is
            // the difference between "382" and "382, of which 379 are whole".
            inspection.scanned && splitByChunking
              ? `${formatNumber(inspection.whole_functions!)} whole + ${formatNumber(
                  inspection.functions! - inspection.whole_functions!,
                )} chunks`
              : inspection.scanned
                ? "will be analysed"
                : "not counted"
          }
        />
        <StatTile
          label="Skipped"
          value={
            inspection.functions_skipped !== null
              ? formatNumber(inspection.functions_skipped)
              : "—"
          }
          tone={inspection.functions_skipped ? "warn" : "muted"}
          hint="over the line limit"
        />
      </div>
      <div className="row wrap" style={{ marginTop: "var(--s3)" }}>
        {Object.entries(inspection.languages).map(([language, count]) => (
          <Badge key={language} variant="neutral" subtle>
            {language} <span className="faint">{count}</span>
          </Badge>
        ))}
      </div>

      {/* What the scope cost. Without this the excluded tree is invisible, and
          an exclusion nobody can see is one nobody can check. */}
      {excluded.length > 0 && (
        <div className="analyze__excluded">
          <span className="faint">
            {formatNumber(inspection.source_files_excluded)} source file
            {inspection.source_files_excluded === 1 ? "" : "s"} excluded
          </span>
          <div className="row wrap">
            {excluded.map(([entry, count]) => (
              <Badge key={entry} variant="neutral" subtle>
                <span className="mono">{entry}</span>{" "}
                <span className="faint">{formatNumber(count)}</span>
              </Badge>
            ))}
          </div>
        </div>
      )}

      {inspection.note && <p className="analyze__note">{inspection.note}</p>}
    </div>
  );
}

function EstimatePanel({
  estimate,
  dryRun,
}: {
  estimate: CostEstimate | null;
  dryRun: boolean;
}) {
  if (dryRun) {
    return (
      <p className="dim">
        A dry run makes no API calls. Edge resolution runs cache-only, so it
        costs <strong>nothing</strong>.
      </p>
    );
  }
  if (!estimate) {
    return <p className="faint">Scan a folder to see a projected cost.</p>;
  }
  if (!estimate.known) {
    // Never invent a rate on the screen that asks you to authorise spending.
    return (
      <p className="dim">
        No estimate available — {estimate.reason}
      </p>
    );
  }
  return (
    <div className="stack-sm">
      <StatTile
        label="Projected cost"
        value={formatCost(estimate.estimate_usd)}
        tone="accent"
        hint={`${formatNumber(estimate.functions)} functions × ${formatCost(estimate.per_function_usd)}`}
      />
      <p className="faint" style={{ fontSize: "var(--fs-xs)" }}>
        Based on {formatNumber(estimate.based_on_functions)} functions previously
        analysed in this mode. {estimate.note}
      </p>
    </div>
  );
}

function ProgressPanel({
  current,
  total,
  currentFunction,
  findings,
  state,
  error,
  outputDir,
  onOpenResults,
}: {
  current: number;
  total: number;
  currentFunction: string | null;
  findings: number;
  state: string;
  error: string | null;
  outputDir: string | null;
  onOpenResults: () => void;
}) {
  const done = state !== "running";
  // A finished run fills the bar even when no per-function counter was ever
  // parsed — a dry run has no analysis loop, so it legitimately prints none,
  // and leaving the bar empty next to "succeeded" reads as a failure.
  const percent =
    total > 0 ? Math.round((current / total) * 100) : done ? 100 : 0;

  const label =
    total > 0
      ? `${current} / ${total} functions`
      : state === "succeeded"
        ? "complete"
        : done
          ? state
          : "starting…";

  return (
    <div className="stack-sm">
      <div className="analyze__progress">
        <div
          className={
            state === "succeeded"
              ? "analyze__progress-fill analyze__progress-fill--done"
              : "analyze__progress-fill"
          }
          style={{ width: `${percent}%` }}
        />
      </div>
      <div className="row-between">
        <span className="mono">
          {label}
          {!done && currentFunction && (
            <span className="faint"> · {currentFunction}</span>
          )}
        </span>
        <span className="num">
          {findings > 0 ? (
            <span style={{ color: "var(--sev-high)" }}>{findings} flagged</span>
          ) : (
            <span className="faint">0 flagged</span>
          )}
        </span>
      </div>

      {error && (
        <div className="note note--error">
          <span className="note__label">{state}</span>
          {error}
        </div>
      )}

      {state === "succeeded" && outputDir && (
        <Button variant="primary" onClick={onOpenResults}>
          View results →
        </Button>
      )}
    </div>
  );
}

function StateBadge({ state }: { state: string }) {
  const variant =
    state === "running" ? "accent"
    : state === "succeeded" ? "ok"
    : state === "cancelled" ? "warn"
    : "err";
  return <Badge variant={variant}>{state}</Badge>;
}

function ConfirmDialog({
  sourcePath,
  outputDir,
  mode,
  budget,
  estimate,
  functions,
  config,
  excludedFiles,
  chunking,
  wholeFunctions,
  onCancel,
  onConfirm,
}: {
  sourcePath: string;
  outputDir: string;
  mode: Mode;
  budget: number | null;
  estimate: CostEstimate | null;
  functions: number | null;
  config: AnalysisConfig | null;
  excludedFiles: number;
  chunking: boolean;
  wholeFunctions: number | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="confirm" role="dialog" aria-modal="true">
      <div className="confirm__backdrop" onClick={onCancel} />
      <div className="confirm__panel">
        <h3>Start this analysis?</h3>
        <p className="dim">This makes paid OpenAI API calls.</p>

        <dl className="kv">
          <dt>Folder</dt>
          <dd>{sourcePath}</dd>
          <dt>Results to</dt>
          <dd>{outputDir}</dd>
          <dt>Mode</dt>
          <dd>{mode === "react" ? "agentic (ReAct)" : "semantic (call graph)"}</dd>
          {/* The scope is the line that decides what the other lines mean, so
              it is stated here and not only on the form behind the dialog. */}
          <dt>Scope</dt>
          <dd>
            {config ? config.filename : "default"}
            {excludedFiles > 0 && (
              <span className="faint">
                {" "}
                · {formatNumber(excludedFiles)} file
                {excludedFiles === 1 ? "" : "s"} excluded
              </span>
            )}
          </dd>
          <dt>Functions</dt>
          <dd>
            {functions !== null ? formatNumber(functions) : "unknown"}
            {chunking && wholeFunctions !== null && wholeFunctions !== functions && (
              <span className="faint">
                {" "}
                · {formatNumber(wholeFunctions)} whole +{" "}
                {formatNumber(functions! - wholeFunctions)} chunks
              </span>
            )}
            {!chunking && (
              <span className="faint"> · oversized dropped</span>
            )}
          </dd>
          <dt>Projected cost</dt>
          <dd>
            {estimate?.known ? formatCost(estimate.estimate_usd) : "unknown"}
          </dd>
          <dt>Budget ceiling</dt>
          <dd>{budget !== null ? formatCost(budget) : "none"}</dd>
        </dl>

        {budget === null && (
          <div className="note" style={{ marginTop: "var(--s3)" }}>
            <span className="note__label">No ceiling set</span>
            Without a budget the run continues until every function is analysed.
            You can still cancel at any point, and the work already paid for is
            saved.
          </div>
        )}

        <div className="confirm__actions">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" onClick={onConfirm}>
            Start analysis
          </Button>
        </div>
      </div>
    </div>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type {
  AnalysisConfig,
  AppliedPatch,
  AppliedPatches,
  CostEstimate,
  CostResponse,
  DirListing,
  EvaluationIndex,
  EvaluationReport,
  EvaluationSummary,
  ExtractionDocument,
  Finding,
  FsRoot,
  GraphDocument,
  GroundTruthDataset,
  HealthResponse,
  InspectResult,
  Job,
  PatchDocument,
  ResultSummary,
  SettingsResponse,
  UISettings,
} from "./types";

// ── settings ─────────────────────────────────────────────────────────────────

export function useSettings() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<SettingsResponse>("/settings"),
  });
}

export function useSaveSettings() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (settings: UISettings) => api.put<SettingsResponse>("/settings", settings),
    onSuccess: (data) => client.setQueryData(["settings"], data),
  });
}

export function useSaveApiKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: { value: string; alias?: string }) =>
      api.put<SettingsResponse>("/settings/api-key", payload),
    onSuccess: (data) => {
      client.setQueryData(["settings"], data);
      client.invalidateQueries({ queryKey: ["health"] });
    },
  });
}

export function useClearApiKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (alias?: string) =>
      api.delete<SettingsResponse>("/settings/api-key", { alias }),
    onSuccess: (data) => client.setQueryData(["settings"], data),
  });
}

export function useTestApiKey() {
  return useMutation({
    mutationFn: (alias?: string) =>
      api.post<{ ok: boolean; detail: string; sample_models?: string[] }>(
        "/settings/api-key/test",
        {},
        { alias },
      ),
  });
}

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<HealthResponse>("/health"),
  });
}

// ── filesystem ───────────────────────────────────────────────────────────────

export function useFsRoots() {
  return useQuery({
    queryKey: ["fs-roots"],
    queryFn: () => api.get<FsRoot[]>("/fs/roots"),
    staleTime: Infinity,
  });
}

export function useDirListing(path: string | null) {
  return useQuery({
    queryKey: ["fs-list", path],
    queryFn: () => api.get<DirListing>("/fs/list", { path: path! }),
    enabled: Boolean(path),
    // The filesystem changes underneath us; never serve a cached listing.
    staleTime: 0,
    retry: false,
  });
}

/**
 * The analysis configs a run can be scoped to.
 *
 * Static on disk, so it is fetched once and kept — the picker must not flicker
 * empty while a re-scan is in flight.
 */
export function useConfigs() {
  return useQuery({
    queryKey: ["configs"],
    queryFn: () => api.get<AnalysisConfig[]>("/configs"),
    staleTime: Infinity,
  });
}

export function useInspect() {
  return useMutation({
    // The config travels with the path: a count means nothing without the scope
    // it was taken under, so the two are never sent separately.
    mutationFn: (request: {
      path: string;
      config_path?: string | null;
      chunk_oversized?: boolean | null;
    }) => api.post<InspectResult>("/fs/inspect", request),
  });
}

// ── jobs ─────────────────────────────────────────────────────────────────────

export interface AnalyzeRequest {
  source_path: string;
  output_dir?: string;
  react: boolean;
  visualize: boolean;
  dry_run: boolean;
  resume: boolean;
  /** Scope for this run. Must be the config the displayed scan was taken under. */
  config_path?: string | null;
  /** null defers to the config; a boolean overrides it for this run only. */
  chunk_oversized?: boolean | null;
  budget_usd?: number | null;
  api_key_alias?: string;
  label?: string;
}

export function useStartAnalyze() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: AnalyzeRequest) => api.post<Job>("/jobs/analyze", request),
    onSuccess: () => client.invalidateQueries({ queryKey: ["jobs"] }),
  });
}

export function useStartPatch() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (request: { output_dir: string; api_key_alias?: string }) =>
      api.post<Job>("/jobs/patch", request),
    onSuccess: () => client.invalidateQueries({ queryKey: ["jobs"] }),
  });
}

export function useEstimate() {
  return useMutation({
    mutationFn: (request: { functions: number; react: boolean }) =>
      api.post<CostEstimate>("/jobs/estimate", request),
  });
}

export function useJobs() {
  return useQuery({
    queryKey: ["jobs"],
    queryFn: () => api.get<Job[]>("/jobs"),
  });
}

/**
 * One job by id.
 *
 * The Analyze form remembers the last job it started, so on returning to the
 * page its state has to be known immediately — waiting for the SSE replay would
 * render a finished run as "Running…" for a moment.
 */
export function useJob(jobId: string | null) {
  return useQuery({
    queryKey: ["jobs", jobId],
    queryFn: () => api.get<Job>(`/jobs/${jobId!}`),
    enabled: Boolean(jobId),
    // A job the server has forgotten (restarted since) must not be retried.
    retry: false,
  });
}

export function useActiveJob() {
  return useQuery({
    queryKey: ["jobs", "active"],
    queryFn: () => api.get<Job | null>("/jobs/active"),
    // Polled so a run started in another tab, or still going after a refresh,
    // is picked up. The live stream does the per-line work, not this.
    refetchInterval: 5000,
  });
}

export function useCancelJob() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) => api.post<{ cancelled: boolean }>(`/jobs/${jobId}/cancel`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["jobs"] }),
  });
}

// ── results ──────────────────────────────────────────────────────────────────

export function useResult(path: string | null) {
  return useQuery({
    queryKey: ["result", path],
    queryFn: () => api.get<ResultSummary>("/results", { path: path! }),
    enabled: Boolean(path),
  });
}

/**
 * Open a results folder produced elsewhere — another session, another machine,
 * or a plain CLI run.
 *
 * Reads are authorised against the registry of directories this tool has
 * written to, so a folder it has never seen is unreadable until this call
 * registers it. The server refuses anything that does not already contain run
 * artifacts, so this widens what can be read without making it a file browser.
 */
export function useOpenResults() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (path: string) => api.post<ResultSummary>("/results/open", { path }),
    onSuccess: (data) => {
      // The folder was unreadable a moment ago; any negative cached result for
      // it has to go, or the Results page would render the old failure.
      client.invalidateQueries({ queryKey: ["result", data.output_dir] });
    },
  });
}

export function useFindings(path: string | null, enabled = true) {
  return useQuery({
    queryKey: ["findings", path],
    queryFn: () => api.get<Finding[]>("/results/findings", { path: path! }),
    enabled: Boolean(path) && enabled,
  });
}

export function useExtraction(path: string | null, enabled = true) {
  return useQuery({
    queryKey: ["extraction", path],
    queryFn: () => api.get<ExtractionDocument>("/results/extraction", { path: path! }),
    enabled: Boolean(path) && enabled,
  });
}

export function useGraph(path: string | null, enabled = true) {
  return useQuery({
    queryKey: ["graph", path],
    queryFn: () => api.get<GraphDocument>("/results/graph", { path: path! }),
    enabled: Boolean(path) && enabled,
  });
}

export function usePatches(path: string | null, enabled = true) {
  return useQuery({
    queryKey: ["patches", path],
    queryFn: () => api.get<PatchDocument | null>("/results/patches", { path: path! }),
    enabled: Boolean(path) && enabled,
  });
}

export function useAppliedPatches(path: string | null, enabled = true) {
  return useQuery({
    queryKey: ["patches-applied", path],
    queryFn: () => api.get<AppliedPatches>("/results/patches/applied", { path: path! }),
    enabled: Boolean(path) && enabled,
  });
}

interface PatchTarget {
  path: string;
  file_path: string;
  function_name: string;
}

/**
 * Write one patch into the analysed project, or take it back out.
 *
 * The only call in this app that modifies a file outside a result directory, so
 * it is deliberately per-finding: there is no bulk variant to reach for by
 * accident. `applied_count` also feeds the results summary, so both queries are
 * refreshed on success.
 */
function usePatchWrite(action: "apply" | "revert") {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (target: PatchTarget) =>
      api.post<AppliedPatch>(`/results/patches/${action}`, target),
    onSuccess: (_data, target) => {
      client.invalidateQueries({ queryKey: ["patches-applied", target.path] });
      client.invalidateQueries({ queryKey: ["artifact", target.path] });
    },
  });
}

export const useApplyPatch = () => usePatchWrite("apply");
export const useRevertPatch = () => usePatchWrite("revert");

export function useArtifact(path: string | null, name: string | null) {
  return useQuery({
    queryKey: ["artifact", path, name],
    queryFn: () => api.get<unknown>(`/results/artifacts/${name!}`, { path: path! }),
    enabled: Boolean(path && name),
  });
}

// ── cost ───────────────────────────────────────────────────────────────────

export function useCost(runId?: string) {
  return useQuery({
    queryKey: ["cost", runId ?? "all"],
    queryFn: () => api.get<CostResponse>("/cost", { run_id: runId }),
  });
}

export function useCostByRun(limit = 25) {
  return useQuery({
    queryKey: ["cost-runs", limit],
    queryFn: () => api.get<import("./types").CostGroup[]>("/cost/runs", { limit }),
  });
}

// ── evaluations ──────────────────────────────────────────────────────────────

export function useEvaluations() {
  return useQuery({
    queryKey: ["evaluations"],
    queryFn: () => api.get<EvaluationIndex>("/evaluations"),
  });
}

export function useEvaluationReport(path: string | null) {
  return useQuery({
    queryKey: ["evaluation", path],
    queryFn: () => api.get<EvaluationReport>("/evaluations/report", { path: path! }),
    enabled: Boolean(path),
  });
}

export function useComparison(path: string | null) {
  return useQuery({
    queryKey: ["comparison", path],
    queryFn: () => api.get<string>("/evaluations/comparison", { path: path! }),
    enabled: Boolean(path),
  });
}

export function useGroundTruthDatasets() {
  return useQuery({
    queryKey: ["ground-truth-datasets"],
    queryFn: () => api.get<GroundTruthDataset[]>("/evaluations/datasets"),
  });
}

/** Reports already produced for a run — drives the Results page cross-link. */
export function useEvaluationsForRun(runId: string | null | undefined) {
  return useQuery({
    queryKey: ["evaluations-for-run", runId],
    queryFn: () => api.get<EvaluationSummary[]>("/evaluations/for-run", { run_id: runId! }),
    enabled: Boolean(runId),
  });
}

/** Scoring is local and free — no API calls, so no confirmation step. */
export function useRunEvaluation() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: { path: string; ground_truth: string }) =>
      api.post<EvaluationReport>("/evaluations/run", payload),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["evaluations"] });
      client.invalidateQueries({ queryKey: ["evaluations-for-run"] });
    },
  });
}

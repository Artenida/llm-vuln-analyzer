import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type {
  CostEstimate,
  CostResponse,
  DirListing,
  ExtractionDocument,
  Finding,
  FsRoot,
  GraphDocument,
  HealthResponse,
  HistoryEntry,
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

export function useInspect() {
  return useMutation({
    mutationFn: (path: string) => api.post<InspectResult>("/fs/inspect", { path }),
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

export function useArtifact(path: string | null, name: string | null) {
  return useQuery({
    queryKey: ["artifact", path, name],
    queryFn: () => api.get<unknown>(`/results/artifacts/${name!}`, { path: path! }),
    enabled: Boolean(path && name),
  });
}

// ── cost and history ─────────────────────────────────────────────────────────

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

export function useHistory() {
  return useQuery({
    queryKey: ["history"],
    queryFn: () => api.get<HistoryEntry[]>("/history"),
  });
}

/** Add a results folder produced elsewhere — another machine, or the CLI. */
export function useOpenResultsFolder() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (path: string) => api.post<HistoryEntry>("/history/open", { path }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["history"] }),
  });
}

export function useForgetHistory() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (entryId: string) => api.delete(`/history/${entryId}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["history"] }),
  });
}

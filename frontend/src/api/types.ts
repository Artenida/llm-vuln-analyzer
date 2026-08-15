/**
 * Mirrors the FastAPI response shapes in src/web/.
 *
 * `null` is meaningful throughout and is never collapsed to 0: a cost of `null`
 * means unknown pricing, which is not the same claim as free. Rendering follows
 * suit — `n/a`, never `$0.00`.
 */

// ── settings ─────────────────────────────────────────────────────────────────

export interface UISettings {
  model: string;
  react: boolean;
  max_steps: number;
  max_function_lines: number;
  visualize: boolean;
  budget_usd: number | null;
  api_key_alias: string;
  results_root: string;
  skip_dirs: string[];
}

export interface ApiKeyStatus {
  alias: string;
  configured: boolean;
  /** Masked preview only. The key value is never sent to the browser. */
  masked: string | null;
  /** Where the key was found: the workspace file, or the environment. */
  source: "workspace" | "environment" | "none";
  /** Absolute path of the workspace key file for this alias. */
  key_file: string;
  /** The environment variable this alias falls back to. */
  env_var: string;
}

export interface EnvironmentReport {
  workspace: string;
  workspace_exists: boolean;
  key_file: string;
  project_root: string;
  python: string;
  python_executable: string;
  ledger_path: string;
  ledger_exists: boolean;
}

export interface SettingsResponse {
  settings: UISettings;
  api_keys: ApiKeyStatus[];
  environment: EnvironmentReport;
}

// ── filesystem ───────────────────────────────────────────────────────────────

export interface FsRoot {
  label: string;
  path: string;
}

export interface DirEntry {
  name: string;
  path: string;
  is_dir: boolean;
  is_result_dir: boolean;
}

export interface DirListing {
  path: string;
  parent: string | null;
  entries: DirEntry[];
  /** Whether the listed folder is itself a result bundle. */
  is_result_dir: boolean;
}

export interface InspectResult {
  path: string;
  exists: boolean;
  is_dir: boolean;
  source_files: number;
  languages: Record<string, number>;
  functions: number | null;
  functions_skipped: number | null;
  scanned: boolean;
  note: string | null;
}

// ── jobs ─────────────────────────────────────────────────────────────────────

export type JobState = "running" | "succeeded" | "failed" | "cancelled";

export interface Job {
  id: string;
  kind: "analyze" | "patch";
  label: string;
  state: JobState;
  started_at: string;
  finished_at: string | null;
  exit_code: number | null;
  current: number;
  total: number;
  current_function: string | null;
  findings: number;
  output_dir: string | null;
  source_path: string | null;
  error: string | null;
  command: string;
}

export interface JobEvent {
  type: "started" | "log" | "state" | "finished" | "ping";
  line?: string;
  current?: number;
  total?: number;
  current_function?: string | null;
  findings?: number;
  job?: Job;
}

export type CostEstimate =
  | { known: false; reason: string }
  | {
      known: true;
      functions: number;
      per_function_usd: number;
      estimate_usd: number;
      based_on_functions: number;
      mode: string;
      note: string | null;
    };

// ── results ──────────────────────────────────────────────────────────────────

export interface RunTotals {
  total_functions?: number | null;
  vulnerabilities_found?: number | null;
  clean?: number | null;
  errors?: number | null;
  hallucinated?: number | null;
  total_prompt_tokens?: number | null;
  total_completion_tokens?: number | null;
  total_tokens?: number | null;
  total_cost_usd?: number | null;
}

export interface ExtractionTotals {
  functions_found?: number | null;
  functions_skipped_oversized?: number | null;
  coverage?: number | null;
}

export interface ArtifactRef {
  name: string;
  size_bytes: number;
  modified_at: string;
  kind: string;
  readable: boolean;
}

export interface PatchTotals {
  total_patches?: number | null;
  valid?: number | null;
  invalid?: number | null;
  total_cost_usd?: number | null;
}

export interface ResultSummary {
  output_dir: string;
  display_dir: string;
  modified_at: string | null;

  has_analysis: boolean;
  has_extraction: boolean;
  has_graph: boolean;
  has_graph_html: boolean;
  /** mtime of the embedded graph HTML — stamped onto the iframe URL. */
  graph_html_version: string | null;
  has_annotated_html: boolean;
  has_dot: boolean;
  has_checkpoint: boolean;
  has_patches: boolean;

  run_id: string | null;
  model: string | null;
  source_path: string | null;
  timestamp: string | null;
  schema_version: string | null;
  analysis_mode: string | null;

  totals: RunTotals;
  extraction_totals: ExtractionTotals;
  meta: Record<string, unknown>;
  /** True when the run was cancelled or hit its budget before finishing. */
  partial: boolean;
  partial_reason: string | null;

  severity_counts: Record<string, number>;
  cwe_counts: Record<string, number>;
  graph_nodes: number;
  checkpoint_records: number;

  patch_summary: PatchTotals | null;
  patch_file: string | null;
  artifacts: ArtifactRef[];
}

export interface Finding {
  function_name: string;
  file_path: string;
  language?: string | null;
  vulnerability_found: boolean;
  cwe_id: string | null;
  affected_lines: number[];
  severity: string | null;
  explanation: string | null;
  patch_suggestion: string | null;
  confidence: number | null;
  hallucination_flag: boolean;
  analysis_mode: string | null;
  error: string | null;
  duplicate_group: number | null;
  unified_diff?: string | null;
  patch_valid?: boolean | null;
  patch_error?: string | null;
  prompt_tokens?: number;
  completion_tokens?: number;
  cost_usd?: number | null;
}

export interface ExtractedFunction {
  file_path: string;
  function_name: string;
  start_line: number;
  end_line: number;
  language: string;
  code: string;
}

export interface SkippedFunction {
  function_name: string;
  file_path: string;
  start_line: number;
  end_line: number;
  line_count: number;
}

export interface ExtractionDocument {
  metadata?: { source_path?: string; generated_at?: string };
  summary?: ExtractionTotals;
  results?: ExtractedFunction[];
  skipped_oversized?: SkippedFunction[];
}

export interface GraphNode {
  function_name: string;
  file_path: string;
  callers: string[];
  callees: string[];
  is_entry_point: boolean;
  is_infrastructure: boolean;
  is_external: boolean;
  is_taint_source: boolean;
  is_taint_sink: boolean;
}

export interface GraphDocument {
  source_path?: string;
  timestamp?: string;
  total_nodes?: number;
  graph?: Record<string, GraphNode>;
}

export interface PatchRecord {
  function_name: string;
  file_path: string;
  cwe_id?: string | null;
  severity?: string | null;
  unified_diff?: string | null;
  patch_valid?: boolean | null;
  patch_error?: string | null;
  patched_code?: string | null;
  prompt_tokens?: number;
  completion_tokens?: number;
  cost_usd?: number | null;
}

/** One patch written into the analysed project, and the bytes it replaced. */
export interface AppliedPatch {
  function_name: string;
  file_path: string;
  cwe_id?: string | null;
  severity?: string | null;
  state: "applied" | "reverted";
  applied_at?: string | null;
  reverted_at?: string | null;
  line?: number | null;
  original_code?: string | null;
  patched_code?: string | null;
}

export interface AppliedPatches {
  entries: AppliedPatch[];
  applied_count: number;
}

export interface PatchDocument {
  run_id?: string;
  source_path?: string;
  timestamp?: string;
  summary?: PatchTotals;
  patches?: PatchRecord[];
}

// ── cost ─────────────────────────────────────────────────────────────────────

export interface CostGroup {
  group_key: string;
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  /** null when any event in the group used an unpriced model — not zero. */
  cost_usd: number | null;
}

export interface CostResponse {
  available: boolean;
  ledger_path: string;
  total: CostGroup | null;
  by_phase: CostGroup[];
  by_model: CostGroup[];
  by_api_key: CostGroup[];
}

// ── evaluations ──────────────────────────────────────────────────────────────

export interface ConfusionMetrics {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
}

/** Deduplicated recall: one planted bug copy-pasted twice counts once. */
export interface UniqueRecall {
  planted: number;
  detected: number;
  recall: number;
}

/**
 * Whether the ground truth behind a report was reviewed. `needs_curation` is
 * null when the dataset is no longer on this machine — unknown, never assumed
 * curated.
 */
export interface CurationStatus {
  known: boolean;
  scaffolded: boolean | null;
  reviewed: boolean | null;
  needs_curation: boolean | null;
  functions_unreviewed?: number | null;
  functions_prefilled_vulnerable?: number | null;
  ground_truth_path?: string;
}

export interface EvaluationSummary {
  path: string;
  display_path: string;
  name: string;
  modified_at: string | null;

  run_id: string | null;
  dataset: string | null;
  model: string | null;
  analysis_mode: string | null;
  source_path: string | null;
  generated_at: string | null;
  schema_version: string | null;

  detection_metrics: ConfusionMetrics;
  cwe_accuracy_on_true_positives: number | null;
  unique_vulnerability_recall: UniqueRecall;
  hallucination_rate_on_flagged: number | null;
  total_cost_usd: number | null;
  total_tokens: number | null;
  cost_per_tp_usd: number | null;

  instance_count: number;
  unmatched_count: number;
  unresolved_count: number;
  curation: CurationStatus;
}

export interface EvaluationInstance {
  instance_id: string;
  function_name: string;
  file: string;
  gt_vulnerable: boolean;
  gt_cwe: string | null;
  analyzed: boolean;
  predicted_vulnerable: boolean;
  predicted_cwe: string | null;
  outcome: "TP" | "FP" | "FN" | "TN" | string;
  cwe_correct: boolean;
  hallucination_flag: boolean;
}

export interface CweBreakdownRow {
  cwe_id: string;
  planted: number;
  detected: number;
  cwe_correct: number;
}

/** A finding whose function name has no ground truth row — unscorable. */
export interface UnmatchedFinding {
  function_name: string | null;
  file_path: string | null;
  vulnerability_found: boolean | null;
  cwe_id: string | null;
}

/** A ground truth row whose function name matched several findings. */
export interface UnresolvedFinding {
  function_name: string;
  expected_file: string;
  candidate_files: (string | null)[];
}

export interface EvaluationReport extends EvaluationSummary {
  instances: EvaluationInstance[];
  cwe_breakdown: CweBreakdownRow[];
  unmatched_findings: UnmatchedFinding[];
  unresolved_findings: UnresolvedFinding[];
}

export interface ComparisonEntry {
  path: string;
  display_path: string;
  name: string;
  dataset: string | null;
  modified_at: string | null;
}

export interface EvaluationIndex {
  reports: EvaluationSummary[];
  comparisons: ComparisonEntry[];
}

export interface GroundTruthDataset {
  name: string;
  folder: string;
  path: string;
  description: string;
  source_path: string;
  function_count: number;
  vulnerable_count: number;
  curation: CurationStatus;
}

export interface HealthResponse {
  status: string;
  project_root: string;
  python: string;
  ledger_exists: boolean;
  api_key: ApiKeyStatus;
}

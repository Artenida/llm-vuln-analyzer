import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { CostEstimate, InspectResult } from "@/api/types";

/**
 * The Analyze form's state, held above the router.
 *
 * It lives here rather than in the page because the page unmounts the moment you
 * navigate to another page, which would throw away a path you had just
 * picked and a scan that took seconds to run. It is also mirrored to
 * localStorage, so the same is true across a refresh or a restart of the server —
 * re-typing a path is exactly the kind of work a tool should not ask for twice.
 */

export type AnalyzeMode = "react" | "semantic";

export interface AnalyzeFormState {
  sourcePath: string;
  outputDir: string;
  mode: AnalyzeMode;
  visualize: boolean;
  dryRun: boolean;
  resume: boolean;
  budget: number | null;
  /** Result of the last folder scan — kept so returning here doesn't re-scan. */
  inspection: InspectResult | null;
  estimate: CostEstimate | null;
  /** The last run started from this form, so progress is still shown on return. */
  jobId: string | null;
  /**
   * Whether Settings defaults have been applied. Without this the defaults
   * would re-apply on every mount and silently overwrite your choices each
   * time you came back to the page.
   */
  seededFromSettings: boolean;
}

const EMPTY: AnalyzeFormState = {
  sourcePath: "",
  outputDir: "",
  mode: "react",
  visualize: true,
  dryRun: false,
  resume: false,
  budget: null,
  inspection: null,
  estimate: null,
  jobId: null,
  seededFromSettings: false,
};

const STORAGE_KEY = "vulnanalyzer.analyze-form.v1";

interface AnalyzeFormContextValue {
  form: AnalyzeFormState;
  update: (patch: Partial<AnalyzeFormState>) => void;
  reset: () => void;
}

const AnalyzeFormContext = createContext<AnalyzeFormContextValue | null>(null);

function load(): AnalyzeFormState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return EMPTY;
    const stored = JSON.parse(raw) as Partial<AnalyzeFormState>;
    // Merged over EMPTY rather than used directly: a state shape from an older
    // build must not leave a field undefined and break an input.
    return { ...EMPTY, ...stored };
  } catch {
    return EMPTY;
  }
}

export function AnalyzeFormProvider({ children }: { children: ReactNode }) {
  const [form, setForm] = useState<AnalyzeFormState>(load);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(form));
    } catch {
      // Private mode or a full quota — losing persistence is not worth an error.
    }
  }, [form]);

  const update = useCallback((patch: Partial<AnalyzeFormState>) => {
    setForm((previous) => ({ ...previous, ...patch }));
  }, []);

  const reset = useCallback(() => {
    // Settings defaults are deliberately re-seeded after a reset.
    setForm({ ...EMPTY });
  }, []);

  const value = useMemo(() => ({ form, update, reset }), [form, update, reset]);

  return (
    <AnalyzeFormContext.Provider value={value}>{children}</AnalyzeFormContext.Provider>
  );
}

export function useAnalyzeForm(): AnalyzeFormContextValue {
  const context = useContext(AnalyzeFormContext);
  if (context === null) {
    throw new Error("useAnalyzeForm must be used inside AnalyzeFormProvider");
  }
  return context;
}

import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Job, JobEvent } from "@/api/types";

export interface JobStreamState {
  lines: string[];
  current: number;
  total: number;
  currentFunction: string | null;
  findings: number;
  job: Job | null;
  connected: boolean;
}

const EMPTY: JobStreamState = {
  lines: [],
  current: 0,
  total: 0,
  currentFunction: null,
  findings: 0,
  job: null,
  connected: false,
};

/**
 * Live job output over Server-Sent Events.
 *
 * SSE rather than polling because a run prints thousands of lines over minutes,
 * and rather than a WebSocket because the traffic is strictly one-way. The
 * backend replays the log on connect, so a refresh mid-run rejoins with the
 * full history instead of an empty pane.
 */
export function useJobStream(jobId: string | null): JobStreamState {
  const [state, setState] = useState<JobStreamState>(EMPTY);
  const queryClient = useQueryClient();
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!jobId) {
      setState(EMPTY);
      return;
    }

    setState(EMPTY);
    const source = new EventSource(`/api/jobs/${jobId}/events`);
    sourceRef.current = source;

    source.onopen = () => setState((prev) => ({ ...prev, connected: true }));

    source.onmessage = (message) => {
      let event: JobEvent;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }
      if (event.type === "ping") return;

      setState((prev) => {
        const next = { ...prev, connected: true };
        if (event.line !== undefined) next.lines = [...prev.lines, event.line];
        if (event.current !== undefined) next.current = event.current;
        if (event.total !== undefined) next.total = event.total;
        if (event.current_function !== undefined) {
          next.currentFunction = event.current_function ?? null;
        }
        if (event.findings !== undefined) next.findings = event.findings;
        if (event.job) {
          next.job = event.job;
          // Adopt the counters the job record carries. The replay a reconnecting
          // browser receives is log lines only — without this, returning to the
          // page showed a finished run stuck at "starting…" with an empty bar.
          next.current = Math.max(next.current, event.job.current);
          next.total = Math.max(next.total, event.job.total);
          next.findings = Math.max(next.findings, event.job.findings);
        }
        return next;
      });

      if (event.type === "finished") {
        source.close();
        // The run just wrote files — every result and cost view is now stale.
        queryClient.invalidateQueries({ queryKey: ["jobs"] });
        queryClient.invalidateQueries({ queryKey: ["history"] });
        queryClient.invalidateQueries({ queryKey: ["cost"] });
        queryClient.invalidateQueries({ queryKey: ["result"] });
        queryClient.invalidateQueries({ queryKey: ["findings"] });
        queryClient.invalidateQueries({ queryKey: ["patches"] });
      }
    };

    source.onerror = () => {
      setState((prev) => ({ ...prev, connected: false }));
    };

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [jobId, queryClient]);

  return state;
}

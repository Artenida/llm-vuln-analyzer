import { useEffect, useRef, useState } from "react";
import "./LogStream.css";

/** Tint a log line by what it says. The CLI's own vocabulary, not a new one. */
function toneOf(line: string): string {
  if (/→\s*VULN/i.test(line)) return "log--vuln";
  if (/→\s*clean/i.test(line)) return "log--clean";
  if (/\bERROR\b|Traceback|→ ERROR/.test(line)) return "log--error";
  if (/\bPARTIAL RUN\b|budget ceiling|interrupted/i.test(line)) return "log--warn";
  if (/^\s*\[\s*\d+\s*\/\s*\d+\s*\]/.test(line)) return "log--progress";
  if (/^(Extraction|Call graph|Analyzing|Total|Results saved|Cost|Estimated)/.test(line)) {
    return "log--head";
  }
  return "";
}

export function LogStream({
  lines,
  height = 320,
  emptyLabel = "Waiting for output…",
}: {
  lines: string[];
  height?: number;
  emptyLabel?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);

  useEffect(() => {
    if (!follow) return;
    const element = containerRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [lines, follow]);

  function onScroll() {
    const element = containerRef.current;
    if (!element) return;
    // Scrolling up pauses auto-follow so you can read back mid-run; returning
    // to the bottom resumes it.
    const atBottom =
      element.scrollHeight - element.scrollTop - element.clientHeight < 40;
    setFollow(atBottom);
  }

  return (
    <div className="log">
      <div
        className="log__body"
        style={{ height }}
        ref={containerRef}
        onScroll={onScroll}
        role="log"
        aria-live="polite"
      >
        {lines.length === 0 ? (
          <p className="log__empty">{emptyLabel}</p>
        ) : (
          lines.map((line, index) => (
            <div key={index} className={`log__line ${toneOf(line)}`}>
              {line || " "}
            </div>
          ))
        )}
      </div>
      {!follow && (
        <button
          type="button"
          className="log__follow"
          onClick={() => {
            setFollow(true);
            const element = containerRef.current;
            if (element) element.scrollTop = element.scrollHeight;
          }}
        >
          ↓ Follow output
        </button>
      )}
    </div>
  );
}

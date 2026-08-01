import { useMemo } from "react";
import "./CodeBlock.css";

/**
 * Source with line numbers, and the flagged lines marked.
 *
 * `startLine` matters: `affected_lines` from a finding are absolute file line
 * numbers, while the code shown is only the function's slice. Numbering from
 * the function's real start is what makes the two line up.
 */
export function CodeBlock({
  code,
  startLine = 1,
  highlight = [],
  maxHeight = 420,
}: {
  code: string;
  startLine?: number;
  highlight?: number[];
  maxHeight?: number;
}) {
  const lines = useMemo(() => code.replace(/\n$/, "").split("\n"), [code]);
  const flagged = useMemo(() => new Set(highlight), [highlight]);

  return (
    <div className="code" style={{ maxHeight }}>
      <table className="code__table">
        <tbody>
          {lines.map((line, index) => {
            const number = startLine + index;
            const isFlagged = flagged.has(number);
            return (
              <tr key={number} className={isFlagged ? "code__row code__row--flagged" : "code__row"}>
                <td className="code__gutter">{number}</td>
                <td className="code__line">{line || " "}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Unified-diff renderer.
 *
 * Deliberately not syntax-highlighted: what matters in a patch review is which
 * lines moved, and colouring the language on top of the +/- colouring makes
 * both harder to read.
 */
export function DiffView({ diff, maxHeight = 420 }: { diff: string; maxHeight?: number }) {
  const lines = useMemo(() => diff.replace(/\n$/, "").split("\n"), [diff]);

  return (
    <div className="code diff" style={{ maxHeight }}>
      {lines.map((line, index) => {
        let tone = "";
        if (line.startsWith("+++") || line.startsWith("---")) tone = "diff--file";
        else if (line.startsWith("@@")) tone = "diff--hunk";
        else if (line.startsWith("+")) tone = "diff--add";
        else if (line.startsWith("-")) tone = "diff--del";
        return (
          <div key={index} className={`diff__line ${tone}`}>
            {line || " "}
          </div>
        );
      })}
    </div>
  );
}

/** Collapsible raw JSON — the fallback that makes every field reachable. */
export function JsonViewer({ value, maxHeight = 520 }: { value: unknown; maxHeight?: number }) {
  const text = useMemo(() => {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }, [value]);

  return (
    <pre className="code json" style={{ maxHeight }}>
      {text}
    </pre>
  );
}

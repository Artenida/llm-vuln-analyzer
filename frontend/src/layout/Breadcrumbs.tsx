import { Link, useLocation } from "react-router-dom";
import "./Breadcrumbs.css";

const LABELS: Record<string, string> = {
  datasets: "Datasets",
  runs: "Runs",
  evaluations: "Evaluations",
  patches: "Patches",
  costs: "Costs",
  jobs: "Jobs",
  compare: "Compare",
};

/**
 * Derived from the URL rather than passed down from pages — a page should not
 * have to remember to declare its own breadcrumb, and the URL already carries
 * the hierarchy (/runs/juice-shop/agentic-v1).
 */
export function Breadcrumbs() {
  const { pathname } = useLocation();
  const segments = pathname.split("/").filter(Boolean);

  if (segments.length === 0) {
    return <nav className="crumbs" aria-label="Breadcrumb">Overview</nav>;
  }

  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      <Link to="/">Overview</Link>
      {segments.map((segment, index) => {
        const to = `/${segments.slice(0, index + 1).join("/")}`;
        const isLast = index === segments.length - 1;
        const decoded = decodeURIComponent(segment);
        // The '_' dataset sentinel is an addressing detail, not a place.
        const label = decoded === "_" ? "standalone" : (LABELS[decoded] ?? decoded);
        return (
          <span key={to} className="crumbs__item">
            <span className="crumbs__sep" aria-hidden="true">
              /
            </span>
            {isLast ? (
              <span className="crumbs__current">{label}</span>
            ) : (
              <Link to={to}>{label}</Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}

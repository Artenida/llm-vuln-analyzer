import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useActiveJob, useCost, useSettings } from "@/api/hooks";
import { formatCost } from "@/lib/format";
import { Breadcrumbs } from "./Breadcrumbs";
import "./AppShell.css";

const NAV = [
  { to: "/", label: "Analyze", glyph: "▶" },
  // No ?path — Results opens the most recent run on its own, so seeing what you
  // just ran is one click from anywhere.
  { to: "/results", label: "Results", glyph: "◈" },
  { to: "/evaluations", label: "Evaluations", glyph: "±" },
  { to: "/history", label: "History", glyph: "▤" },
  { to: "/costs", label: "Costs", glyph: "$" },
  { to: "/settings", label: "Settings", glyph: "⚙" },
];

export function AppShell() {
  const { data: cost } = useCost();
  const { data: settings } = useSettings();
  const { data: activeJob } = useActiveJob();
  const navigate = useNavigate();

  const keyMissing =
    settings != null &&
    !settings.api_keys.some(
      (key) => key.alias === settings.settings.api_key_alias && key.configured,
    );

  return (
    <div className="shell">
      <aside className="shell__sidebar">
        <div className="shell__brand">
          <span className="shell__brand-mark" aria-hidden="true">
            ◤
          </span>
          <span className="shell__brand-text">
            vuln<strong>analyzer</strong>
          </span>
        </div>

        <nav className="shell__nav" aria-label="Primary">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                isActive ? "shell__link shell__link--active" : "shell__link"
              }
            >
              <span className="shell__glyph" aria-hidden="true">
                {item.glyph}
              </span>
              {item.label}
              {item.to === "/settings" && keyMissing && (
                <span className="shell__alert" title="No API key configured">
                  !
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="shell__footer">
          <div className="shell__footer-row">
            <span>Total spend</span>
            <span className="num">
              {cost?.available ? formatCost(cost.total?.cost_usd) : "—"}
            </span>
          </div>
        </div>
      </aside>

      <div className="shell__main">
        <header className="shell__topbar">
          <Breadcrumbs />
          <div className="shell__topbar-meta">
            {/* A run started elsewhere stays visible from every screen — it is
                spending money whether or not you are looking at it. */}
            {activeJob && activeJob.state === "running" && (
              <button
                type="button"
                className="shell__running"
                onClick={() => navigate("/")}
                title={`${activeJob.label} — click to view`}
              >
                <span className="shell__pulse" aria-hidden="true" />
                {activeJob.kind === "patch" ? "patching" : "analysing"}
                {activeJob.total > 0 && (
                  <span className="num">
                    {activeJob.current}/{activeJob.total}
                  </span>
                )}
              </button>
            )}
          </div>
        </header>

        <main className="shell__content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

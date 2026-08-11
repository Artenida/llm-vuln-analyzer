import { Route, Routes } from "react-router-dom";
import { AppShell } from "./layout/AppShell";
import { AnalyzePage } from "./routes/AnalyzePage";
import { ResultsPage } from "./routes/ResultsPage";
import { EvaluationsPage } from "./routes/EvaluationsPage";
import { CostsPage } from "./routes/CostsPage";
import { SettingsPage } from "./routes/SettingsPage";
import { NotFoundPage } from "./routes/NotFoundPage";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<AnalyzePage />} />
        {/* Results are addressed by their output directory, which can be
            anywhere on disk — hence a query parameter, not a path segment. */}
        <Route path="results" element={<ResultsPage />} />
        {/* Reports live beside the dataset they scored, not inside a run — so
            this page is addressed by report path, again as a query parameter. */}
        <Route path="evaluations" element={<EvaluationsPage />} />
        <Route path="costs" element={<CostsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

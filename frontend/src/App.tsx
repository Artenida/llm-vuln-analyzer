import { Route, Routes } from "react-router-dom";
import { AppShell } from "./layout/AppShell";
import { AnalyzePage } from "./routes/AnalyzePage";
import { ResultsPage } from "./routes/ResultsPage";
import { CostsPage } from "./routes/CostsPage";
import { HistoryPage } from "./routes/HistoryPage";
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
        <Route path="costs" element={<CostsPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

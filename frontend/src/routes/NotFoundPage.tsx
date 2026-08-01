import { Link, useLocation } from "react-router-dom";
import { EmptyState } from "@/components";

export function NotFoundPage() {
  const { pathname } = useLocation();
  return (
    <EmptyState
      icon="?"
      title="No such page"
      detail={
        <>
          <code>{pathname}</code> is not a route in this build. Later sections
          land in Sprints 10–12 — see <code>docs/frontend-plan.md</code>.
          <br />
          <Link to="/">Back to overview</Link>
        </>
      }
    />
  );
}

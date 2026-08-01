import { useSearchParams } from "react-router-dom";
import type { ReactNode } from "react";
import "./Tabs.css";

export interface TabItem {
  id: string;
  label: ReactNode;
  /** Small trailing count, e.g. the number of findings. */
  count?: number | null;
  /** Greys the tab and blocks selection — used when a run lacks that artifact. */
  disabled?: boolean;
  disabledReason?: string;
}

interface TabsProps {
  items: TabItem[];
  /** Query-string key the active tab is stored in, so tabs are deep-linkable. */
  param?: string;
  children: (activeId: string) => ReactNode;
}

export function Tabs({ items, param = "tab", children }: TabsProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const enabled = items.filter((item) => !item.disabled);
  const requested = searchParams.get(param);
  const active =
    enabled.find((item) => item.id === requested)?.id ?? enabled[0]?.id ?? "";

  function select(id: string) {
    const next = new URLSearchParams(searchParams);
    next.set(param, id);
    // replace: switching tabs shouldn't stack history entries between the
    // page you came from and the one you'd expect Back to return to.
    setSearchParams(next, { replace: true });
  }

  return (
    <div className="tabs">
      <div className="tabs__list" role="tablist">
        {items.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={item.id === active}
            disabled={item.disabled}
            title={item.disabled ? item.disabledReason : undefined}
            className={item.id === active ? "tabs__tab tabs__tab--active" : "tabs__tab"}
            onClick={() => select(item.id)}
          >
            {item.label}
            {item.count !== null && item.count !== undefined && (
              <span className="tabs__count">{item.count}</span>
            )}
          </button>
        ))}
      </div>
      <div className="tabs__panel" role="tabpanel">
        {children(active)}
      </div>
    </div>
  );
}

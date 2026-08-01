import type { ReactNode } from "react";
import "./FilterBar.css";

interface FilterBarProps {
  search: string;
  onSearch: (value: string) => void;
  placeholder?: string;
  /** Rendered between the search box and the count — facet chips, selects. */
  children?: ReactNode;
  /** "12 of 379" style readout. Always shown, so a filter is never invisible. */
  count?: ReactNode;
  onReset?: () => void;
}

export function FilterBar({
  search,
  onSearch,
  placeholder = "Search…",
  children,
  count,
  onReset,
}: FilterBarProps) {
  return (
    <div className="filterbar">
      <div className="filterbar__search">
        <span className="filterbar__icon" aria-hidden="true">
          ⌕
        </span>
        <input
          type="search"
          value={search}
          placeholder={placeholder}
          aria-label={placeholder}
          onChange={(event) => onSearch(event.target.value)}
        />
      </div>
      {children}
      <div className="filterbar__spacer" />
      {count !== undefined && <span className="filterbar__count">{count}</span>}
      {onReset && (
        <button type="button" className="filterbar__reset" onClick={onReset}>
          Reset
        </button>
      )}
    </div>
  );
}

interface ChipsProps<T extends string> {
  options: readonly T[];
  selected: T[];
  onChange: (next: T[]) => void;
  /** Renders a nicer label than the raw value. */
  label?: (value: T) => ReactNode;
  counts?: Partial<Record<T, number>>;
}

/** Multi-select facet chips. Empty selection means "no filter", not "none". */
export function FilterChips<T extends string>({
  options,
  selected,
  onChange,
  label,
  counts,
}: ChipsProps<T>) {
  return (
    <div className="filterbar__chips" role="group">
      {options.map((option) => {
        const active = selected.includes(option);
        return (
          <button
            key={option}
            type="button"
            className={active ? "chip chip--active" : "chip"}
            aria-pressed={active}
            onClick={() =>
              onChange(
                active
                  ? selected.filter((value) => value !== option)
                  : [...selected, option],
              )
            }
          >
            {label ? label(option) : option}
            {counts?.[option] !== undefined && (
              <span className="chip__count">{counts[option]}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

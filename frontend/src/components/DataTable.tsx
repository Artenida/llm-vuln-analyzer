import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { EmptyState } from "./States";
import "./DataTable.css";

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /**
   * Makes the column sortable. Return null for a missing value — nulls always
   * sort last regardless of direction, so an unanalysed run never floats to the
   * top of a "most findings" sort.
   */
  sortValue?: (row: T) => string | number | null;
  align?: "left" | "right";
  width?: string;
  /** Hides the column below a narrow viewport. */
  secondary?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  initialSort?: { columnId: string; direction: "asc" | "desc" };
  onRowClick?: (row: T) => void;
  /** Marks a row as the current selection. */
  isActive?: (row: T) => boolean;
  empty?: ReactNode;
  dense?: boolean;
}

type SortState = { columnId: string; direction: "asc" | "desc" } | null;

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  initialSort,
  onRowClick,
  isActive,
  empty,
  dense = false,
}: DataTableProps<T>) {
  const [sort, setSort] = useState<SortState>(initialSort ?? null);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const column = columns.find((c) => c.id === sort.columnId);
    if (!column?.sortValue) return rows;
    const factor = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const left = column.sortValue!(a);
      const right = column.sortValue!(b);
      // Nulls last in both directions — see the Column.sortValue note.
      if (left === null && right === null) return 0;
      if (left === null) return 1;
      if (right === null) return -1;
      if (typeof left === "number" && typeof right === "number") {
        return (left - right) * factor;
      }
      return String(left).localeCompare(String(right), undefined, {
        numeric: true,
        sensitivity: "base",
      }) * factor;
    });
  }, [rows, columns, sort]);

  function toggleSort(column: Column<T>) {
    if (!column.sortValue) return;
    setSort((current) => {
      if (current?.columnId !== column.id) {
        // Numbers are almost always most interesting at their largest, so a
        // first click on a numeric column sorts descending.
        const numericFirst = typeof column.sortValue!(rows[0]) === "number";
        return { columnId: column.id, direction: numericFirst ? "desc" : "asc" };
      }
      return {
        columnId: column.id,
        direction: current.direction === "asc" ? "desc" : "asc",
      };
    });
  }

  if (rows.length === 0) {
    return <div className="datatable__empty">{empty ?? <EmptyState />}</div>;
  }

  return (
    <div className="datatable">
      <table className={dense ? "datatable__table datatable__table--dense" : "datatable__table"}>
        <thead>
          <tr>
            {columns.map((column) => {
              const active = sort?.columnId === column.id;
              const sortable = Boolean(column.sortValue);
              return (
                <th
                  key={column.id}
                  style={column.width ? { width: column.width } : undefined}
                  className={[
                    column.align === "right" ? "is-right" : "",
                    column.secondary ? "is-secondary" : "",
                    sortable ? "is-sortable" : "",
                    active ? "is-active" : "",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                  aria-sort={
                    active
                      ? sort!.direction === "asc"
                        ? "ascending"
                        : "descending"
                      : undefined
                  }
                >
                  {sortable ? (
                    <button
                      type="button"
                      className="datatable__sort"
                      onClick={() => toggleSort(column)}
                    >
                      {column.header}
                      <span className="datatable__caret" aria-hidden="true">
                        {active ? (sort!.direction === "asc" ? "▲" : "▼") : "◆"}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr
              key={rowKey(row)}
              className={[
                onRowClick ? "is-clickable" : "",
                isActive?.(row) ? "is-active" : "",
              ]
                .filter(Boolean)
                .join(" ")}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={
                onRowClick
                  ? (event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onRowClick(row);
                      }
                    }
                  : undefined
              }
            >
              {columns.map((column) => (
                <td
                  key={column.id}
                  className={[
                    column.align === "right" ? "is-right" : "",
                    column.secondary ? "is-secondary" : "",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                >
                  {column.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

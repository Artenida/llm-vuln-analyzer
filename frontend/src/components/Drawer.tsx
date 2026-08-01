import { useEffect } from "react";
import type { ReactNode } from "react";
import "./Drawer.css";

/**
 * Right-side detail panel.
 *
 * A panel rather than a full page so the findings table stays visible — you
 * read a finding in the context of the list you are working through.
 */
export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = 720,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  width?: number;
}) {
  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="drawer" role="dialog" aria-modal="true">
      <div className="drawer__backdrop" onClick={onClose} />
      <aside className="drawer__panel" style={{ width }}>
        <header className="drawer__header">
          <div className="drawer__heading">
            <h3 className="drawer__title">{title}</h3>
            {subtitle && <div className="drawer__subtitle">{subtitle}</div>}
          </div>
          <button type="button" className="drawer__close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="drawer__body">{children}</div>
      </aside>
    </div>
  );
}

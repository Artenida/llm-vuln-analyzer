import type { ReactNode } from "react";
import "./Card.css";

interface CardProps {
  title?: ReactNode;
  /** Right-aligned slot in the header — counts, filters, links. */
  actions?: ReactNode;
  /** Explanatory line under the title. Prose, not monospace. */
  description?: ReactNode;
  /** Removes the body padding, for cards whose body is a full-bleed table. */
  flush?: boolean;
  className?: string;
  children: ReactNode;
}

/** The only bordered container in the system. See docs/frontend-plan.md §3.3. */
export function Card({
  title,
  actions,
  description,
  flush = false,
  className = "",
  children,
}: CardProps) {
  const hasHeader = Boolean(title || actions || description);
  return (
    <section className={`card ${className}`}>
      {hasHeader && (
        <header className="card__header">
          <div className="card__heading">
            {title && <h3 className="card__title">{title}</h3>}
            {description && <p className="card__description">{description}</p>}
          </div>
          {actions && <div className="card__actions">{actions}</div>}
        </header>
      )}
      <div className={flush ? "card__body card__body--flush" : "card__body"}>
        {children}
      </div>
    </section>
  );
}

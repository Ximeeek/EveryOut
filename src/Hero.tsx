import type { ReactNode } from "react";
import DotIcon from "./DotIcon";
import type { DotIconName } from "./DotIcon";

export default function Hero({
  meta,
  title,
  description,
  icon = "logout",
  animated = false,
  animateTitle = false,
  children,
}: {
  meta: string;
  title: string;
  description: string;
  icon?: DotIconName;
  animated?: boolean;
  animateTitle?: boolean;
  children?: ReactNode;
}) {
  return (
    <section className="hero" aria-labelledby="flow-title">
      <div className="hero-icon">
        <DotIcon name={icon} size={58} animated={animated} />
      </div>
      <p className="meta">{meta}</p>
      <h1 id="flow-title" tabIndex={-1} aria-live="polite" aria-atomic="true">
        {animateTitle ? (
          <span key={title} className="hero-title-text">
            {title}
          </span>
        ) : (
          title
        )}
      </h1>
      <p className="hero-description">{description}</p>
      {children}
    </section>
  );
}

import { useState, type CSSProperties } from "react";

export default function RollingCount({
  value,
  zeroLabel,
  padded = false,
  previous = value,
}: {
  value: number;
  zeroLabel?: string;
  padded?: boolean;
  previous?: number;
}) {
  const [transition, setTransition] = useState({ from: previous, to: value });
  if (transition.to !== value) {
    setTransition({ from: transition.to, to: value });
  }
  const format = (number: number) =>
    number === 0 && zeroLabel
      ? zeroLabel
      : padded
        ? String(number).padStart(2, "0")
        : String(number);
  const steps = Math.min(Math.abs(transition.to - transition.from), 40);
  const values = steps
    ? Array.from({ length: steps + 1 }, (_, index) =>
        Math.round(
          transition.from + ((transition.to - transition.from) * index) / steps,
        ),
      )
    : [value];
  return (
    <span className="rolling-count" aria-label={format(value)}>
      <span
        key={`${transition.from}-${transition.to}`}
        className="rolling-track"
        aria-hidden="true"
        style={{ "--roll-offset": `${-steps}em` } as CSSProperties}
      >
        {values.map((number, index) => (
          <span key={index}>{format(number)}</span>
        ))}
      </span>
    </span>
  );
}

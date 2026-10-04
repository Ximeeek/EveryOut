import type { CSSProperties } from "react";

const bitmaps = {
  logout: [
    "111100000",
    "100100000",
    "100101000",
    "100100100",
    "100111110",
    "100100100",
    "100101000",
    "100100000",
    "111100000",
  ],
  apps: [
    "111000111",
    "101000101",
    "111000111",
    "000000000",
    "000000000",
    "000000000",
    "111000111",
    "101000101",
    "111000111",
  ],
  browser: [
    "001111100",
    "010010010",
    "100010001",
    "100010001",
    "111111111",
    "100010001",
    "100010001",
    "010010010",
    "001111100",
  ],
  accounts: [
    "000111000",
    "001000100",
    "001000100",
    "000111000",
    "000000000",
    "001111100",
    "010000010",
    "100000001",
    "111111111",
  ],
  check: [
    "000000000",
    "000000001",
    "000000010",
    "000000100",
    "100001000",
    "010010000",
    "001100000",
    "000000000",
    "000000000",
  ],
  attention: [
    "000010000",
    "000111000",
    "001010100",
    "001010100",
    "010010010",
    "010000010",
    "100010001",
    "100000001",
    "111111111",
  ],
  settings: [
    "000010000",
    "001111100",
    "011010110",
    "010000010",
    "111010111",
    "010000010",
    "011010110",
    "001111100",
    "000010000",
  ],
  back: [
    "000000000",
    "000100000",
    "001000000",
    "010000000",
    "111111111",
    "010000000",
    "001000000",
    "000100000",
    "000000000",
  ],
  grid: Array.from({ length: 9 }, () => "111111111"),
} as const;

export type DotIconName = keyof typeof bitmaps;

export default function DotIcon({
  name,
  size = 28,
  animated = false,
  fill = 1,
}: {
  name: DotIconName;
  size?: number;
  animated?: boolean;
  fill?: number;
}) {
  return (
    <svg
      className={`dot-icon${animated ? " dot-animated" : ""}`}
      width={size}
      height={size}
      viewBox="0 0 54 54"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      {bitmaps[name].flatMap((row, y) =>
        [...row].map((pixel, x) =>
          pixel === "1" ? (
            <circle
              key={`${x}-${y}`}
              cx={3 + x * 6}
              cy={3 + y * 6}
              r={1.9}
              opacity={y * 9 + x < fill * 81 ? 1 : 0.15}
              style={{ "--dot-delay": `${(x + y) * 55}ms` } as CSSProperties}
            />
          ) : null,
        ),
      )}
    </svg>
  );
}

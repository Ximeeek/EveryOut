import type { CSSProperties } from "react";
import { motion } from "./motion";

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
  minimize: ["00000", "00000", "00000", "11111", "00000"],
  maximize: ["11111", "10001", "10001", "10001", "11111"],
  restore: ["00111", "00101", "11111", "10100", "11100"],
  close: ["10001", "01010", "00100", "01010", "10001"],
  checkbox: ["11111", "10001", "10001", "10001", "11111"],
  checked: ["11111", "11111", "11111", "11111", "11111"],
  mixed: ["11111", "10001", "11111", "10001", "11111"],
} as const;

export type DotIconName = keyof typeof bitmaps;

export default function DotIcon({
  name,
  size = 28,
  animated = false,
  fill = 1,
  delta,
  deltaCount = 0,
}: {
  name: DotIconName;
  size?: number;
  animated?: boolean;
  fill?: number;
  delta?: "up" | "down" | "same";
  deltaCount?: number;
}) {
  const bitmap = bitmaps[name];
  const grid = bitmap.length;
  const pitch = Math.max(4, Math.round(size / grid));
  const pixels = pitch * grid;
  const diameter = Math.max(2, Math.floor(pitch / 2));
  const offset = Math.floor((pitch - diameter) / 2);
  let litIndex = 0;
  return (
    <svg
      className={`dot-icon${animated ? " dot-animated" : ""}${delta ? ` dot-${delta}` : ""}`}
      width={pixels}
      height={pixels}
      style={
        {
          width: pixels,
          height: pixels,
          "--motion-wave": `${motion.wave}ms`,
          "--motion-settle": `${motion.settle}ms`,
        } as CSSProperties
      }
      viewBox={`0 0 ${pixels} ${pixels}`}
      shapeRendering="crispEdges"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      {bitmap.flatMap((row, y) =>
        [...row].map((pixel, x) => {
          const index = pixel === "1" ? litIndex++ : -1;
          return (
            <rect
              key={`${x}-${y}`}
              x={offset + x * pitch}
              y={offset + y * pitch}
              width={diameter}
              height={diameter}
              opacity={
                pixel === "1"
                  ? y * grid + x < fill * grid * grid
                    ? 1
                    : 0.15
                  : 0
              }
              data-delta-dot={
                index >= 0 && index < deltaCount ? "true" : undefined
              }
              style={
                {
                  transform: animated
                    ? `translate(${((x % 3) - 1) * 2}px, ${((y % 3) - 1) * 2}px)`
                    : "translate(0, 0)",
                  "--dot-delay": `${(delta ? Math.max(0, index) : x + y) * motion.stagger}ms`,
                  "--dot-out-x": `${(x - Math.floor(grid / 2)) * 2}px`,
                  "--dot-out-y": `${(y - Math.floor(grid / 2)) * 2}px`,
                } as CSSProperties
              }
            />
          );
        }),
      )}
    </svg>
  );
}

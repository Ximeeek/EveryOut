import type { CSSProperties } from "react";

export const motion = {
  scanMinimum: 600,
  wave: 1600,
  settle: 650,
  delta: 1800,
  roll: 650,
  stagger: 24,
} as const;

export const motionStyle = Object.fromEntries(
  Object.entries(motion).map(([key, value]) => [
    `--motion-${key}`,
    `${value}ms`,
  ]),
) as CSSProperties;

export async function visibleScan<T>(operation: () => Promise<T>): Promise<T> {
  const [result] = await Promise.allSettled([
    operation(),
    new Promise<void>((resolve) => setTimeout(resolve, motion.scanMinimum)),
  ]);
  if (result.status === "rejected") throw result.reason;
  return result.value;
}

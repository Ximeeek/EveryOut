import { afterEach, expect, it, vi } from "vitest";
import { motion, visibleScan } from "./motion";

afterEach(() => vi.useRealTimers());
it("keeps fast successful scans visible for at least 600 ms", async () => {
  vi.useFakeTimers();
  const finished = vi.fn();
  const scan = visibleScan(async () => "inventory").then(finished);
  await vi.advanceTimersByTimeAsync(motion.scanMinimum - 1);
  expect(finished).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  await scan;
  expect(finished).toHaveBeenCalledWith("inventory");
});
it("does not delay a scan that already took longer than the minimum", async () => {
  vi.useFakeTimers();
  const operation = vi.fn(
    () =>
      new Promise<string>((resolve) =>
        setTimeout(() => resolve("inventory"), 900),
      ),
  );
  const finished = vi.fn();
  const scan = visibleScan(operation).then(finished);
  await vi.advanceTimersByTimeAsync(899);
  expect(finished).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  await scan;
  expect(finished).toHaveBeenCalledWith("inventory");
  expect(operation).toHaveBeenCalledTimes(1);
});
it("also preserves the minimum duration on scan failure", async () => {
  vi.useFakeTimers();
  const failed = vi.fn();
  const scan = visibleScan(async () => {
    throw new Error("scan failed");
  }).catch(failed);
  await vi.advanceTimersByTimeAsync(599);
  expect(failed).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  await scan;
  expect(failed).toHaveBeenCalledWith(
    expect.objectContaining({ message: "scan failed" }),
  );
});

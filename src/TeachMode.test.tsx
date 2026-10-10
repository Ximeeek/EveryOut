import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { isTauri } from "@tauri-apps/api/core";
import { teach } from "./api";
import type { TeachPhase, TeachView } from "./api";
import TeachMode from "./TeachMode";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: vi.fn(() => true) }));
vi.mock("./api", () => ({ teach: vi.fn() }));
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(isTauri).mockReturnValue(true);
});

it("guides explicit phases and sends session state only, with no cleanup operation", async () => {
  const user = userEvent.setup();
  let view: TeachView = {
    id: "session-1",
    application: "TotallyUnknownApp.exe",
    stage: "discovering",
    next_phase: null,
    completeness: "complete",
    candidate_roots: [],
    completed_cycles: 0,
    diagnostics: [],
    result: null,
  };
  const phases: TeachPhase[] = [
    "launch-logged-out",
    "login",
    "settled-logged-in",
    "restart-persistence",
    "vendor-logout",
    "closed-logged-out",
  ];
  vi.mocked(teach).mockImplementation(async (request) => {
    if (request.operation === "history") return { kind: "history", data: [] };
    if (request.operation === "discover")
      view = {
        ...view,
        stage: "ready",
        candidate_roots: ["C:/Local/SomeVendor"],
      };
    if (request.operation === "begin-cycle")
      view = { ...view, stage: "focused", next_phase: phases[0] };
    if (request.operation === "advance")
      view = {
        ...view,
        next_phase: phases[phases.indexOf(view.next_phase!) + 1] ?? null,
      };
    if (request.operation === "finish")
      view = { ...view, stage: "finished", next_phase: null };
    return { kind: "view", data: view };
  });
  render(<TeachMode disabled={false} />);
  expect(
    screen.getByText(
      /does not read passwords, tokens, cookies or database contents/,
    ),
  ).toBeVisible();
  await user.type(
    screen.getByLabelText("Application executable path"),
    "C:\\Apps\\TotallyUnknownApp.exe",
  );
  await user.click(screen.getByRole("button", { name: "Start discovery" }));
  await user.click(
    await screen.findByRole("button", { name: "Finish discovery now" }),
  );
  await user.click(
    await screen.findByRole("button", { name: "Capture closed baseline" }),
  );
  for (const phase of phases.slice(0, 3)) {
    await user.click(
      await screen.findByRole("button", { name: "Confirm state and continue" }),
    );
    expect(vi.mocked(teach).mock.calls.at(-1)?.[0]).toEqual({
      operation: "advance",
      id: "session-1",
      signed_in: phase !== "launch-logged-out",
    });
  }
  await user.click(
    await screen.findByRole("button", { name: "Not signed in" }),
  );
  expect(vi.mocked(teach).mock.calls.at(-1)?.[0]).toEqual({
    operation: "advance",
    id: "session-1",
    signed_in: false,
  });
  await user.click(
    screen.getByRole("button", { name: "Finish and save observation" }),
  );
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: "Finish and save observation" }),
    ).not.toBeInTheDocument(),
  );
  expect(
    vi
      .mocked(teach)
      .mock.calls.every(([request]) =>
        [
          "history",
          "start",
          "discover",
          "get",
          "begin-cycle",
          "advance",
          "finish",
        ].includes(request.operation),
      ),
  ).toBe(true);
});
it("disables native observation in browser previews", () => {
  vi.mocked(isTauri).mockReturnValue(false);
  render(<TeachMode disabled={false} />);
  expect(
    screen.getByRole("button", { name: "Start discovery" }),
  ).toBeDisabled();
  expect(teach).not.toHaveBeenCalled();
});

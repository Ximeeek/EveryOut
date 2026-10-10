import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { validation } from "./api";
import type {
  LearnedObservation,
  ValidationStatus,
  ValidationView,
} from "./api";
import observation from "../docs/architecture/examples/learned-observation.json";
import ControlledValidation from "./ControlledValidation";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true }));
vi.mock("./api", () => ({ validation: vi.fn() }));
const status: ValidationStatus = {
  recovery_required: false,
  pending_sessions: [],
  diagnostics: [],
  rules: [],
  active: null,
};
const learned = observation as unknown as LearnedObservation;
const view: ValidationView = {
  id: "validation-id",
  stage: "control",
  scope: [{ root: learned.roots[0].root, family: "local storage" }],
  trials: [],
  diagnostics: [],
  rule: null,
};
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(validation).mockResolvedValue({ kind: "status", data: status });
});
it("starts only with session policy and submits outcomes without paths or ownership assertions", async () => {
  const user = userEvent.setup();
  vi.mocked(validation).mockImplementation(async (request) =>
    request.operation === "status"
      ? { kind: "status", data: status }
      : { kind: "view", data: view },
  );
  render(<ControlledValidation disabled={false} observations={[learned]} />);
  const start = screen.getByRole("button", {
    name: "Start controlled validation",
  });
  expect(start).toBeDisabled();
  await user.selectOptions(
    screen.getByLabelText("Saved complete observation"),
    learned.session_id,
  );
  expect(start).toBeDisabled();
  await user.click(
    screen.getByRole("checkbox", { name: /I accept temporary moves/ }),
  );
  await user.click(start);
  expect(vi.mocked(validation).mock.calls.at(-1)?.[0]).toEqual({
    operation: "start",
    observation_id: learned.session_id,
    accept_session_policy: true,
  });
  await user.click(await screen.findByRole("button", { name: "Unclear" }));
  expect(vi.mocked(validation).mock.calls.at(-1)?.[0]).toEqual({
    operation: "outcome",
    id: view.id,
    outcome: "unclear",
  });
  expect(screen.getByRole("button", { name: "Signed in" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Signed out" })).toBeVisible();
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
});
it("shows interrupted sessions and keeps new validation blocked until recovery", async () => {
  const user = userEvent.setup();
  vi.mocked(validation).mockResolvedValue({
    kind: "status",
    data: {
      ...status,
      recovery_required: true,
      pending_sessions: ["interrupted"],
    },
  });
  render(<ControlledValidation disabled={false} observations={[learned]} />);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "All cleanup and new validation are blocked",
  );
  expect(
    screen.queryByRole("button", { name: "Start controlled validation" }),
  ).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Retry recovery" }));
  expect(vi.mocked(validation).mock.calls.at(-1)?.[0]).toEqual({
    operation: "recover",
  });
});
it("does not offer a shared or incomplete observation as a validation input", () => {
  const shared = structuredClone(learned);
  shared.roots[0].ownership.state = "shared-conflict";
  const incomplete = structuredClone(learned);
  incomplete.completeness = "incomplete";
  render(
    <ControlledValidation
      disabled={false}
      observations={[shared, incomplete]}
    />,
  );
  expect(screen.getAllByRole("option")).toHaveLength(1);
  expect(
    screen.getByRole("button", { name: "Start controlled validation" }),
  ).toBeDisabled();
});

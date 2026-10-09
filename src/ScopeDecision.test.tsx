import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import ScopeDecision from "./ScopeDecision";
import { demoDecision } from "./demoFixtures";

it("renders the backend decision and individual safety blockers without inferring permission", () => {
  const decision = demoDecision();
  decision.action_allowed = false;
  decision.blocked_by = [
    "unknown-authentication-closure",
    "unreviewed-preservation",
    "unvalidated-product-version",
  ];
  render(<ScopeDecision decision={decision} />);
  expect(
    screen.getByText("The login scope has not been validated."),
  ).toBeVisible();
  expect(
    screen.getByText("Preservation effects have not been reviewed."),
  ).toBeVisible();
  expect(
    screen.getByText("The current product version has not been validated."),
  ).toBeVisible();
  expect(screen.queryByText(/can proceed after/)).not.toBeInTheDocument();
  expect(screen.getByText(/Accepting data loss does not remove/)).toBeVisible();
});
it("explains version revalidation and keeps full provenance in technical details", () => {
  const decision = demoDecision();
  decision.action_allowed = false;
  decision.evidence.version_applicability.state = "stale";
  decision.blocked_by = ["product-version-revalidation-required"];
  render(<ScopeDecision decision={decision} />);
  expect(screen.getByText("Needs revalidation")).toBeVisible();
  expect(
    screen.getByText("The application changed and needs revalidation."),
  ).toBeVisible();
  expect(screen.getByText(/"source": "synthetic-fixture"/)).toBeInTheDocument();
});

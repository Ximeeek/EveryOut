import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import CatalogUpdates from "./CatalogUpdates";
import * as api from "./api";

vi.mock("./api", () => ({
  checkCatalogUpdates: vi.fn(),
  activateCatalogUpdate: vi.fn(),
}));
const settings = {
  account_mode: "current" as const,
  process_close_policy: "ask" as const,
  first_run_completed: true,
};
beforeEach(() => vi.resetAllMocks());
it("checks only on request, renders inert changelog and activates only on acceptance", async () => {
  const user = userEvent.setup();
  const invalidate = vi.fn();
  const setBusy = vi.fn();
  vi.mocked(api.checkCatalogUpdates).mockResolvedValue({
    installed_version: "1",
    proposed_version: "2",
    digest: "verified-digest",
    changelog: "<script>untrusted text</script>",
    error: null,
    helper_compatible: true,
  });
  vi.mocked(api.activateCatalogUpdate).mockResolvedValue({
    installed_version: "2",
    proposed_version: null,
    digest: null,
    changelog: null,
    error: null,
    helper_compatible: false,
  });
  render(
    <CatalogUpdates
      settings={settings}
      busy={false}
      setBusy={setBusy}
      invalidate={invalidate}
    />,
  );
  expect(api.checkCatalogUpdates).not.toHaveBeenCalled();
  await user.click(
    screen.getByRole("button", { name: "Check for catalog updates" }),
  );
  expect(
    await screen.findByText("<script>untrusted text</script>"),
  ).toBeInTheDocument();
  expect(document.querySelector("script")).toBeNull();
  expect(invalidate).toHaveBeenCalledTimes(1);
  expect(api.activateCatalogUpdate).not.toHaveBeenCalled();
  await user.click(
    screen.getByRole("button", { name: "Accept catalog update" }),
  );
  expect(
    await screen.findByText("Catalog accepted. Scan again before any cleanup."),
  ).toBeInTheDocument();
  expect(api.activateCatalogUpdate).toHaveBeenCalledWith("verified-digest");
  expect(invalidate).toHaveBeenCalledTimes(2);
  expect(
    screen.getByText(/compatible helper application release/),
  ).toBeInTheDocument();
});
it("shows configuration failures without an acceptance button", async () => {
  vi.mocked(api.checkCatalogUpdates).mockResolvedValue({
    installed_version: "1",
    proposed_version: null,
    digest: null,
    changelog: null,
    error: "catalog-unconfigured",
    helper_compatible: true,
  });
  render(
    <CatalogUpdates
      settings={settings}
      busy={false}
      setBusy={vi.fn()}
      invalidate={vi.fn()}
    />,
  );
  await userEvent
    .setup()
    .click(screen.getByRole("button", { name: "Check for catalog updates" }));
  expect(await screen.findByText(/not configured/)).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Accept catalog update" }),
  ).toBeNull();
});

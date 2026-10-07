import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import RollingCount from "./RollingCount";

it("rolls through intermediate values while exposing only the target count", () => {
  const { rerender, container } = render(<RollingCount value={2} />);
  rerender(<RollingCount value={5} />);
  expect(screen.getByLabelText("5")).toBeInTheDocument();
  expect(container.querySelector(".rolling-track")?.textContent).toBe("2345");
  rerender(<RollingCount value={3} />);
  expect(container.querySelector(".rolling-track")?.textContent).toBe("543");
  expect(screen.getByLabelText("3")).toBeInTheDocument();
});

it("starts with the actual selection on mount and rolls from No on selection", () => {
  const { rerender, container } = render(
    <RollingCount value={0} zeroLabel="No" padded />,
  );
  rerender(<RollingCount value={2} zeroLabel="No" padded />);
  expect(container.querySelector(".rolling-track")?.textContent).toBe("No0102");
  expect(screen.getByLabelText("02")).toBeInTheDocument();
});

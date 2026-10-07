import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(cleanup);
// Allow the deliberate 600 ms scan floor plus concurrent jsdom startup/rendering.
configure({ asyncUtilTimeout: 2000 });

// jsdom does not implement native modal/top-layer behavior.
HTMLDialogElement.prototype.showModal = function () {
  this.open = true;
};
HTMLDialogElement.prototype.close = function () {
  this.open = false;
};

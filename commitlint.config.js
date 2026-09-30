export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "docs",
        "style",
        "refactor",
        "perf",
        "test",
        "build",
        "ci",
        "chore",
        "revert",
      ],
    ],
    "scope-empty": [2, "never"],
    "header-max-length": [2, "always", 72],
    "body-empty": [2, "never"],
    "body-min-length": [2, "always", 20],
  },
};

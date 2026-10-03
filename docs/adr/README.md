# Architecture Decision Records

Architecture Decision Records (ADRs) capture decisions that shape EveryOut's design and
development. Keep each record concise, explain context and consequences, and link related records
when a decision changes.

## Numbering and files

Use the next available four-digit number, starting with `0000` for the template. Name records
`NNNN-short-kebab-case-title.md`. Never reuse a number, including when a proposal is rejected.
Copy [the template](0000-template.md) for each new decision.

## Statuses

- **Proposed**: open for discussion; not yet a project commitment.
- **Accepted**: approved and treated as the current decision.
- **Superseded**: replaced by a later accepted ADR; link to its number.

Update this index when adding or superseding a record. Preserve old records so the decision
history remains clear.

## Records

| Number                                                 | Title                                                              | Status   |
| ------------------------------------------------------ | ------------------------------------------------------------------ | -------- |
| [0001](0001-license.md)                                | License the project under GNU GPL version 3 or later               | Accepted |
| [0002](0002-retain-tauri-rust-stack.md)                | Retain Tauri 2.x with a Rust system layer                          | Accepted |
| [0003](0003-rust-command-capability-boundary.md)       | Keep critical operations behind scoped Rust commands               | Accepted |
| [0004](0004-windows-metadata-and-deletion-bindings.md) | Use official Windows bindings for object-bound platform operations | Accepted |
| [0005](0005-code-signing.md)                           | Prefer conditional Foundation signing for public releases          | Proposed |

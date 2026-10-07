# EveryOut UI revision 2 evidence

All images use the development browser adapter with simulated data. No real
cleanup, program closure or administrator request ran during these checks.

| Device scale | Overview                      | Magnified icons                              |
| ------------ | ----------------------------- | -------------------------------------------- |
| 100%         | [Overview](overview-1.png)    | [Logo, primary action, Apps](icons-1.png)    |
| 125%         | [Overview](overview-1-25.png) | [Logo, primary action, Apps](icons-1-25.png) |
| 150%         | [Overview](overview-1-5.png)  | [Logo, primary action, Apps](icons-1-5.png)  |

Icon crops are enlarged with nearest-neighbor sampling so raster edges remain
visible. Integer dot geometry and crisp-edge rasterization keep the three problem
icons sharp at each scale. The primary action has no dark icon disc.

[Compact overview](overview-compact.png) uses 640 by 480 logical pixels at 125% and
has no horizontal overflow. The large hero icon hides at this short height to keep
the controls visible; all category and action icons retain their original extents.

[Scanning](scanning.png) captures the continuous wave. [Rescan deltas](rescan-deltas.png)
shows an Apps increase, a Browsers decrease and unchanged Windows/dev detections.
[Reduced motion](rescan-reduced-motion.png) shows the same pills with instant final
counts. Browser checks verified that the pills disappear, the scanning wave runs,
and reduced motion has no running animations.

[Stable rescan](stable-rescan.png) keeps the selection counter, descriptions,
category icons and primary action in place while the main glyph and heading
animate. [No change feedback](no-change-pill.png) shows neutral capsules with a
pulsing indicator. Both use selectable medium-confidence known providers; browser
checks verified that category toggles work and unchecked choices survive rescan.

Keyboard checks at all three scales cleared categories using Space/Enter, moved
focus with arrow keys, disabled the primary action for an empty selection, restored
selection and opened the deliberate confirmation without opening settings.

The native window check was interrupted with Escape. Dragging, double-click
maximize, edge resizing, Alt+F4 and Win+Arrow still need manual native validation.
Window-command wiring, capability restrictions and native compilation pass.
The Windows 11 maximize-button Snap Layout flyout is intentionally unavailable.

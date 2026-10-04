# EveryOut antivirus and EDR reports

## Report safely

EveryOut's security contract prohibits reading, copying, decrypting or transmitting session
secrets; the wipe itself must remain offline. This is a design requirement, not a security
certification. Binary/helper integrity checks are distinct from accessing session secrets.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/docs/architecture/10-threat-model.md, accessed 2026-10-03]

Use the [false_positive_report issue form](https://github.com/Ximeeek/EveryOut/issues/new?template=false_positive_report.yml)
for a suspected antivirus/EDR misclassification. The form asks for vendor/product, detection
name, EveryOut version, file SHA-256 and Windows version; a safe scan-report link is optional.
It prohibits uploading executables or secrets.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/.github/ISSUE_TEMPLATE/false_positive_report.yml, accessed 2026-10-03]

Also provide, after removing personal information, the exact release asset/source URL, alert
time, security-product/engine/definition versions, catalog version, signature status and whether
the alert occurred during download, install, launch, scan or reviewed cleanup. Supply a redacted
alert screenshot only if it reveals no account names, paths or secrets. Prefer synthetic
reproduction steps. These are project reporting requirements, not additions to the existing form.
[HYPOTHESIS]

Do not attach profiles, cookies, token/credential stores, backups, dumps or arbitrary diagnostic
logs. Do not disable antivirus, add exclusions or elevate solely to bypass a block. If the alert
suggests actual secret access, unexpected networking or compromise, use the private
[security reporting and coordinated disclosure procedure](../../SECURITY.md#coordinated-disclosure).
Treat the cause as unresolved until investigated. [HYPOTHESIS]

## Maintainer triage and evidence bundle

1. Compare the reported SHA-256 with the exact published file. For mismatches, investigate
   tampering, wrong downloads or build differences before calling the detection a false positive.
2. Distinguish a malware/PUA verdict, SmartScreen's low-reputation warning and an intentional EDR
   access-policy block. Microsoft explicitly separates SmartScreen from Defender Antivirus.
   [VERIFIED: https://learn.microsoft.com/en-us/defender-xdr/developer-faq, accessed 2026-10-03]
3. Reproduce only in a disposable snapshot VM with synthetic session fixtures. Record the
   detected file, app/catalog version, Windows/security-product versions, alert class and sanitized
   steps. Retain the exact release artifact without rebuilding/re-signing it for submission.
4. Assemble the SHA-256, filename/version, publisher/chain/timestamp status, source commit and
   CI/release URL. Prefer the affected signed release; if unsigned, state that explicitly. Include
   the precise triggering action and user-visible purpose, not only a general claim of safety.
5. Include a source link and a commit-specific
   [threat model](../architecture/10-threat-model.md). State: “EveryOut's design prohibits reading,
   copying, decrypting or transmitting secrets. Reviewed wiping deletes only approved local
   session targets; discovery and reports use permitted metadata.” Verify this explanation against
   the affected build. Explain optional elevation and user-requested catalog networking honestly.
6. If source review or evidence indicates malicious modification or a real vulnerability, pause
   distribution and follow SECURITY.md; do not request allowlisting of a compromised file.

The numbered actions are maintainer policy. Their effectiveness and each report's eventual
verdict are unverified. [HYPOTHESIS]

## Microsoft submission

The [Microsoft Security Intelligence submission portal](https://www.microsoft.com/en-us/wdsi/filesubmission)
provides a **Software developer** route and choices for the affected Microsoft product and
incorrect malware/PUA detection. It supports file submission and tracking with a Microsoft account.
[VERIFIED: https://www.microsoft.com/en-us/wdsi/filesubmission, accessed 2026-10-03]

The maintainer must sign in, select Software developer, select the actual affected product and
incorrect-detection category, upload only the clean release file that triggered the alert, and
provide the evidence above in English. Follow the live form's size/archive instructions; never
upload user session files. Save the submission ID and link privately, and add only sanitized
status to the public issue. These are project handling instructions. [HYPOTHESIS]

Microsoft instructs developers to wait for a final determination before disputing it through
the developer contact form linked from the result. It does not provide a developer preapproval
or false-positive-prevention program.
[VERIFIED: https://learn.microsoft.com/en-us/defender-xdr/developer-faq, accessed 2026-10-03]

A Microsoft malware-review submission must not be described as guaranteed consumer SmartScreen
reputation clearance. Current SmartScreen documentation says consumer reputation builds
organically; enterprise administrators can submit for managed-deployment review.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03]

## Other vendors and managed-device blocks

| Vendor / case                     | Official route and procedure                                                                                                                                                                                                                                                                                                                                               |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ESET file verdict                 | Follow KB141: archive the affected binary with the documented password `infected`, identify a false positive (or PUA false positive) in the subject, include background and alert evidence, and submit to `samples@eset.com`. [VERIFIED: https://support.eset.com/en/kb141-submit-a-virus-website-or-potential-false-positive-sample-to-the-eset-lab, accessed 2026-10-03] |
| Norton file or URL                | Use Norton's official file/URL review instructions for the exact verdict type. [VERIFIED: https://support.norton.com/sp/en/us/home/current/solutions/kb20090410134005EN, accessed 2026-10-03]                                                                                                                                                                              |
| Other antivirus                   | Identify the vendor's official false-positive/sample portal, verify its current instructions and privacy terms, then submit only the affected release binary and sanitized evidence. Record the vendor URL and access date in the case. [HYPOTHESIS]                                                                                                                       |
| Managed EDR behavior/policy block | Ask the device administrator to investigate the event and open the vendor's enterprise support case. A sample verdict change may not change an organization's access policy; do not recommend exclusions or protection bypass. [HYPOTHESIS]                                                                                                                                |

The maintainer performs submissions personally. Adapt the evidence bundle to each vendor's
attachment/link restrictions, never attach personal logs, and request a secure official channel
for oversized release artifacts rather than splitting user data into samples. [HYPOTHESIS]

## Timelines, closure and monitoring

No general Microsoft review SLA or universal AV/EDR clearance time is established by this
research. Do not promise a response within hours or days. ESET documents an urgent follow-up
after three unresolved days; this is an escalation instruction, not a guaranteed resolution time.
[VERIFIED: https://support.eset.com/en/kb141-submit-a-virus-website-or-potential-false-positive-sample-to-the-eset-lab, accessed 2026-10-03]
[HYPOTHESIS]

Track suspected, reproduced, submitted, vendor-confirmed and retested states. Record the exact
file hash, verdict date and definition/product versions when retesting. Close only after documenting
the result; a changed verdict for one product/hash does not establish clearance for other releases
or vendors. Monitor new reports after each release and preserve blocked/partial wipe outcomes.
If withdrawing an asset, publish an explicit advisory and replacement version rather than silently
replacing its bytes. These are maintainer policy obligations. [HYPOTHESIS]

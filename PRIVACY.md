# Privacy Policy and Collection Scope

Minecraft SS Forensics is a local Windows forensic utility. A normal scan is read-only and stores no results externally. The GUI requires explicit consent before starting a scan; headless CLI scans require the `--consent` acknowledgement. Neither grants administrator rights or installs services/drivers.

## Local collection

Depending on consent scope and source availability, the scanner may inspect:

- Minecraft installation directories and immediate `mods` contents, launcher/config/log evidence supported by enabled collectors, mod archive metadata, and file hashes.
- A targeted set of currently running launcher, Java/Minecraft, and known-named processes. Minecraft attribution requires a supported client process name or Java command-line launch markers. Available process metadata includes PID, start time, image path/hash, parent PID/name, redacted command line, architecture, and loaded modules.
- Loaded module paths, base address, size, hash (when accessible), file metadata, and Windows Authenticode trust result. Module and memory visibility depends on Windows permissions and process architecture.
- Supported historical Windows artifacts and selected registry/service/driver records. They are best-effort sources, not complete execution logs.
- Bounded executable/archive file discovery in selected user staging locations and Recycle Bin metadata.
- USB storage device records. A USBSTOR entry is not proof that a device was used for cheating.

The scanner does not read raw process memory into reports or transmit inventories. Memory inspection is limited to a read-only heuristic check of private executable regions for a PE `MZ` header. It is not comprehensive injection detection.

## Optional sensitive data and network behavior

- Browser-history inspection is off by default and requires the separate GUI checkbox or CLI `--browser` option. It copies selected Chromium history databases to a temporary directory, queries only known domain matches, and deletes its temporary copies on completion where possible. Results can indicate a URL match only; they do not prove download, execution, or cheating.
- Online mod hash verification is opt-in in the GUI. CLI mode disables online verification. If enabled in the GUI, the application contacts configured public verification providers for file hash lookups; it does not upload files or raw memory.
- No analytics, telemetry, account service, or remote report upload is implemented. Exported HTML reports are self-contained and do not require external web requests.

## Report privacy

Exported JSON, HTML and Markdown are sanitized copies. User profile directory components and common command-line secrets are redacted; machine and account identifiers are replaced with placeholders. The source report held in memory is not changed by export. CSV applies path/command-line redaction to findings. Review every report before sharing: arbitrary text/artifact content may include personal data not covered by a specific redaction rule.

Report SHA-256 integrity detects payload changes relative to the embedded digest; it does not authenticate the collector, prove the original machine, or establish chain of custody.

## Permissions

The application does not silently elevate. Standard-user access is sufficient for many user-profile and process checks. Windows may deny access to protected processes, other users' data, event logs, Prefetch, registry hives, services, drivers, or module details. Such outcomes should be reported as unavailable, partial, skipped, or permission denied and are not evidence of deletion or tampering. Administrator execution may expose additional OS-protected artifacts, but is optional and must be chosen by the user.

## Data not intentionally collected

The scanner does not intentionally collect personal documents, photos, credentials, saved passwords, browser cookies, keystrokes, screen/audio/video recordings, or full browsing history. It does not inspect unrelated process memory or upload personal files.

## Retention

Reports are saved only to the user-selected local destination. Temporary browser-history copies are removed on a best-effort basis after querying. The user controls report retention and sharing.

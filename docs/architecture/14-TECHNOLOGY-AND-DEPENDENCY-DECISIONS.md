# 14 — Technology Stack, Dependencies & Trade-Off Decisions

**Platform Name**: Minecraft SS Forensics  
**Document Status**: Official Architecture Specification  
**Version**: 3.0.0-DRAFT  
**Author**: Principal Software Systems Architect  
**Classification**: Technology Strategy & Dependency Governance  

---

## 1. Current Technology Inventory & Baseline

`[VERIFIED]` The current platform is built on the following technological foundation:

| Technology Component | Current Version / Implementation | Role in System | Justification & Verification Status |
| :--- | :--- | :--- | :--- |
| **Runtime & SDK** | .NET 8.0 LTS (`net8.0-windows`) | Master application framework | High-performance managed runtime with native Windows interop, single-file compilation, and long-term support. |
| **UI Framework** | Windows Presentation Foundation (WPF) | Desktop GUI for Scanner & Viewer | Native Windows desktop UI, GPU-accelerated rendering, rich vector graphics, zero web-view overhead. |
| **P/Invoke Win32 Interop** | Hand-crafted P/Invoke in `ProcessScanner`, `PrefetchParser` | Low-level OS telemetry collection | Direct access to native Win32 APIs (`psapi.dll`, `kernel32.dll`, `wintrust.dll`, `ntdll.dll`). |
| **Database Library** | `Microsoft.Data.Sqlite` v10.0.14 | Reading browser history databases | In-memory read-only parsing of Chromium SQLite history files. |
| **WMI Management** | `System.Management` v10.0.14 | Process command-line extraction | Fallback query mechanism for retrieving process command lines and JVM arguments. |
| **Event Logging** | `System.Diagnostics.EventLog` v8.0.0 | Querying Windows Event 7045 | Reads Windows System Event Log for kernel driver service installations. |
| **Test Framework** | `xUnit` v2.5.3 + VSTest | Unit and scenario test execution | Industry standard .NET test runner; 91 passing automated tests. |

---

## 2. Evaluation of Proposed Technologies & Architectural Trade-Offs

### Decision 1: Managed .NET 8.0 vs Native C++ / Rust
- **Proposal**: Retain .NET 8.0 LTS as the core development language; do not rewrite in C++ or Rust.
- **Alternatives Evaluated**: C++20 (MSVC), Rust (x86_64-pc-windows-msvc).
- **Trade-Off Analysis**:
  - *Native C++*: Offers smaller initial binary size, but introduces severe memory safety risks (buffer overflows, UAF) in complex ZIP and SQLite parsing. Writing secure bytecode and manifest parsers in C++ requires significantly higher engineering effort.
  - *Rust*: Memory-safe, excellent performance, but lacks native WPF GUI tooling (requiring sluggish webview wrappers like Tauri or immature GUI crates like Slint/Iced).
  - *.NET 8.0*: Provides memory safety, built-in cryptographic primitives, native Win32 P/Invoke, rich WPF UI, and single-file self-contained publishing (`PublishSingleFile=true`).
- **Architectural Verdict**: `[ACCEPTED]` **Retain .NET 8.0 LTS.**

### Decision 2: In-Memory Graph Storage vs Embedded Graph DB
- **Proposal**: Implement a lightweight in-memory Directed Graph structure (`AdjacencyListGraph<TEntity, TRelationship>`) rather than embedding a heavyweight graph database engine (like Neo4j or RocksDB).
- **Alternatives Evaluated**: Embedded SQLite with recursive CTEs, LiteDB, RocksDB.
- **Trade-Off Analysis**:
  - An inspection session typically discovers 500–5,000 entity nodes and 1,000–10,000 edges.
  - A managed in-memory C# data structure handles this scale in less than $15\text{ MB}$ of heap RAM, with traversal queries executing in sub-millisecond times ($O(V + E)$).
  - Introducing an external database engine adds binary bloat, file locking headaches, and unneeded complexity.
- **Architectural Verdict**: `[ACCEPTED]` **Lightweight In-Memory Adjacency Graph.**

### Decision 3: Standalone Self-Contained Binary vs Modular DLL Bundle
- **Proposal**: Publish the scanner as a single-file, self-contained executable with native libraries bundled (`IncludeNativeLibrariesForSelfExtract=true`).
- **Alternatives Evaluated**: Multi-file ZIP archive with separate `.dll` dependencies.
- **Trade-Off Analysis**:
  - *Multi-file ZIP*: Requires players to extract an archive before running; non-technical users frequently run directly from inside the ZIP, corrupting relative paths.
  - *Single-File Bundle*: Single double-click execution for players; enables simple one-line PowerShell launcher commands; simplifies cryptographic hash verification.
- **Architectural Verdict**: `[ACCEPTED]` **Single-File Self-Contained Executable.**

---

## 3. Dependency Governance & Supply Chain Security

To protect the platform from supply chain compromises:
1. **Minimal External NuGets**: The solution restricts external package dependencies to official Microsoft packages (`Microsoft.Data.Sqlite`, `System.Management`, `System.Diagnostics.EventLog`). Zero third-party unvetted NuGet packages are permitted in the core engine.
2. **Deterministic NuGet Restore**: Uses locked package versions with SHA-512 package hash verification via `packages.lock.json`.
3. **Reproducible Compilation**: Builds are configured with `Deterministic=true` to guarantee that identical source code produces identical binary hashes when compiled under the same SDK version.

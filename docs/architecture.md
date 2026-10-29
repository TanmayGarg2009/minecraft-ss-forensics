# System Architecture — Stage 1

## Overview
Minecraft Screenshare (SS) Forensics is a consent-based, high-integrity reporting system designed for Minecraft anti-cheat investigations and competitive verification. Stage 1 implements the backend ingestion API, relational database models, cryptographic bearer-link access engine, raw evidence abstraction, and browser dashboard viewer.

```mermaid
flowchart TD
    subgraph FutureAgent["Stage 2: Windows Native Scanner"]
        EXE["Scanner Executable (Win 10/11)"]
        Consent["Explicit Player Consent (v1.0)"]
    end

    subgraph BackendAPI["Stage 1: ASP.NET Core 8 Web API"]
        RateLimit["Rate Limiting & Size Gate (15MB max)"]
        Validator["Strict Schema & XSS Validator"]
        ReportSvc["Report Ingestion Service"]
        IdGen["144-bit Cryptographic ID Generator"]
        Hmac["HMAC-SHA256 Deletion Key Hasher"]
        CleanupService["Background Retention Purge (Hourly)"]
    end

    subgraph DataStore["Data & Evidence Storage"]
        DB[("PostgreSQL / SQLite (EF Core)")]
        Disk[("Abstract Evidence Store (App_Data / S3)")]
    end

    subgraph Dashboard["Stage 1: React 18 + Vite Report Viewer"]
        Staff["Server Staff / Anti-Cheat Teams"]
        Viewer["Browser Report Viewer (Bearer URL)"]
        DeleteFlow["Player Deletion Portal"]
    end

    EXE -->|1. Submit JSON Payload| RateLimit
    RateLimit --> Validator
    Validator --> ReportSvc
    ReportSvc --> IdGen
    ReportSvc --> Hmac
    ReportSvc --> DB
    ReportSvc --> Disk
    ReportSvc -->|2. Return Share URL & Deletion Key| EXE
    EXE -->|3. Player sends share URL to staff| Staff
    Staff -->|4. Access /report/mc_... (No Login)| Viewer
    Viewer -->|5. Query Public Report| BackendAPI
    EXE -.->|6. Optional Player Deletion| DeleteFlow
    DeleteFlow -->|7. DELETE with DeletionKey| BackendAPI
    CleanupService -->|8. Automatic Expired Report Purge| DB
    CleanupService -->|8. Remove Expired Raw Evidence| Disk
```

---

## Architectural Principles & Boundaries

### 1. Ingestion Boundary
- The scanner client communicates with the backend solely over HTTPS via the REST contract defined in `docs/stage-2-agent-contract.md`.
- No client-controlled arbitrary file paths are used on the server filesystem.
- All requests are checked for:
  - Max body size: 15 MB.
  - Allowed schema version: `1.0.0`.
  - Player consent confirmation: `ConsentConfirmation.ConsentGiven == true`. Submissions without consent are strictly rejected (HTTP 400).
  - Cross-Site Scripting (XSS) prevention: strings containing executable script tokens (`<script>`, `javascript:`, event handlers) are rejected.
  - Strict enum validation for severities, categories, and confidence levels.

### 2. Bearer-Link Access Model
- Reports are publicly accessible to anyone possessing the complete unguessable identifier URL (`/report/mc_<random144bit>`).
- No staff accounts or authentication walls are required for Stage 1. This prevents account management overhead, session hijacking, or database credential leaks during time-critical investigations.
- **Privacy Protections**:
  - URLs cannot be enumerated (144-bit entropy using cryptographically secure random number generators).
  - Report responses set `Cache-Control: no-store, no-cache, must-revalidate` to avoid proxy caching.
  - Automatic expiration (default 7 days, configurable up to 30 days) ensures reports do not linger indefinitely.
  - Full reports and evidence bodies are excluded from server operational logs.

### 3. Deletion Credential Security
- When a report is ingested, a 256-bit secret `DeletionKey` (e.g. `del_<64hex>`) is generated.
- The plaintext `DeletionKey` is returned **only once** in the ingestion response to the submitting scanner.
- The server stores only an HMAC-SHA256 hash of this key computed with a server-side salt.
- Neither the deletion key nor its hash is ever included in the public GET report response or shareable URL.
- When deleting a report, constant-time comparison (`CryptographicOperations.FixedTimeEquals`) is used to resist timing side-channel attacks.

### 4. Storage Abstraction
- **Structured Data**: Report metadata, findings, timeline events, and diagnostic records are modeled in Entity Framework Core and stored in PostgreSQL in production, with SQLite supported for zero-dependency local development and automated testing.
- **Raw Evidence Payloads**: Large raw dumps (Prefetch headers, USN journal slices, loaded module lists) are abstracted behind `IStorageService`. The Stage 1 implementation writes to a sanitized local directory with path-traversal prevention. This abstraction can be swapped with AWS S3, Azure Blob, or MinIO without modifying the domain layer.

---

## Component Separation

| Component | Technology | Responsibility |
| :--- | :--- | :--- |
| **Backend API** | ASP.NET Core 8 Web API (C#) | Ingestion validation, rate limiting, cryptographic token generation, evidence storage, query endpoints, security middleware, and background retention cleanup. |
| **Database** | PostgreSQL (EF Core / Npgsql) + SQLite | Relational schema, indices on `PublicId`, cascade deletion of report children, expiration queries. |
| **Storage Abstraction** | `IStorageService` (LocalEvidenceStorageService) | Path-traversal-safe storage of raw forensic text dumps and structured logs. |
| **Frontend Viewer** | React 18, TypeScript, Vite, Tailwind CSS | High-density forensic dashboard, multi-axis search and filter, timeline visualization, print stylesheet, JSON export, and deletion workflow. |
| **Demo Laboratory** | React Synthetic Presets | Embedded sandbox with realistic synthetic scenarios (Clean Player, Autoclicker/USN, Process Injection) for testing without a physical Windows scanner. |

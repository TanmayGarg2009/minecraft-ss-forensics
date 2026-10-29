export interface SyntheticPreset {
  id: string;
  name: string;
  subtitle: string;
  payload: any;
}

export const SYNTHETIC_PRESETS: SyntheticPreset[] = [
  {
    id: 'clean-player',
    name: 'Clean Competitive Player',
    subtitle: 'Zero detections, clean mods inventory, valid Forge 1.8.9 environment',
    payload: {
      schemaVersion: "1.0.0",
      scannerVersion: "1.0.0-stage1-synthetic",
      scanMode: "FULL",
      osName: "Windows 11 Home",
      osVersion: "10.0.22631.3447",
      osArchitecture: "x64",
      scanStartedAt: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
      scanCompletedAt: new Date().toISOString(),
      detectedMinecraftVersions: ["1.8.9"],
      detectedLoaders: ["Forge 11.15.1.2318", "OptiFine_1.8.9_HD_U_M5"],
      consentConfirmation: {
        consentGiven: true,
        collectionScopeVersion: "1.0",
        consentTimestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString()
      },
      collectionCoverage: {
        totalChecks: 38,
        passedChecks: 37,
        flaggedChecks: 0,
        unavailableChecks: 1
      },
      retentionDays: 7,
      findings: [],
      evidenceItems: [
        {
          publicEvidenceId: "ev_mods_001",
          type: "ModInventory",
          title: "Mods Folder Inventory",
          description: "All JAR files located in .minecraft/mods with valid signatures and hashes.",
          structuredPayload: [
            { name: "OptiFine_1.8.9_HD_U_M5.jar", sizeBytes: 2451000, sha256: "9f83c2e1d4b6a8e7f0123456789abcdef0123456789abcdef0123456789abcde", verified: true },
            { name: "Essential-loader-1.8.9.jar", sizeBytes: 154020, sha256: "3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0123456789abcdef0123456789abcd", verified: true },
            { name: "KeystrokesMod-v5.jar", sizeBytes: 312000, sha256: "7a8b9c0d1e2f3a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456", verified: true }
          ],
          isAvailable: true
        },
        {
          publicEvidenceId: "ev_jvm_001",
          type: "JvmArguments",
          title: "Minecraft JVM Launch Flags",
          description: "Captured process command-line parameters for javaw.exe.",
          rawContent: "-Xmx3072M -Xms1024M -XX:+UnlockExperimentalVMOptions -XX:+UseG1GC -Dminecraft.applet.TargetDirectory=C:\\Users\\Player\\AppData\\Roaming\\.minecraft",
          isAvailable: true
        }
      ],
      timelineEvents: [
        {
          timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "Process",
          description: "Minecraft 1.8.9 launched via Official Launcher (PID: 8412)",
          source: "Process Creation Audit",
          confidence: "Certain"
        },
        {
          timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "Consent",
          description: "Player accepted data collection consent scope v1.0",
          source: "Scanner Agent",
          confidence: "Certain"
        },
        {
          timestamp: new Date().toISOString(),
          isInferred: false,
          category: "Scan",
          description: "Diagnostic scan completed cleanly. 37 checks verified.",
          source: "Forensics Engine",
          confidence: "Certain"
        }
      ],
      diagnosticItems: [
        {
          checkName: "NTFS USN Journal Parsing",
          source: "Volume \\\\.\\C:",
          status: "Completed",
          reason: "Parsed 1,450 journal entries spanning past 24 hours. No suspicious deletions detected."
        },
        {
          checkName: "Kernel Filter Driver Hook",
          source: "Ring 0",
          status: "Skipped",
          reason: "User-space scanner deliberately excludes kernel drivers to preserve player system stability and privacy.",
          recommendation: "Standard user-space forensic collection is sufficient."
        }
      ]
    }
  },
  {
    id: 'autoclicker-usn',
    name: 'Autoclicker & USN Deletion Traces',
    subtitle: 'High-confidence Prefetch execution artifact + Deleted mod in NTFS USN journal',
    payload: {
      schemaVersion: "1.0.0",
      scannerVersion: "1.0.0-stage1-synthetic",
      scanMode: "FULL",
      osName: "Windows 11 Pro",
      osVersion: "10.0.22631.3527",
      osArchitecture: "x64",
      scanStartedAt: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
      scanCompletedAt: new Date().toISOString(),
      detectedMinecraftVersions: ["1.8.9"],
      detectedLoaders: ["Lunar Client v3.2.1"],
      consentConfirmation: {
        consentGiven: true,
        collectionScopeVersion: "1.0",
        consentTimestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString()
      },
      collectionCoverage: {
        totalChecks: 42,
        passedChecks: 39,
        flaggedChecks: 2,
        unavailableChecks: 1
      },
      retentionDays: 7,
      findings: [
        {
          ruleId: "WIN-PREF-003",
          title: "Standalone Clicker Binary Execution in Prefetch",
          category: "ExecutionArtifacts",
          severity: "High",
          confidence: "High",
          explanation: "Windows Prefetch file 'AUTOCLICKER_V4.EXE-2B8A1C9D.pf' indicates execution of a known autoclicker utility approximately 12 minutes prior to screen sharing.",
          observedEvidence: {
            prefetchFile: "AUTOCLICKER_V4.EXE-2B8A1C9D.pf",
            runCount: 4,
            lastRunUtc: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
            referencedVolumes: ["\\VOLUME{01d9f8a2-1132-4e08-9844-32a104081c12}"]
          },
          filePath: "C:\\Users\\User\\Downloads\\autoclicker_v4.exe",
          fileSizeBytes: 425984,
          fileSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          firstObservedAt: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
          lastObservedAt: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
          evidenceSource: "Prefetch",
          detectionRuleVersion: "1.4.1",
          limitationsAndFalsePositives: "Prefetch proves execution of the binary on this machine; it does not confirm active clicking during a specific duel without corresponding game input logs."
        },
        {
          ruleId: "NTFS-USN-008",
          title: "Deleted External Mod File Recorded in USN Journal",
          category: "FileDeletion",
          severity: "Medium",
          confidence: "Medium",
          explanation: "The NTFS Change Journal recorded a file deletion (USN_REASON_FILE_DELETE) for 'Vape_Loader.jar' inside a temporary workspace directory 5 minutes before screenshare request.",
          observedEvidence: {
            recordNumber: 4920194,
            fileName: "Vape_Loader.jar",
            reasonFlags: ["USN_REASON_DATA_OVERWRITE", "USN_REASON_FILE_DELETE"],
            parentFrn: "0x0002000000014b2c"
          },
          filePath: "C:\\Users\\User\\AppData\\Local\\Temp\\Vape_Loader.jar",
          fileSizeBytes: 891240,
          firstObservedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
          lastObservedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
          evidenceSource: "UsnJournal",
          detectionRuleVersion: "1.1.0",
          limitationsAndFalsePositives: "File was deleted prior to scan. SHA-256 cannot be computed from deleted USN records alone. Contextual correlation with download logs is advised."
        }
      ],
      evidenceItems: [
        {
          publicEvidenceId: "ev_pref_full_001",
          type: "WindowsArtifact",
          title: "Prefetch Metadata Header Dump",
          description: "Raw parsed header timestamps and dependency file references from Prefetch entry.",
          rawContent: "[PREFETCH DUMP: AUTOCLICKER_V4.EXE]\nVersion: Windows 10/11 (30)\nHash: 0x2B8A1C9D\nRun Count: 4\nLast Execution: " + new Date(Date.now() - 12 * 60 * 1000).toISOString() + "\nReferenced DLLs:\n - KERNEL32.DLL\n - USER32.DLL\n - MSVCP140.DLL",
          sha256Hash: "d4e5f6a1b2c30415263748596a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b",
          isAvailable: true
        },
        {
          publicEvidenceId: "ev_usn_entries_002",
          type: "CorrelationResult",
          title: "NTFS USN Journal Deletion Timeline",
          description: "Structured slice of file deletion events occurring within 30 minutes of investigation call.",
          structuredPayload: [
            { timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(), path: "C:\\Users\\User\\AppData\\Local\\Temp\\Vape_Loader.jar", action: "FILE_DELETE" },
            { timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(), path: "C:\\Users\\User\\AppData\\Local\\Temp\\hsperfdata_user\\8412", action: "DATA_TRUNCATION" }
          ],
          isAvailable: true
        }
      ],
      timelineEvents: [
        {
          timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "Execution",
          description: "Minecraft launched via Lunar Client",
          source: "Lunar Client Logs",
          confidence: "High"
        },
        {
          timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "Execution",
          description: "autoclicker_v4.exe executed",
          source: "Windows Prefetch",
          confidence: "High",
          correlationGroup: "CORR-CLICKER"
        },
        {
          timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "FileDeletion",
          description: "Vape_Loader.jar deleted from Temp directory",
          source: "NTFS USN Journal",
          confidence: "High",
          correlationGroup: "CORR-CLEANUP"
        },
        {
          timestamp: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "Investigation",
          description: "Screen share investigation requested by Server Staff",
          source: "Audit Log",
          confidence: "Certain"
        }
      ],
      diagnosticItems: [
        {
          checkName: "BAM (Background Activity Moderator)",
          source: "Registry",
          status: "Completed",
          reason: "Successfully parsed execution timestamps for user profile."
        },
        {
          checkName: "Recycle Bin Artifact Verification",
          source: "C:\\$Recycle.Bin",
          status: "Completed",
          reason: "Scanned recycle bin indices. No matches for deleted JAR (file was permanently deleted / Shift+Del)."
        }
      ]
    }
  },
  {
    id: 'injection-anomaly',
    name: 'Process Injection & Native DLL Hook',
    subtitle: 'Critical memory anomaly: Unsigned foreign DLL mapped into javaw.exe memory space',
    payload: {
      schemaVersion: "1.0.0",
      scannerVersion: "1.0.0-stage1-synthetic",
      scanMode: "FULL",
      osName: "Windows 10 Enterprise",
      osVersion: "10.0.19045.4291",
      osArchitecture: "x64",
      scanStartedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      scanCompletedAt: new Date().toISOString(),
      detectedMinecraftVersions: ["1.20.4"],
      detectedLoaders: ["Fabric 0.15.11"],
      consentConfirmation: {
        consentGiven: true,
        collectionScopeVersion: "1.0",
        consentTimestamp: new Date(Date.now() - 11 * 60 * 1000).toISOString()
      },
      collectionCoverage: {
        totalChecks: 45,
        passedChecks: 41,
        flaggedChecks: 3,
        unavailableChecks: 1
      },
      retentionDays: 14,
      findings: [
        {
          ruleId: "MEM-INJ-001",
          title: "Foreign Unsigned DLL Injected into javaw.exe",
          category: "ProcessInjection",
          severity: "Critical",
          confidence: "High",
          explanation: "Memory module enumeration of the running Minecraft process (javaw.exe, PID 9244) discovered an unsigned library mapped from a non-standard directory with executable memory protection flags (PAGE_EXECUTE_READWRITE).",
          observedEvidence: {
            processId: 9244,
            moduleBaseAddress: "0x7FFB34000000",
            moduleSize: 1048576,
            modulePath: "C:\\Users\\User\\AppData\\Local\\Temp\\k32hook.dll",
            isSigned: false,
            memoryProtection: "PAGE_EXECUTE_READWRITE"
          },
          processId: 9244,
          processName: "javaw.exe",
          processCommandLine: "\"C:\\Program Files\\Java\\jdk-17\\bin\\javaw.exe\" -Xmx4096m -jar fabric-loader.jar",
          filePath: "C:\\Users\\User\\AppData\\Local\\Temp\\k32hook.dll",
          fileSizeBytes: 245760,
          fileSha256: "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0123456789abcdef0123456789abcdef",
          firstObservedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
          lastObservedAt: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
          evidenceSource: "ProcessMemoryMetadata",
          detectionRuleVersion: "2.1.0",
          limitationsAndFalsePositives: "Some legitimate screen recording overlays (e.g. Discord, OBS, RivaTuner) hook Direct3D/OpenGL. However, legitimate hooks are digitally signed and loaded from Program Files."
        },
        {
          ruleId: "JVM-CLASS-003",
          title: "Anomalous Class Bytecode Modification",
          category: "JvmEnvironment",
          severity: "High",
          confidence: "Medium",
          explanation: "Java Instrumentation agent detected runtime bytecode modification of net.minecraft.client.entity.EntityPlayerSP with foreign method instructions.",
          observedEvidence: {
            modifiedClass: "net.minecraft.client.entity.EntityPlayerSP",
            addedMethods: ["hookMovementSpeed()", "bypassReachCheck()"],
            isRetransformable: true
          },
          evidenceSource: "JvmArgs",
          detectionRuleVersion: "1.3.0",
          limitationsAndFalsePositives: "Legitimate optimization mods (Lithium, Sodium) perform bytecode transformation via Mixins. Check classloader origin."
        }
      ],
      evidenceItems: [
        {
          publicEvidenceId: "ev_loaded_modules_001",
          type: "LoadedModules",
          title: "Loaded DLL Modules in javaw.exe",
          description: "Complete list of 84 loaded PE modules with code signature verification status.",
          rawContent: "[MODULE LIST javaw.exe PID 9244]\n0x7FF6B0000000 javaw.exe [Signed: Microsoft]\n0x7FFB90000000 ntdll.dll [Signed: Microsoft]\n0x7FFB8F000000 KERNEL32.DLL [Signed: Microsoft]\n0x7FFB34000000 k32hook.dll [UNSIGNED - NO COMPANY - TEMP FOLDER]",
          sha256Hash: "c3d4e5f6a1b2c30415263748596a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
          isAvailable: true
        }
      ],
      timelineEvents: [
        {
          timestamp: new Date(Date.now() - 28 * 60 * 1000).toISOString(),
          isInferred: false,
          category: "Launch",
          description: "Fabric 1.20.4 launched with 14 active mods",
          source: "Launcher Log",
          confidence: "Certain"
        },
        {
          timestamp: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
          isInferred: true,
          category: "Injection",
          description: "Inferred injection time of k32hook.dll into javaw.exe",
          source: "Module Load Audit & PE Header",
          confidence: "High",
          correlationGroup: "CORR-INJECTION"
        }
      ],
      diagnosticItems: [
        {
          checkName: "Process Memory Safety Check",
          source: "VirtualQueryEx User Mode",
          status: "Completed",
          reason: "Successfully traversed virtual memory segments."
        }
      ]
    }
  }
];

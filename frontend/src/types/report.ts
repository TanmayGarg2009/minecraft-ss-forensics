export type ScanMode = 'QUICK' | 'FULL';
export type ProcessingStatus = 'Completed' | 'Partial' | 'Failed';

export type Severity = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
export type ConfidenceLevel = 'Low' | 'Medium' | 'High' | 'Certain';

export type FindingCategory =
  | 'ModIntegrity'
  | 'ProcessInjection'
  | 'ExecutionArtifacts'
  | 'JvmEnvironment'
  | 'FileDeletion'
  | 'NetworkAnomaly'
  | 'Other';

export type EvidenceSource =
  | 'ModFolder'
  | 'Prefetch'
  | 'UsnJournal'
  | 'BamDam'
  | 'JvmArgs'
  | 'EventLogs'
  | 'ProcessMemoryMetadata'
  | 'ShimCache'
  | 'Amcache'
  | 'Other';

export type EvidenceType =
  | 'MinecraftLog'
  | 'LauncherLog'
  | 'ModInventory'
  | 'ModPolicyAudit'
  | 'JvmArguments'
  | 'LoadedModules'
  | 'FileMetadata'
  | 'WindowsArtifact'
  | 'CorrelationResult'
  | 'DiagnosticFailure';

export type GameplayPolicy = 'ALLOWED' | 'PROHIBITED' | 'RESTRICTED' | 'NEEDS_REVIEW' | 'UNKNOWN';

export interface ModInventoryItem {
  name: string;
  fileName: string;
  sizeBytes?: number;
  fileSizeBytes?: number;
  sha256: string;
  sha512?: string;
  modId?: string;
  modName?: string;
  version?: string;
  loader?: string;
  // Authenticity
  verified: boolean;
  verificationState: string;
  verificationProvider?: string;
  verificationExplanation?: string;
  projectUrl?: string;
  // Gameplay Policy (Independent from authenticity)
  gameplayPolicy?: GameplayPolicy | string;
  policy?: GameplayPolicy | string;
  behaviorCategory?: string;
  policyConfidence?: string;
  policyReason?: string;
  policyExplanation?: string;
  policyLimitations?: string;
  restrictionConditions?: string;
  hasConflictingSignals?: boolean;
  conflictDetails?: string;
  appliedPolicyName?: string;
  appliedGamemode?: string;
  appliedPolicyVersion?: string;
  suspiciousNotes?: string[];
}

export interface ConsentDetail {
  consentGiven: boolean;
  collectionScopeVersion: string;
  consentTimestamp: string;
}

export interface CoverageDetail {
  totalChecks: number;
  passedChecks: number;
  flaggedChecks: number;
  unavailableChecks: number;
}

export interface FindingDetail {
  ruleId: string;
  title: string;
  category: FindingCategory | string;
  severity: Severity;
  confidence: ConfidenceLevel;
  explanation: string;
  observedEvidence?: any;
  filePath?: string;
  fileSizeBytes?: number;
  fileSha256?: string;
  fileCreatedTime?: string;
  fileModifiedTime?: string;
  fileLastAccessTime?: string;
  processId?: number;
  processName?: string;
  processCommandLine?: string;
  firstObservedAt?: string;
  lastObservedAt?: string;
  evidenceSource: EvidenceSource | string;
  detectionRuleVersion: string;
  limitationsAndFalsePositives: string;
}

export interface EvidenceSummary {
  publicEvidenceId: string;
  type: EvidenceType | string;
  title: string;
  description: string;
  sha256Hash?: string;
  isAvailable: boolean;
  diagnosticMessage?: string;
  capturedAt: string;
  hasRawContent: boolean;
  structuredPayload?: any;
  rawContent?: string;
}

export interface TimelineEventDetail {
  timestamp: string;
  isInferred: boolean;
  category: string;
  description: string;
  source: string;
  confidence: ConfidenceLevel | string;
  correlationGroup?: string;
}

export interface DiagnosticItemDetail {
  checkName: string;
  source: string;
  status: 'Completed' | 'Skipped' | 'AccessDenied' | 'Unsupported' | 'Failed' | string;
  reason: string;
  recommendation?: string;
}

export interface ReportDetail {
  publicId: string;
  schemaVersion: string;
  scannerVersion: string;
  createdAt: string;
  uploadedAt: string;
  scanStartedAt?: string;
  scanCompletedAt?: string;
  scanMode: ScanMode;
  osName: string;
  osVersion: string;
  osArchitecture: string;
  detectedMinecraftVersions: string[];
  detectedLoaders: string[];
  appliedPolicyName?: string;
  appliedPolicyVersion?: string;
  appliedGamemode?: string;
  appliedPolicyRulesUrl?: string;
  consent: ConsentDetail;
  processingStatus: ProcessingStatus | string;
  expiresAt: string;
  coverage: CoverageDetail;
  severitySummary: Record<string, number>;
  findings: FindingDetail[];
  evidenceItems: EvidenceSummary[];
  timelineEvents: TimelineEventDetail[];
  diagnosticItems: DiagnosticItemDetail[];
  privacyNotice: string;
}

export interface SubmitReportResponse {
  publicId: string;
  shareUrl: string;
  deletionKey: string;
  expiresAt: string;
  processingStatus: string;
  findingsCount: number;
  message: string;
}

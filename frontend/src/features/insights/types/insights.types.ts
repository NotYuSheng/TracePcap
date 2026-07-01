export interface NodeRole {
  entityType: string;
  entityKey: string;
  roleLabel: string | null;
  roleDescription: string | null;
  llmSuggested: boolean;
  confirmedByHuman: boolean;
  createdAt: string;
  updatedAt: string;
  /** Staleness (#369): when the label was confirmed and, if drifted, since when + what changed. */
  labeledAt: string | null;
  staleSince: string | null;
  staleFields: string[] | null;
}

export interface NetworkExternalEvent {
  id: string;
  networkId: string;
  eventTime: string;
  title: string;
  description: string | null;
  createdAt: string;
}

export interface NetworkAnnotation {
  id: string;
  networkId: string;
  snapshotId: string | null;
  body: string;
  createdAt: string;
  updatedAt: string;
}

export interface NarrativeSection {
  title: string;
  content: string;
}

export interface Anomaly {
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface Correlation {
  externalEvent: string;
  networkChange: string;
  explanation: string;
}

export type InsightAudience = 'TECHNICAL' | 'EXECUTIVE' | 'OT';
export type InsightFocus    = 'SECURITY' | 'OPERATIONAL' | 'COMPLIANCE';

export interface InsightOptions {
  audience: InsightAudience;
  focus: InsightFocus;
}

export interface NetworkInsight {
  id: string;
  networkId: string;
  generatedAt: string;
  modelUsed: string | null;
  status: 'COMPLETED' | 'FAILED';
  errorMessage: string | null;
  audience: InsightAudience | null;
  focus: InsightFocus | null;
  summary: string | null;
  narrativeSections: NarrativeSection[] | null;
  anomalies: Anomaly[] | null;
  correlations: Correlation[] | null;
  recommendations: string[] | null;
}

export interface SubnetDefinition {
  id: number | null;
  cidr: string;
  label: string | null;
  description: string | null;
  source: 'AUTO' | 'MANUAL';
  confirmed: boolean;
  hostCount?: number;
  densityScore?: number;
  snapshotsSeen?: number;
  totalSnapshots?: number;
  createdAt?: string;
  updatedAt?: string;
}

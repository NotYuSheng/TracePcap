export type IpClassification = 'PRIVATE' | 'PUBLIC';

export interface CustomPrivateRange {
  id: number;
  cidr: string;
  label: string | null;
  classification: IpClassification;
}


export type Domain = 
  | 'General Security Concepts' 
  | 'Threats, Vulnerabilities, Mitigations' 
  | 'Security Architecture' 
  | 'Security Operations' 
  | 'Governance, Risk, Compliance';

export interface Reference {
  source: 'Study Guide' | 'Practice Exams';
  section: string; // e.g. "1.2 - Physical Security"
  page?: number;
}

export interface Scenario {
  id: string;
  domain: Domain;
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string; // The high-level summary
  rationales: string[]; // Specific explanation for EACH option [0,1,2,3]
  objectiveCodes: string[]; // e.g. ["2.4", "1.2"]
  tags: string[];
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  logs: string[];
  refs: Reference[];
}

export interface GameState {
  xp: number;
  level: number;
  clearedScenarios: string[];
  currentScenarioId: string | null;
  activeDomain: Domain | 'ALL';
  streak: number;
}

export const DOMAINS: Domain[] = [
  'General Security Concepts',
  'Threats, Vulnerabilities, Mitigations',
  'Security Architecture',
  'Security Operations',
  'Governance, Risk, Compliance'
];

export type Domain = 
  | 'General Security Concepts' 
  | 'Threats, Vulnerabilities, Mitigations' 
  | 'Security Architecture' 
  | 'Security Operations' 
  | 'Governance, Risk, Compliance';

export interface Scenario {
  id: string;
  domain: Domain;
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  logs: string[]; // Mock logs associated with this scenario
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
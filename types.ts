
export type Domain =
  | 'General Security Concepts'
  | 'Threats, Vulnerabilities, Mitigations'
  | 'Security Architecture'
  | 'Security Operations'
  | 'Governance, Risk, Compliance';

export interface Reference {
  source: 'Study Guide' | 'Practice Exams';
  section: string;
  page?: number;
}

// --- Legacy quiz format (kept for test mode / Firestore compatibility) ---
export interface Scenario {
  id: string;
  domain: Domain;
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
  rationales: string[];
  objectiveCodes: string[];
  tags: string[];
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  logs: string[];
  refs: Reference[];
}

// --- Investigation mission format ---
export type IntelType = 'log' | 'report' | 'intercepted' | 'forensic' | 'witness' | 'alert';

export interface IntelNode {
  id: string;
  type: IntelType;
  label: string;
  content: string;
  critical: boolean;
}

export interface Mission {
  id: string;
  title: string;
  domain: Domain;
  objectiveCodes: string[];
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  briefing: string;
  intel: IntelNode[];
  challenge: {
    question: string;
    options: string[];
    correctIndex: number;
    rationales: string[];
  };
  debrief: string;
  escalation: string;
  refs: Reference[];
}

// --- Game state ---
export interface GameState {
  xp: number;
  level: number;
  clearedScenarios: string[];
  clearedMissions: string[];
  currentScenarioId: string | null;
  currentMissionId: string | null;
  activeDomain: Domain | 'ALL';
  streak: number;
  mode: 'investigate' | 'test';
}

export const DOMAINS: Domain[] = [
  'General Security Concepts',
  'Threats, Vulnerabilities, Mitigations',
  'Security Architecture',
  'Security Operations',
  'Governance, Risk, Compliance'
];

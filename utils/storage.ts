import { GameState } from '../types';

const STORAGE_KEY = 'darktrace_save_v1';

const DEFAULT_STATE: GameState = {
  xp: 0,
  level: 1,
  clearedScenarios: [],
  clearedMissions: [],
  currentScenarioId: null,
  currentMissionId: null,
  activeDomain: 'ALL',
  streak: 0,
  mode: 'investigate'
};

export const saveGame = (state: GameState) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (e) {
    console.error('Failed to save game state', e);
  }
};

export const loadGame = (): GameState => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (!saved) return DEFAULT_STATE;
    const parsed = JSON.parse(saved);
    // Merge with defaults so old saves get new fields
    return { ...DEFAULT_STATE, ...parsed };
  } catch (e) {
    console.error('Failed to load game state', e);
    return DEFAULT_STATE;
  }
};

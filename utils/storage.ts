import { GameState } from '../types';

const STORAGE_KEY = 'darktrace_save_v1';

const DEFAULT_STATE: GameState = {
  xp: 0,
  level: 1,
  clearedScenarios: [],
  currentScenarioId: null,
  activeDomain: 'ALL',
  streak: 0
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
    return saved ? JSON.parse(saved) : DEFAULT_STATE;
  } catch (e) {
    console.error('Failed to load game state', e);
    return DEFAULT_STATE;
  }
};
import { Mission } from '../types';

export type MissionSelectionReason = 'sequence' | 'prerequisite' | 'review';

export interface MissionSelection {
  mission: Mission | null;
  reason: MissionSelectionReason | null;
  detail?: string;
}

const REVIEW_CADENCE = 4;

export const getNextMission = (missions: Mission[], clearedMissions: string[]): MissionSelection => {
  const nextRegular = missions.find(mission => !clearedMissions.includes(mission.id));

  if (!nextRegular) {
    return { mission: null, reason: null };
  }

  if (clearedMissions.length > 0 && clearedMissions.length % REVIEW_CADENCE === 0) {
    const lastClearedId = clearedMissions[clearedMissions.length - 1];
    const reviewMission = missions.find(mission => mission.id === lastClearedId);
    if (reviewMission) {
      return { mission: reviewMission, reason: 'review' };
    }
  }

  if (nextRegular.prerequisites && nextRegular.prerequisites.length > 0) {
    const unmetPrereqId = nextRegular.prerequisites.find(id => !clearedMissions.includes(id));
    if (unmetPrereqId) {
      const prerequisiteMission = missions.find(mission => mission.id === unmetPrereqId);
      if (prerequisiteMission) {
        return { mission: prerequisiteMission, reason: 'prerequisite', detail: prerequisiteMission.title };
      }
    }
  }

  return { mission: nextRegular, reason: 'sequence' };
};

import React from 'react';
import { Shield, Zap, Target, Activity } from 'lucide-react';
import { GameState } from '../types';

interface IntelHUDProps {
  state: GameState;
}

export const IntelHUD: React.FC<IntelHUDProps> = ({ state }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div className="bg-cyber-slate/30 border border-cyber-slate p-3 rounded-lg flex items-center gap-3">
        <div className="p-2 bg-cyber-cyan/10 rounded-full text-cyber-cyan">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-gray-400 font-mono uppercase">Security Level</div>
          <div className="text-lg font-bold text-white">{state.level}</div>
        </div>
      </div>

      <div className="bg-cyber-slate/30 border border-cyber-slate p-3 rounded-lg flex items-center gap-3">
        <div className="p-2 bg-cyber-amber/10 rounded-full text-cyber-amber">
          <Zap className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-gray-400 font-mono uppercase">XP Gained</div>
          <div className="text-lg font-bold text-white">{state.xp}</div>
        </div>
      </div>

      <div className="bg-cyber-slate/30 border border-cyber-slate p-3 rounded-lg flex items-center gap-3">
        <div className="p-2 bg-cyber-emerald/10 rounded-full text-cyber-emerald">
          <Target className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-gray-400 font-mono uppercase">Resolved</div>
          <div className="text-lg font-bold text-white">{state.clearedScenarios.length}</div>
        </div>
      </div>

      <div className="bg-cyber-slate/30 border border-cyber-slate p-3 rounded-lg flex items-center gap-3">
        <div className="p-2 bg-cyber-rose/10 rounded-full text-cyber-rose">
          <Activity className="w-5 h-5" />
        </div>
        <div>
          <div className="text-xs text-gray-400 font-mono uppercase">Streak</div>
          <div className="text-lg font-bold text-white">{state.streak}</div>
        </div>
      </div>
    </div>
  );
};
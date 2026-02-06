import React from 'react';
import { Mission } from '../types';
import { AlertTriangle, FileText, Shield } from 'lucide-react';
import { motion } from 'framer-motion';

interface MissionBriefingProps {
  mission: Mission;
  onBeginInvestigation: () => void;
}

export const MissionBriefing: React.FC<MissionBriefingProps> = ({ mission, onBeginInvestigation }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex-1 p-6 flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-2">
        <span className={`text-xs font-bold px-2 py-1 rounded border ${
          mission.threatLevel === 'critical' ? 'text-cyber-rose bg-cyber-rose/10 border-cyber-rose/30' :
          mission.threatLevel === 'high' ? 'text-orange-400 bg-orange-400/10 border-orange-400/30' :
          mission.threatLevel === 'medium' ? 'text-cyber-amber bg-cyber-amber/10 border-cyber-amber/30' :
          'text-cyber-emerald bg-cyber-emerald/10 border-cyber-emerald/30'
        }`}>
          {mission.threatLevel.toUpperCase()} PRIORITY
        </span>
        {mission.objectiveCodes.map(oc => (
          <span key={oc} className="text-[10px] font-mono text-cyber-cyan bg-cyber-cyan/10 px-1.5 py-0.5 rounded">
            OBJ {oc}
          </span>
        ))}
      </div>

      <h2 className="text-2xl font-bold text-white mb-1 tracking-tight">
        {mission.title}
      </h2>
      <span className="text-xs text-gray-500 mb-6">{mission.domain}</span>

      {/* Briefing content */}
      <div className="bg-cyber-dark/80 rounded-lg border border-cyber-amber/30 p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-cyber-amber" />
          <h3 className="text-cyber-amber font-bold text-sm tracking-wider">INCIDENT BRIEFING</h3>
        </div>
        <p className="text-gray-300 leading-relaxed text-sm">
          {mission.briefing}
        </p>
      </div>

      {/* Intel preview */}
      <div className="bg-cyber-slate/20 rounded-lg border border-cyber-slate/50 p-4 mb-6">
        <div className="flex items-center gap-2 mb-3">
          <FileText className="w-4 h-4 text-cyber-cyan" />
          <h4 className="text-cyber-cyan text-xs font-bold tracking-wider">AVAILABLE INTELLIGENCE</h4>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {mission.intel.map(node => (
            <div
              key={node.id}
              className="bg-cyber-dark/50 rounded p-2 border border-cyber-slate/30 flex items-center gap-2"
            >
              <div className={`w-2 h-2 rounded-full ${node.critical ? 'bg-cyber-amber' : 'bg-gray-600'}`} />
              <span className="text-xs text-gray-400">{node.label}</span>
              {node.critical && (
                <span className="text-[9px] text-cyber-amber bg-cyber-amber/10 px-1 rounded ml-auto">KEY</span>
              )}
            </div>
          ))}
        </div>
        <p className="text-[10px] text-gray-600 mt-2">
          Review intelligence marked KEY before responding to the incident
        </p>
      </div>

      {/* Tags */}
      <div className="flex gap-2 mb-6">
        {mission.tags.map(tag => (
          <span key={tag} className="text-[10px] text-gray-500 bg-cyber-black/50 px-2 py-0.5 rounded">
            #{tag}
          </span>
        ))}
      </div>

      {/* CTA */}
      <div className="mt-auto pt-4 border-t border-cyber-slate/30">
        <button
          onClick={onBeginInvestigation}
          className="w-full bg-cyber-amber hover:bg-cyber-amber/80 text-cyber-black font-bold py-3 px-8 rounded flex items-center justify-center gap-2 transition-all hover:scale-[1.02]"
        >
          <Shield className="w-5 h-5" /> BEGIN INVESTIGATION
        </button>
      </div>
    </motion.div>
  );
};

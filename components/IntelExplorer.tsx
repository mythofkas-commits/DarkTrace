import React, { useState } from 'react';
import { IntelNode, IntelType } from '../types';
import { FileText, Radio, Search, Shield, AlertTriangle, Eye, Lock, ChevronRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const INTEL_ICONS: Record<IntelType, React.FC<{ className?: string }>> = {
  log: FileText,
  report: Search,
  intercepted: Radio,
  forensic: Shield,
  witness: Eye,
  alert: AlertTriangle,
};

const INTEL_LABELS: Record<IntelType, string> = {
  log: 'SYSTEM LOG',
  report: 'ANALYSIS REPORT',
  intercepted: 'INTERCEPTED INTEL',
  forensic: 'FORENSIC EVIDENCE',
  witness: 'WITNESS STATEMENT',
  alert: 'SECURITY ALERT',
};

interface IntelExplorerProps {
  intelNodes: IntelNode[];
  viewedIds: Set<string>;
  onViewIntel: (id: string) => void;
  onProceedToChallenge: () => void;
  canProceed: boolean;
  criticalCount: number;
  criticalViewed: number;
}

export const IntelExplorer: React.FC<IntelExplorerProps> = ({
  intelNodes,
  viewedIds,
  onViewIntel,
  onProceedToChallenge,
  canProceed,
  criticalCount,
  criticalViewed,
}) => {
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);
  const activeNode = intelNodes.find(n => n.id === activeNodeId);

  const handleOpenNode = (id: string) => {
    setActiveNodeId(id);
    onViewIntel(id);
  };

  return (
    <div className="flex-1 flex flex-col p-4 gap-4">
      {/* Progress bar */}
      <div className="bg-cyber-dark/80 rounded p-3 border border-cyber-slate/50">
        <div className="flex justify-between items-center mb-2">
          <span className="text-xs font-bold text-cyber-cyan tracking-wider">INVESTIGATION PROGRESS</span>
          <span className="text-xs text-gray-400">
            {criticalViewed}/{criticalCount} key intel reviewed
          </span>
        </div>
        <div className="h-1.5 bg-cyber-black rounded-full overflow-hidden">
          <motion.div
            className="h-full bg-gradient-to-r from-cyber-amber to-cyber-emerald"
            initial={{ width: 0 }}
            animate={{ width: `${criticalCount > 0 ? (criticalViewed / criticalCount) * 100 : 0}%` }}
            transition={{ duration: 0.5 }}
          />
        </div>
      </div>

      <div className="flex-1 flex gap-4 min-h-0">
        {/* Intel list (left) */}
        <div className="w-56 flex-shrink-0 space-y-2 overflow-y-auto">
          {intelNodes.map(node => {
            const Icon = INTEL_ICONS[node.type];
            const isViewed = viewedIds.has(node.id);
            const isActive = activeNodeId === node.id;

            return (
              <button
                key={node.id}
                onClick={() => handleOpenNode(node.id)}
                className={`w-full text-left p-3 rounded border transition-all duration-200 ${
                  isActive
                    ? 'bg-cyber-cyan/10 border-cyber-cyan/50 text-cyber-cyan'
                    : isViewed
                    ? 'bg-cyber-slate/20 border-cyber-slate/30 text-gray-400'
                    : 'bg-cyber-dark/80 border-cyber-slate/40 text-gray-300 hover:border-gray-500'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Icon className="w-3.5 h-3.5 flex-shrink-0" />
                  <span className="text-[10px] uppercase tracking-wider truncate">
                    {INTEL_LABELS[node.type]}
                  </span>
                  {node.critical && !isViewed && (
                    <span className="text-[9px] text-cyber-amber bg-cyber-amber/10 px-1 rounded ml-auto flex-shrink-0">
                      KEY
                    </span>
                  )}
                  {isViewed && (
                    <span className="text-[9px] text-cyber-emerald ml-auto flex-shrink-0">
                      REVIEWED
                    </span>
                  )}
                </div>
                <span className="text-xs font-bold block truncate">{node.label}</span>
              </button>
            );
          })}
        </div>

        {/* Intel detail (right) */}
        <div className="flex-1 bg-cyber-dark/60 rounded-lg border border-cyber-slate/40 overflow-hidden flex flex-col min-h-0">
          <AnimatePresence mode="wait">
            {activeNode ? (
              <motion.div
                key={activeNode.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="flex-1 flex flex-col min-h-0"
              >
                {/* Detail header */}
                <div className="bg-cyber-slate/30 px-4 py-2.5 border-b border-cyber-slate/50 flex items-center gap-2 flex-shrink-0">
                  {React.createElement(INTEL_ICONS[activeNode.type], { className: 'w-4 h-4 text-cyber-cyan' })}
                  <span className="text-sm font-bold text-white">{activeNode.label}</span>
                  {activeNode.critical && (
                    <span className="text-[9px] text-cyber-amber bg-cyber-amber/10 px-1.5 py-0.5 rounded border border-cyber-amber/20 ml-auto">
                      KEY EVIDENCE
                    </span>
                  )}
                </div>

                {/* Detail content */}
                <div className="flex-1 overflow-y-auto p-4">
                  <div className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap font-mono">
                    {activeNode.content}
                  </div>
                </div>
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex-1 flex items-center justify-center text-gray-600"
              >
                <div className="text-center">
                  <Lock className="w-10 h-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">Select an intelligence file to review</p>
                  <p className="text-xs mt-1 text-gray-700">
                    Review all KEY evidence before responding
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Proceed button */}
      <div className="flex-shrink-0 pt-2 border-t border-cyber-slate/30">
        {canProceed ? (
          <button
            onClick={onProceedToChallenge}
            className="w-full bg-cyber-cyan hover:bg-cyber-cyan/80 text-cyber-black font-bold py-3 rounded flex items-center justify-center gap-2 transition-all hover:scale-[1.02]"
          >
            <ChevronRight className="w-5 h-5" /> RESPOND TO INCIDENT
          </button>
        ) : (
          <div className="w-full bg-cyber-slate/30 text-gray-500 font-bold py-3 rounded flex items-center justify-center gap-2 cursor-not-allowed border border-cyber-slate/50">
            <Lock className="w-4 h-4" />
            <span>REVIEW {criticalCount - criticalViewed} MORE KEY INTEL TO PROCEED</span>
          </div>
        )}
      </div>
    </div>
  );
};

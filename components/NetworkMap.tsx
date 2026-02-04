import React from 'react';
import { motion } from 'framer-motion';

interface NetworkMapProps {
  active: boolean;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export const NetworkMap: React.FC<NetworkMapProps> = ({ active, threatLevel }) => {
  const getPulseColor = () => {
    switch (threatLevel) {
      case 'critical': return '#f43f5e'; // Rose
      case 'high': return '#f97316'; // Orange
      case 'medium': return '#f59e0b'; // Amber
      default: return '#10b981'; // Emerald
    }
  };

  const getDuration = () => {
    switch (threatLevel) {
      case 'critical': return 0.5;
      case 'high': return 1;
      case 'medium': return 2;
      default: return 4;
    }
  };

  return (
    <div className="relative w-full h-64 bg-cyber-black rounded-lg border border-cyber-slate/50 overflow-hidden flex items-center justify-center shadow-lg shadow-cyber-rose/5">
      {/* Grid Background */}
      <div className="absolute inset-0 opacity-10" 
           style={{ backgroundImage: 'linear-gradient(#334155 1px, transparent 1px), linear-gradient(90deg, #334155 1px, transparent 1px)', backgroundSize: '20px 20px' }}>
      </div>

      {/* Nodes */}
      <svg className="w-full h-full absolute inset-0 pointer-events-none">
        {/* Connections */}
        <line x1="50%" y1="50%" x2="20%" y2="30%" stroke="#1e293b" strokeWidth="2" />
        <line x1="50%" y1="50%" x2="80%" y2="30%" stroke="#1e293b" strokeWidth="2" />
        <line x1="50%" y1="50%" x2="20%" y2="70%" stroke="#1e293b" strokeWidth="2" />
        <line x1="50%" y1="50%" x2="80%" y2="70%" stroke="#1e293b" strokeWidth="2" />

        {/* Central Node */}
        <motion.circle 
          cx="50%" cy="50%" r="10" 
          fill={getPulseColor()}
          animate={active ? { scale: [1, 1.5, 1], opacity: [0.9, 0.6, 0.9] } : {}}
          transition={{ duration: getDuration(), repeat: Infinity }}
        />
        <circle cx="50%" cy="50%" r="6" fill="#0f172a" stroke={getPulseColor()} strokeWidth="2" />

        {/* Satellite Nodes */}
        {[
          { cx: '20%', cy: '30%' },
          { cx: '80%', cy: '30%' },
          { cx: '20%', cy: '70%' },
          { cx: '80%', cy: '70%' }
        ].map((pos, i) => (
          <motion.g key={i}>
             <motion.circle 
              cx={pos.cx} cy={pos.cy} r="6" 
              fill={getPulseColor()}
              initial={{ opacity: 0.2 }}
              animate={active ? { opacity: [0.2, 0.5, 0.2] } : {}}
              transition={{ duration: getDuration(), delay: i * 0.2, repeat: Infinity }}
            />
            <circle cx={pos.cx} cy={pos.cy} r="4" fill="#0f172a" stroke="#475569" strokeWidth="2" />
          </motion.g>
        ))}
      </svg>
      
      <div className="absolute top-2 right-2 text-xs font-mono text-gray-500 bg-cyber-black/80 px-2 py-1 rounded">
        NET_STATUS: {active ? 'THREAT DETECTED' : 'NORMAL'}
      </div>
    </div>
  );
};
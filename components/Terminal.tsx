import React, { useEffect, useRef } from 'react';
import { Terminal as TerminalIcon } from 'lucide-react';

interface TerminalProps {
  logs: string[];
}

export const Terminal: React.FC<TerminalProps> = ({ logs }) => {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="bg-cyber-black border border-cyber-slate/50 rounded-lg overflow-hidden flex flex-col h-64 font-mono text-sm shadow-lg shadow-cyber-cyan/5">
      <div className="bg-cyber-slate/50 px-4 py-2 flex items-center gap-2 border-b border-cyber-slate/50">
        <TerminalIcon className="w-4 h-4 text-cyber-cyan" />
        <span className="text-gray-400 font-bold tracking-wider">TERMINAL_OUTPUT</span>
      </div>
      <div className="p-4 overflow-y-auto flex-1 space-y-1">
        {logs.length === 0 && <span className="text-gray-600 italic">System initialized. Waiting for input...</span>}
        {logs.map((log, i) => (
          <div key={i} className="text-cyber-emerald/90 break-words">
            <span className="text-cyber-cyan mr-2">$</span>
            {log}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};
import React from 'react';
import { Search } from 'lucide-react';

interface SignalSearchProps {
  searchTerm: string;
  setSearchTerm: (term: string) => void;
  resultCount: number;
}

export const SignalSearch: React.FC<SignalSearchProps> = ({ searchTerm, setSearchTerm, resultCount }) => {
  return (
    <div className="bg-cyber-dark/80 border border-cyber-cyan/30 rounded p-4 mb-4 flex items-center gap-4 shadow-[0_0_15px_rgba(6,182,212,0.1)]">
      <div className="text-cyber-cyan">
        <Search className="w-5 h-5" />
      </div>
      <div className="flex-1">
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="ENTER_SIGNAL_QUERY (e.g. 'Ransomware', 'Cloud', 'SQL')"
          className="w-full bg-transparent border-b border-cyber-slate text-cyber-emerald font-mono focus:outline-none focus:border-cyber-cyan placeholder-gray-600 uppercase"
          autoFocus
        />
      </div>
      <div className="font-mono text-xs text-cyber-cyan/70">
        MATCHES: {resultCount}
      </div>
    </div>
  );
};
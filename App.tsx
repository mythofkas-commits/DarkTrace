import React, { useState, useEffect, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { Terminal } from './components/Terminal';
import { NetworkMap } from './components/NetworkMap';
import { IntelHUD } from './components/IntelHUD';
import { SignalSearch } from './components/SignalSearch';
import { scenarios } from './data/dataset';
import { saveGame, loadGame } from './utils/storage';
import { GameState, Scenario, DOMAINS, Domain } from './types';
import { AlertTriangle, CheckCircle, XCircle, Play, ChevronRight, BookOpen, Target } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const App = () => {
  const [gameState, setGameState] = useState<GameState>(loadGame());
  const [logs, setLogs] = useState<string[]>(['Initializing DarkTrace...', 'Loading Knowledge Base... OK', 'Waiting for command...']);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<'correct' | 'incorrect' | null>(null);
  const [showExplanation, setShowExplanation] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  // Filter available scenarios based on cleared list, active domain, AND search term
  const availableScenarios = useMemo(() => {
    return scenarios.filter(s => {
      const isCleared = gameState.clearedScenarios.includes(s.id);
      const matchesDomain = gameState.activeDomain === 'ALL' || s.domain === gameState.activeDomain;
      const matchesSearch = searchTerm === '' || 
        s.question.toLowerCase().includes(searchTerm.toLowerCase()) || 
        s.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        s.explanation.toLowerCase().includes(searchTerm.toLowerCase());
      
      return !isCleared && matchesDomain && matchesSearch;
    });
  }, [gameState.clearedScenarios, gameState.activeDomain, searchTerm]);

  const currentScenario: Scenario | undefined = useMemo(() => {
    if (!gameState.currentScenarioId) return undefined;
    return scenarios.find(s => s.id === gameState.currentScenarioId);
  }, [gameState.currentScenarioId]);

  useEffect(() => {
    saveGame(gameState);
  }, [gameState]);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-49), msg]);
  };

  const startSpecificScenario = (scenarioId: string) => {
    const nextScenario = scenarios.find(s => s.id === scenarioId);
    if (!nextScenario) return;

    setGameState(prev => ({ ...prev, currentScenarioId: nextScenario.id }));
    setFeedback(null);
    setSelectedOption(null);
    setShowExplanation(false);
    
    addLog(`[ALERT] Intercepting Signal: ${nextScenario.id}`);
    nextScenario.logs.forEach((l, i) => {
      setTimeout(() => addLog(`> ${l}`), 500 + (i * 800));
    });
  }

  const startRandomScenario = () => {
    if (availableScenarios.length === 0) {
      addLog("MISSION COMPLETE. All known threats neutralized.");
      return;
    }
    const randomIndex = Math.floor(Math.random() * availableScenarios.length);
    const nextScenario = availableScenarios[randomIndex];
    startSpecificScenario(nextScenario.id);
  };

  const handleDomainChange = (domain: Domain | 'ALL') => {
    setGameState(prev => ({ ...prev, activeDomain: domain }));
    addLog(`[SYSTEM] Filter updated: ${domain}`);
  };

  const submitAnswer = () => {
    if (selectedOption === null || !currentScenario) return;

    if (selectedOption === currentScenario.correctIndex) {
      setFeedback('correct');
      addLog(`[SUCCESS] Threat ${currentScenario.id} neutralized.`);
      
      setGameState(prev => {
        const xpGain = 100 + (prev.streak * 10);
        const newXp = prev.xp + xpGain;
        const newLevel = Math.floor(newXp / 1000) + 1;
        const newStreak = prev.streak + 1;

        return {
          ...prev,
          xp: newXp,
          streak: newStreak,
          clearedScenarios: [...prev.clearedScenarios, currentScenario.id],
          level: newLevel,
        };
      });
      setShowExplanation(true);
    } else {
      setFeedback('incorrect');
      addLog(`[FAILURE] Countermeasure failed for ${currentScenario.id}.`);
      setGameState(prev => ({
        ...prev,
        streak: 0
      }));
    }
  };

  return (
    <div className="min-h-screen bg-cyber-black text-slate-200 p-4 font-mono selection:bg-cyber-cyan selection:text-cyber-black">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <header className="flex justify-between items-center border-b border-cyber-slate/50 pb-4">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tighter flex items-center gap-2">
              <span className="text-cyber-rose">DARK</span>TRACE 
              <span className="text-xs bg-cyber-slate px-2 py-1 rounded text-cyber-cyan">PRO_BUILD_v1.7</span>
            </h1>
            <p className="text-cyber-cyan/60 text-sm">SY0-701 FORENSIC RANGE</p>
          </div>
          <button 
            onClick={() => {
              if (confirm('Reset Campaign Progress?')) {
                localStorage.clear();
                window.location.reload();
              }
            }}
            className="text-xs text-cyber-rose/50 hover:text-cyber-rose transition-colors"
          >
            RESET_SIMULATION
          </button>
        </header>

        <IntelHUD state={gameState} />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Sidebar / Domain Filter */}
          <div className="lg:col-span-3 space-y-4">
             <div className="bg-cyber-slate/20 rounded-lg p-4 border border-cyber-slate/50">
               <h3 className="text-cyber-cyan font-bold mb-3 flex items-center gap-2">
                 <ChevronRight className="w-4 h-4" /> DOMAINS
               </h3>
               <div className="space-y-2">
                 <button 
                   onClick={() => handleDomainChange('ALL')}
                   className={`w-full text-left text-xs p-2 rounded transition-colors ${gameState.activeDomain === 'ALL' ? 'bg-cyber-cyan/20 text-cyber-cyan' : 'hover:bg-cyber-slate/40 text-gray-400'}`}
                 >
                   ALL CHANNELS
                 </button>
                 {DOMAINS.map(d => (
                   <button 
                    key={d}
                    onClick={() => handleDomainChange(d)}
                    className={`w-full text-left text-xs p-2 rounded transition-colors ${gameState.activeDomain === d ? 'bg-cyber-cyan/20 text-cyber-cyan' : 'hover:bg-cyber-slate/40 text-gray-400'}`}
                   >
                     {d}
                   </button>
                 ))}
               </div>
             </div>
             
             {/* Progress Status */}
             <div className="bg-cyber-slate/20 rounded-lg p-4 border border-cyber-slate/50">
                <div className="flex justify-between text-xs mb-2">
                  <span>PROGRESS</span>
                  <span>{Math.round((gameState.clearedScenarios.length / scenarios.length) * 100)}%</span>
                </div>
                <div className="h-2 bg-cyber-dark rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyber-cyan to-cyber-emerald transition-all duration-500"
                    style={{ width: `${(gameState.clearedScenarios.length / scenarios.length) * 100}%` }}
                  />
                </div>
             </div>
          </div>

          {/* Main Interface */}
          <div className="lg:col-span-6">
            <div className="bg-cyber-slate/20 rounded-lg border border-cyber-slate/50 min-h-[600px] flex flex-col relative overflow-hidden">
              {!currentScenario ? (
                <div className="flex-1 flex flex-col p-6">
                   <SignalSearch 
                      searchTerm={searchTerm} 
                      setSearchTerm={setSearchTerm} 
                      resultCount={availableScenarios.length}
                   />
                   
                   <div className="flex-1 overflow-y-auto pr-2 space-y-2">
                     {availableScenarios.length === 0 ? (
                       <div className="flex flex-col items-center justify-center h-full text-gray-500">
                         <Target className="w-12 h-12 mb-2 opacity-20" />
                         <p>NO SIGNALS DETECTED</p>
                       </div>
                     ) : (
                       availableScenarios.map(s => (
                         <div 
                            key={s.id}
                            onClick={() => startSpecificScenario(s.id)}
                            className="bg-cyber-dark/50 p-4 rounded border border-cyber-slate/30 hover:border-cyber-cyan/50 hover:bg-cyber-slate/30 cursor-pointer transition-all group"
                         >
                           <div className="flex justify-between items-center mb-1">
                             <span className="text-cyber-cyan font-bold text-xs">{s.id}</span>
                             <span className={`text-[10px] px-2 py-0.5 rounded ${
                               s.threatLevel === 'critical' ? 'bg-cyber-rose/20 text-cyber-rose' :
                               s.threatLevel === 'high' ? 'bg-orange-500/20 text-orange-500' :
                               'bg-cyber-emerald/20 text-cyber-emerald'
                             }`}>
                               {s.threatLevel.toUpperCase()}
                             </span>
                           </div>
                           <div className="text-gray-400 text-sm line-clamp-2 group-hover:text-white transition-colors">
                             {s.question}
                           </div>
                           <div className="text-xs text-gray-600 mt-2 font-mono">
                             DOMAIN: {s.domain}
                           </div>
                         </div>
                       ))
                     )}
                   </div>
                   
                   {availableScenarios.length > 0 && (
                     <div className="mt-4 pt-4 border-t border-cyber-slate/30">
                        <button 
                          onClick={startRandomScenario}
                          className="w-full bg-cyber-cyan hover:bg-cyber-cyan/80 text-cyber-black font-bold py-3 px-8 rounded flex items-center justify-center gap-2 transition-all hover:scale-[1.02]"
                        >
                          <Play className="w-5 h-5" /> ENGAGE RANDOM TARGET
                        </button>
                     </div>
                   )}
                </div>
              ) : (
                <div className="flex-1 p-6 flex flex-col">
                  {/* Scenario Header */}
                  <div className="flex justify-between items-start mb-6">
                     <span className="text-xs font-bold text-cyber-rose bg-cyber-rose/10 px-2 py-1 rounded border border-cyber-rose/20">
                       INCIDENT: {currentScenario.id}
                     </span>
                     <span className="text-xs text-gray-500">{currentScenario.domain}</span>
                  </div>

                  {/* Question */}
                  <h2 className="text-xl font-bold text-white mb-8 leading-relaxed">
                    {currentScenario.question}
                  </h2>

                  {/* Options */}
                  <div className="space-y-3 flex-1">
                    {currentScenario.options.map((opt, idx) => (
                      <button
                        key={idx}
                        disabled={feedback !== null}
                        onClick={() => setSelectedOption(idx)}
                        className={`w-full text-left p-4 rounded border transition-all duration-200 
                          ${selectedOption === idx 
                            ? 'bg-cyber-slate border-cyber-cyan text-cyber-cyan' 
                            : 'bg-cyber-dark/50 border-cyber-slate/50 hover:border-gray-500 text-gray-300'}
                          ${feedback === 'correct' && idx === currentScenario.correctIndex ? '!bg-cyber-emerald/20 !border-cyber-emerald !text-cyber-emerald' : ''}
                          ${feedback === 'incorrect' && selectedOption === idx ? '!bg-cyber-rose/20 !border-cyber-rose !text-cyber-rose' : ''}
                        `}
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-6 h-6 flex items-center justify-center rounded text-xs border ${selectedOption === idx ? 'border-cyber-cyan' : 'border-gray-600'}`}>
                            {String.fromCharCode(65 + idx)}
                          </div>
                          <span>{opt}</span>
                        </div>
                      </button>
                    ))}
                  </div>

                  {/* Action Bar */}
                  <div className="mt-8 pt-4 border-t border-cyber-slate/50 flex justify-between items-center">
                    {feedback === null ? (
                      <button 
                        onClick={submitAnswer}
                        disabled={selectedOption === null}
                        className="ml-auto bg-cyber-cyan disabled:opacity-50 disabled:cursor-not-allowed hover:bg-cyber-cyan/80 text-cyber-black font-bold py-2 px-6 rounded transition-all"
                      >
                        EXECUTE COUNTERMEASURE
                      </button>
                    ) : (
                      <div className="w-full flex justify-between items-center">
                        <div className="flex items-center gap-2">
                           {feedback === 'correct' ? (
                             <span className="flex items-center gap-2 text-cyber-emerald font-bold"><CheckCircle className="w-5 h-5" /> THREAT NEUTRALIZED</span>
                           ) : (
                             <span className="flex items-center gap-2 text-cyber-rose font-bold"><XCircle className="w-5 h-5" /> BREACH SUCCESSFUL</span>
                           )}
                           
                           {/* Explanation Toggle */}
                           {feedback === 'incorrect' && (
                             <button 
                              onClick={() => setShowExplanation(!showExplanation)}
                              className="ml-4 text-xs underline text-gray-400 hover:text-white"
                             >
                               {showExplanation ? 'Hide Analysis' : 'View Analysis'}
                             </button>
                           )}
                        </div>
                        <button 
                          onClick={() => setGameState(prev => ({...prev, currentScenarioId: null}))}
                          className="bg-cyber-slate hover:bg-cyber-slate/80 text-white font-bold py-2 px-6 rounded border border-cyber-slate-500 transition-all"
                        >
                          NEXT INCIDENT
                        </button>
                      </div>
                    )}
                  </div>
                  
                  {/* Explanation Panel */}
                  <AnimatePresence>
                    {(showExplanation || feedback === 'correct') && (
                      <motion.div 
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                      >
                        <div className="mt-4 bg-cyber-dark p-4 rounded border-l-4 border-cyber-cyan">
                          <h4 className="text-cyber-cyan font-bold text-sm mb-1 flex items-center gap-2">
                            <BookOpen className="w-4 h-4" /> FORENSIC ANALYSIS
                          </h4>
                          <p className="text-sm text-gray-300 leading-relaxed">
                            {currentScenario.explanation}
                          </p>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                </div>
              )}
            </div>
          </div>

          {/* Right Sidebar: Visuals & Logs */}
          <div className="lg:col-span-3 space-y-6">
            <div>
              <h3 className="text-xs font-bold text-gray-500 mb-2 tracking-wider">NETWORK STATUS</h3>
              <NetworkMap 
                active={currentScenario !== undefined && feedback === null} 
                threatLevel={currentScenario?.threatLevel || 'low'}
              />
            </div>
            
            <div>
              <h3 className="text-xs font-bold text-gray-500 mb-2 tracking-wider">SYSTEM LOGS</h3>
              <Terminal logs={logs} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
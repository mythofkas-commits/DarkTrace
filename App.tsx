
import React, { useState, useEffect, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { Terminal } from './components/Terminal';
import { NetworkMap } from './components/NetworkMap';
import { IntelHUD } from './components/IntelHUD';
import { SignalSearch } from './components/SignalSearch';
import { MissionBriefing } from './components/MissionBriefing';
import { IntelExplorer } from './components/IntelExplorer';
import { saveGame, loadGame } from './utils/storage';
import { auth, db } from './utils/firebase';
import { signInAnonymously, onAuthStateChanged } from 'firebase/auth';
import { doc, setDoc, getDoc, collection, getDocs } from 'firebase/firestore';
import { GameState, Scenario, Mission, DOMAINS, Domain } from './types';
import { missions as localMissions } from './data/missions';
import {
  AlertTriangle, CheckCircle, XCircle, Play, ChevronRight, BookOpen,
  Target, FileText, Shield, Crosshair
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

type MissionPhase = 'select' | 'briefing' | 'investigating' | 'challenge' | 'debrief';

const App = () => {
  const [gameState, setGameState] = useState<GameState>(loadGame());
  const [logs, setLogs] = useState<string[]>(['Initializing DarkTrace...', 'Loading Knowledge Base... OK', 'Waiting for command...']);
  const [searchTerm, setSearchTerm] = useState('');
  const [user, setUser] = useState<any>(null);

  // --- Mission (investigation) state ---
  const [missions] = useState<Mission[]>(localMissions);
  const [missionPhase, setMissionPhase] = useState<MissionPhase>('select');
  const [viewedIntel, setViewedIntel] = useState<Set<string>>(new Set());
  const [challengeOption, setChallengeOption] = useState<number | null>(null);
  const [challengeResult, setChallengeResult] = useState<'correct' | 'incorrect' | null>(null);

  // --- Quiz (test) state ---
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loadingScenarios, setLoadingScenarios] = useState(false);
  const [quizOption, setQuizOption] = useState<number | null>(null);
  const [quizFeedback, setQuizFeedback] = useState<'correct' | 'incorrect' | null>(null);

  // --- Load scenarios from Firestore (only in test mode) ---
  useEffect(() => {
    if (gameState.mode !== 'test') return;
    if (scenarios.length > 0) return;
    setLoadingScenarios(true);
    const fetchScenarios = async () => {
      try {
        const snapshot = await getDocs(collection(db, 'scenarios'));
        const data = snapshot.docs.map(d => d.data() as Scenario);
        setScenarios(data);
        addLog(`[DATABASE] Loaded ${data.length} scenarios from Firestore.`);
      } catch (err) {
        console.error('Failed to load scenarios:', err);
        addLog('[ERROR] Failed to load scenarios from database.');
        try {
          const { scenarios: localScenarios } = await import('./data/dataset');
          setScenarios(localScenarios);
          addLog(`[FALLBACK] Loaded ${localScenarios.length} scenarios from local dataset.`);
        } catch {
          addLog('[ERROR] No scenario data available.');
        }
      } finally {
        setLoadingScenarios(false);
      }
    };
    fetchScenarios();
  }, [gameState.mode]);

  // --- Derived: current mission ---
  const currentMission: Mission | undefined = useMemo(() => {
    if (!gameState.currentMissionId) return undefined;
    return missions.find(m => m.id === gameState.currentMissionId);
  }, [missions, gameState.currentMissionId]);

  // --- Derived: available missions ---
  const availableMissions = useMemo(() => {
    return missions.filter(m => {
      const isCleared = gameState.clearedMissions.includes(m.id);
      const matchesDomain = gameState.activeDomain === 'ALL' || m.domain === gameState.activeDomain;
      const searchLower = searchTerm.toLowerCase();
      const matchesSearch = searchTerm === '' ||
        m.title.toLowerCase().includes(searchLower) ||
        m.briefing.toLowerCase().includes(searchLower) ||
        m.tags.some(t => t.toLowerCase().includes(searchLower)) ||
        m.objectiveCodes.some(o => o.includes(searchLower));
      return !isCleared && matchesDomain && matchesSearch;
    });
  }, [missions, gameState.clearedMissions, gameState.activeDomain, searchTerm]);

  // --- Derived: available scenarios (test mode) ---
  const availableScenarios = useMemo(() => {
    if (gameState.mode !== 'test') return [];
    return scenarios.filter(s => {
      const isCleared = gameState.clearedScenarios.includes(s.id);
      const matchesDomain = gameState.activeDomain === 'ALL' || s.domain === gameState.activeDomain;
      const searchLower = searchTerm.toLowerCase();
      const matchesSearch = searchTerm === '' ||
        s.question.toLowerCase().includes(searchLower) ||
        s.id.toLowerCase().includes(searchLower) ||
        s.tags.some(t => t.toLowerCase().includes(searchLower)) ||
        s.objectiveCodes.some(o => o.includes(searchLower));
      return !isCleared && matchesDomain && matchesSearch;
    });
  }, [scenarios, gameState.clearedScenarios, gameState.activeDomain, searchTerm, gameState.mode]);

  const currentScenario: Scenario | undefined = useMemo(() => {
    if (!gameState.currentScenarioId) return undefined;
    return scenarios.find(s => s.id === gameState.currentScenarioId);
  }, [scenarios, gameState.currentScenarioId]);

  // --- Derived: investigation intel tracking ---
  const criticalNodes = currentMission?.intel.filter(n => n.critical) ?? [];
  const criticalViewed = criticalNodes.filter(n => viewedIntel.has(n.id)).length;
  const canProceedToChallenge = criticalViewed >= criticalNodes.length && criticalNodes.length > 0;

  // --- Persistence ---
  useEffect(() => { saveGame(gameState); }, [gameState]);

  // --- Cloud auth ---
  useEffect(() => {
    let unsubscribe: (() => void) | undefined;
    const initCloud = async () => {
      try {
        unsubscribe = onAuthStateChanged(auth, async (u) => {
          if (u) {
            setUser(u);
            addLog(`[CLOUD] Uplink established :: UID ${u.uid.slice(0, 6)}...`);
            try {
              const userDoc = await getDoc(doc(db, 'agents', u.uid));
              if (userDoc.exists()) {
                const cloudData = userDoc.data() as GameState;
                setGameState(prev => {
                  if (cloudData.xp > prev.xp) {
                    addLog('[CLOUD] Syncing remote profile...');
                    return {
                      ...cloudData,
                      currentScenarioId: prev.currentScenarioId || cloudData.currentScenarioId,
                      currentMissionId: prev.currentMissionId || cloudData.currentMissionId,
                      clearedMissions: cloudData.clearedMissions ?? prev.clearedMissions ?? [],
                      mode: prev.mode,
                    };
                  }
                  return prev;
                });
              }
            } catch (err) {
              console.error('Cloud fetch error', err);
            }
          } else {
            await signInAnonymously(auth);
          }
        });
      } catch (err) {
        addLog('[ERROR] Cloud uplink failed.');
      }
    };
    initCloud();
    return () => { if (unsubscribe) unsubscribe(); };
  }, []);

  // --- Cloud save ---
  useEffect(() => {
    if (!user || gameState.xp <= 0) return;
    const debounce = setTimeout(async () => {
      try {
        await setDoc(doc(db, 'agents', user.uid), {
          ...gameState,
          lastActive: new Date().toISOString()
        }, { merge: true });
      } catch (e) {
        console.error('Save failed', e);
      }
    }, 3000);
    return () => clearTimeout(debounce);
  }, [gameState, user]);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-49), msg]);
  };

  // ========================================
  // INVESTIGATION MODE ACTIONS
  // ========================================

  const startMission = (missionId: string) => {
    const mission = missions.find(m => m.id === missionId);
    if (!mission) return;
    setGameState(prev => ({ ...prev, currentMissionId: missionId }));
    setMissionPhase('briefing');
    setViewedIntel(new Set());
    setChallengeOption(null);
    setChallengeResult(null);
    addLog(`[ALERT] Incoming threat: ${mission.title}`);
    addLog(`[SYSTEM] Threat level: ${mission.threatLevel.toUpperCase()}`);
    addLog(`[SYSTEM] Domain: ${mission.domain}`);
  };

  const beginInvestigation = () => {
    setMissionPhase('investigating');
    addLog('[SYSTEM] Investigation phase initiated. Review available intelligence.');
    if (currentMission) {
      currentMission.intel.forEach((node, i) => {
        setTimeout(() => {
          addLog(`> [${node.type.toUpperCase()}] ${node.label} available`);
        }, 300 + (i * 400));
      });
    }
  };

  const viewIntelNode = (nodeId: string) => {
    setViewedIntel(prev => {
      const next = new Set(prev);
      if (!next.has(nodeId)) {
        const node = currentMission?.intel.find(n => n.id === nodeId);
        if (node) {
          addLog(`[INTEL] Reviewing: ${node.label}`);
          if (node.critical) {
            addLog(`[SYSTEM] Key evidence reviewed.`);
          }
        }
      }
      next.add(nodeId);
      return next;
    });
  };

  const proceedToChallenge = () => {
    setMissionPhase('challenge');
    addLog('[SYSTEM] All key intelligence reviewed. Awaiting your response.');
  };

  const submitMissionAnswer = () => {
    if (challengeOption === null || !currentMission) return;

    if (challengeOption === currentMission.challenge.correctIndex) {
      setChallengeResult('correct');
      addLog(`[SUCCESS] Correct response. Threat "${currentMission.title}" contained.`);

      setGameState(prev => {
        const investigateXp = 75;
        const correctBonus = 150 + (prev.streak * 15);
        const totalXp = investigateXp + correctBonus;
        const newXp = prev.xp + totalXp;
        const newLevel = Math.floor(newXp / 1000) + 1;

        return {
          ...prev,
          xp: newXp,
          streak: prev.streak + 1,
          clearedMissions: [...prev.clearedMissions, currentMission.id],
          level: newLevel,
        };
      });
    } else {
      setChallengeResult('incorrect');
      addLog(`[FAILURE] Incorrect response. ${currentMission.escalation ? 'Situation escalating...' : 'Review the debrief.'}`);

      setGameState(prev => {
        const investigateXp = 75;
        const newXp = prev.xp + investigateXp;
        const newLevel = Math.floor(newXp / 1000) + 1;
        return { ...prev, xp: newXp, streak: 0, level: newLevel };
      });
    }

    setMissionPhase('debrief');
  };

  const exitMission = () => {
    setGameState(prev => ({ ...prev, currentMissionId: null }));
    setMissionPhase('select');
    setViewedIntel(new Set());
    setChallengeOption(null);
    setChallengeResult(null);
  };

  // ========================================
  // QUIZ (TEST) MODE ACTIONS
  // ========================================

  const startScenario = (scenarioId: string) => {
    const s = scenarios.find(sc => sc.id === scenarioId);
    if (!s) return;
    setGameState(prev => ({ ...prev, currentScenarioId: s.id }));
    setQuizFeedback(null);
    setQuizOption(null);
    addLog(`[ALERT] Intercepting Signal: ${s.id} [${s.objectiveCodes.join(', ')}]`);
    s.logs.forEach((l, i) => {
      setTimeout(() => addLog(`> ${l}`), 500 + (i * 800));
    });
  };

  const submitQuizAnswer = () => {
    if (quizOption === null || !currentScenario) return;
    if (quizOption === currentScenario.correctIndex) {
      setQuizFeedback('correct');
      addLog(`[SUCCESS] Threat ${currentScenario.id} neutralized.`);
      setGameState(prev => {
        const xpGain = 100 + (prev.streak * 10);
        const newXp = prev.xp + xpGain;
        return {
          ...prev,
          xp: newXp,
          streak: prev.streak + 1,
          clearedScenarios: [...prev.clearedScenarios, currentScenario.id],
          level: Math.floor(newXp / 1000) + 1,
        };
      });
    } else {
      setQuizFeedback('incorrect');
      addLog(`[FAILURE] Countermeasure failed for ${currentScenario.id}.`);
      setGameState(prev => ({ ...prev, streak: 0 }));
    }
  };

  // ========================================
  // MODE TOGGLE
  // ========================================

  const toggleMode = () => {
    const newMode = gameState.mode === 'investigate' ? 'test' : 'investigate';
    setGameState(prev => ({
      ...prev,
      mode: newMode as 'investigate' | 'test',
      currentScenarioId: null,
      currentMissionId: null,
    }));
    setMissionPhase('select');
    setViewedIntel(new Set());
    setChallengeOption(null);
    setChallengeResult(null);
    setQuizOption(null);
    setQuizFeedback(null);
    addLog(`[SYSTEM] Mode switched to ${newMode.toUpperCase()}`);
  };

  const handleDomainChange = (domain: Domain | 'ALL') => {
    setGameState(prev => ({ ...prev, activeDomain: domain }));
    addLog(`[SYSTEM] Filter updated: ${domain}`);
  };

  const activeThreatLevel = gameState.mode === 'investigate'
    ? (currentMission?.threatLevel ?? 'low')
    : (currentScenario?.threatLevel ?? 'low');

  const isActive = gameState.mode === 'investigate'
    ? (currentMission !== undefined && missionPhase === 'investigating')
    : (currentScenario !== undefined && quizFeedback === null);

  const totalItems = gameState.mode === 'investigate' ? missions.length : scenarios.length;
  const clearedItems = gameState.mode === 'investigate' ? gameState.clearedMissions.length : gameState.clearedScenarios.length;
  const progressPct = totalItems > 0 ? Math.round((clearedItems / totalItems) * 100) : 0;

  // ========================================
  // RENDER
  // ========================================

  return (
    <div className="min-h-screen bg-cyber-black text-slate-200 p-4 font-mono selection:bg-cyber-cyan selection:text-cyber-black">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* Header */}
        <header className="flex justify-between items-center border-b border-cyber-slate/50 pb-4">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tighter flex items-center gap-2">
              <span className="text-cyber-rose">DARK</span>TRACE
              <span className="text-xs bg-cyber-slate px-2 py-1 rounded text-cyber-cyan">PRO_BUILD_v2.0</span>
            </h1>
            <p className="text-cyber-cyan/60 text-sm">SY0-701 FORENSIC RANGE</p>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={toggleMode}
              className={`text-xs px-3 py-1.5 rounded border transition-all ${
                gameState.mode === 'investigate'
                  ? 'bg-cyber-amber/10 border-cyber-amber/30 text-cyber-amber'
                  : 'bg-cyber-cyan/10 border-cyber-cyan/30 text-cyber-cyan'
              }`}
            >
              {gameState.mode === 'investigate' ? 'INVESTIGATE MODE' : 'TEST MODE'}
            </button>
            <button
              onClick={() => {
                if (confirm('Reset Campaign Progress?')) {
                  localStorage.removeItem('darktrace_save_v1');
                  window.location.reload();
                }
              }}
              className="text-xs text-cyber-rose/50 hover:text-cyber-rose transition-colors"
            >
              RESET
            </button>
          </div>
        </header>

        <IntelHUD state={gameState} />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

          {/* Left Sidebar */}
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

            <div className="bg-cyber-slate/20 rounded-lg p-4 border border-cyber-slate/50">
              <div className="flex justify-between text-xs mb-2">
                <span>PROGRESS</span>
                <span>{progressPct}%</span>
              </div>
              <div className="h-2 bg-cyber-dark rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyber-cyan to-cyber-emerald transition-all duration-500"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
              <div className="text-[10px] text-gray-600 mt-1">
                {clearedItems} / {totalItems} {gameState.mode === 'investigate' ? 'missions' : 'scenarios'}
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-6">
            <div className="bg-cyber-slate/20 rounded-lg border border-cyber-slate/50 min-h-[600px] flex flex-col relative overflow-hidden">

              {/* ====== INVESTIGATE MODE ====== */}
              {gameState.mode === 'investigate' && (
                <>
                  {/* Mission Select */}
                  {missionPhase === 'select' && !currentMission && (
                    <div className="flex-1 flex flex-col p-6">
                      <SignalSearch searchTerm={searchTerm} setSearchTerm={setSearchTerm} resultCount={availableMissions.length} />
                      <div className="flex-1 overflow-y-auto pr-2 space-y-2">
                        {availableMissions.length === 0 ? (
                          <div className="flex flex-col items-center justify-center h-full text-gray-500">
                            <Shield className="w-12 h-12 mb-2 opacity-20" />
                            <p>ALL THREATS NEUTRALIZED</p>
                            <p className="text-xs mt-1 text-gray-600">Switch to TEST MODE to practice exam questions</p>
                          </div>
                        ) : (
                          availableMissions.map(m => (
                            <div
                              key={m.id}
                              onClick={() => startMission(m.id)}
                              className="bg-cyber-dark/50 p-4 rounded border border-cyber-slate/30 hover:border-cyber-amber/50 hover:bg-cyber-slate/30 cursor-pointer transition-all group"
                            >
                              <div className="flex justify-between items-center mb-1">
                                <span className="text-cyber-amber font-bold text-xs flex items-center gap-2">
                                  {m.id}
                                  {m.objectiveCodes.map(code => (
                                    <span key={code} className="bg-cyber-slate text-gray-400 px-1 rounded text-[9px] border border-cyber-slate/50">OBJ {code}</span>
                                  ))}
                                </span>
                                <span className={`text-[10px] px-2 py-0.5 rounded ${
                                  m.threatLevel === 'critical' ? 'bg-cyber-rose/20 text-cyber-rose' :
                                  m.threatLevel === 'high' ? 'bg-orange-500/20 text-orange-500' :
                                  m.threatLevel === 'medium' ? 'bg-cyber-amber/20 text-cyber-amber' :
                                  'bg-cyber-emerald/20 text-cyber-emerald'
                                }`}>{m.threatLevel.toUpperCase()}</span>
                              </div>
                              <div className="text-white text-sm font-bold mb-1 group-hover:text-cyber-amber transition-colors">{m.title}</div>
                              <div className="text-gray-400 text-xs line-clamp-2">{m.briefing}</div>
                              <div className="flex gap-2 mt-2">
                                {m.tags.slice(0, 3).map(tag => (
                                  <span key={tag} className="text-[10px] text-gray-500 bg-cyber-black/50 px-1 rounded">#{tag}</span>
                                ))}
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}

                  {/* Briefing */}
                  {missionPhase === 'briefing' && currentMission && (
                    <MissionBriefing mission={currentMission} onBeginInvestigation={beginInvestigation} />
                  )}

                  {/* Investigating */}
                  {missionPhase === 'investigating' && currentMission && (
                    <IntelExplorer
                      intelNodes={currentMission.intel}
                      viewedIds={viewedIntel}
                      onViewIntel={viewIntelNode}
                      onProceedToChallenge={proceedToChallenge}
                      canProceed={canProceedToChallenge}
                      criticalCount={criticalNodes.length}
                      criticalViewed={criticalViewed}
                    />
                  )}

                  {/* Challenge */}
                  {missionPhase === 'challenge' && currentMission && challengeResult === null && (
                    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex-1 p-6 flex flex-col">
                      <div className="flex items-center gap-2 mb-4">
                        <Crosshair className="w-5 h-5 text-cyber-rose" />
                        <h3 className="text-cyber-rose font-bold text-sm tracking-wider">INCIDENT RESPONSE</h3>
                      </div>
                      <h2 className="text-lg font-bold text-white mb-6 leading-relaxed">{currentMission.challenge.question}</h2>
                      <div className="space-y-3 flex-1">
                        {currentMission.challenge.options.map((opt, idx) => (
                          <button
                            key={idx}
                            onClick={() => setChallengeOption(idx)}
                            className={`w-full text-left p-4 rounded border transition-all duration-200 ${
                              challengeOption === idx
                                ? 'bg-cyber-slate border-cyber-cyan text-cyber-cyan'
                                : 'bg-cyber-dark/50 border-cyber-slate/50 hover:border-gray-500 text-gray-300'
                            }`}
                          >
                            <div className="flex items-center gap-3">
                              <div className={`w-6 h-6 flex items-center justify-center rounded text-xs border ${challengeOption === idx ? 'border-cyber-cyan' : 'border-gray-600'}`}>
                                {String.fromCharCode(65 + idx)}
                              </div>
                              <span className="text-sm">{opt}</span>
                            </div>
                          </button>
                        ))}
                      </div>
                      <div className="mt-6 pt-4 border-t border-cyber-slate/50">
                        <button
                          onClick={submitMissionAnswer}
                          disabled={challengeOption === null}
                          className="ml-auto bg-cyber-cyan disabled:opacity-50 disabled:cursor-not-allowed hover:bg-cyber-cyan/80 text-cyber-black font-bold py-2 px-6 rounded transition-all block"
                        >
                          EXECUTE COUNTERMEASURE
                        </button>
                      </div>
                    </motion.div>
                  )}

                  {/* Debrief */}
                  {missionPhase === 'debrief' && currentMission && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex-1 p-6 flex flex-col overflow-y-auto">
                      {/* Result banner */}
                      <div className={`rounded-lg p-4 mb-6 border ${
                        challengeResult === 'correct' ? 'bg-cyber-emerald/10 border-cyber-emerald/30' : 'bg-cyber-rose/10 border-cyber-rose/30'
                      }`}>
                        <div className="flex items-center gap-2 mb-2">
                          {challengeResult === 'correct' ? (
                            <><CheckCircle className="w-5 h-5 text-cyber-emerald" /><span className="font-bold text-cyber-emerald">THREAT NEUTRALIZED</span></>
                          ) : (
                            <><XCircle className="w-5 h-5 text-cyber-rose" /><span className="font-bold text-cyber-rose">RESPONSE FAILED</span></>
                          )}
                        </div>
                        <p className={`text-xs ${challengeResult === 'correct' ? 'text-cyber-emerald/80' : 'text-cyber-rose/80'}`}>
                          {challengeResult === 'correct'
                            ? '+225 XP (75 investigation + 150 correct response + streak bonus)'
                            : '+75 XP (investigation completed — you still learned from the evidence)'}
                        </p>
                      </div>

                      {/* Option rationales */}
                      <div className="space-y-2 mb-6">
                        {currentMission.challenge.options.map((opt, idx) => (
                          <div key={idx} className="space-y-1">
                            <div className={`p-3 rounded border text-sm ${
                              idx === currentMission.challenge.correctIndex ? 'bg-cyber-emerald/10 border-cyber-emerald/30 text-cyber-emerald' :
                              idx === challengeOption && challengeOption !== currentMission.challenge.correctIndex ? 'bg-cyber-rose/10 border-cyber-rose/30 text-cyber-rose' :
                              'bg-cyber-dark/30 border-cyber-slate/30 text-gray-500'
                            }`}>
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-xs">{String.fromCharCode(65 + idx)}.</span>
                                <span>{opt}</span>
                              </div>
                            </div>
                            <p className={`text-xs pl-6 ${idx === currentMission.challenge.correctIndex ? 'text-cyber-emerald/70' : 'text-gray-600'}`}>
                              {currentMission.challenge.rationales[idx]}
                            </p>
                          </div>
                        ))}
                      </div>

                      {/* Escalation (wrong only) */}
                      {challengeResult === 'incorrect' && currentMission.escalation && (
                        <div className="bg-cyber-rose/5 rounded-lg p-4 mb-6 border-l-4 border-cyber-rose">
                          <h4 className="text-cyber-rose font-bold text-sm mb-2 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" /> ESCALATION
                          </h4>
                          <p className="text-sm text-gray-300 leading-relaxed">{currentMission.escalation}</p>
                        </div>
                      )}

                      {/* Debrief */}
                      <div className="bg-cyber-dark rounded-lg p-4 mb-6 border-l-4 border-cyber-cyan">
                        <h4 className="text-cyber-cyan font-bold text-sm mb-2 flex items-center gap-2">
                          <BookOpen className="w-4 h-4" /> DEBRIEF
                        </h4>
                        <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">{currentMission.debrief}</p>
                      </div>

                      {/* References */}
                      <div className="flex flex-wrap gap-2 mb-6">
                        {currentMission.refs.map((ref, i) => (
                          <span key={i} className="text-xs bg-cyber-slate/50 px-3 py-1 rounded text-cyber-cyan flex items-center gap-2 border border-cyber-cyan/20">
                            <FileText className="w-3 h-3" /> {ref.source}: {ref.section} {ref.page ? `(p.${ref.page})` : ''}
                          </span>
                        ))}
                      </div>

                      {/* Actions */}
                      <div className="mt-auto pt-4 border-t border-cyber-slate/30 flex gap-3">
                        {challengeResult === 'incorrect' && (
                          <button
                            onClick={() => {
                              setChallengeOption(null);
                              setChallengeResult(null);
                              setMissionPhase('investigating');
                              addLog('[SYSTEM] Reopening investigation for retry...');
                            }}
                            className="flex-1 bg-cyber-amber/20 hover:bg-cyber-amber/30 text-cyber-amber font-bold py-3 rounded border border-cyber-amber/30 transition-all"
                          >
                            RETRY INVESTIGATION
                          </button>
                        )}
                        <button
                          onClick={exitMission}
                          className="flex-1 bg-cyber-slate hover:bg-cyber-slate/80 text-white font-bold py-3 rounded transition-all"
                        >
                          {challengeResult === 'correct' ? 'NEXT MISSION' : 'RETURN TO MISSIONS'}
                        </button>
                      </div>
                    </motion.div>
                  )}
                </>
              )}

              {/* ====== TEST MODE ====== */}
              {gameState.mode === 'test' && (
                <>
                  {!currentScenario ? (
                    <div className="flex-1 flex flex-col p-6">
                      <SignalSearch searchTerm={searchTerm} setSearchTerm={setSearchTerm} resultCount={availableScenarios.length} />
                      {loadingScenarios ? (
                        <div className="flex-1 flex items-center justify-center text-gray-500"><p>Loading scenarios from database...</p></div>
                      ) : (
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
                                onClick={() => startScenario(s.id)}
                                className="bg-cyber-dark/50 p-4 rounded border border-cyber-slate/30 hover:border-cyber-cyan/50 hover:bg-cyber-slate/30 cursor-pointer transition-all group"
                              >
                                <div className="flex justify-between items-center mb-1">
                                  <span className="text-cyber-cyan font-bold text-xs flex items-center gap-2">
                                    {s.id}
                                    {s.objectiveCodes.map(code => (
                                      <span key={code} className="bg-cyber-slate text-gray-400 px-1 rounded text-[9px] border border-cyber-slate/50">OBJ {code}</span>
                                    ))}
                                  </span>
                                  <span className={`text-[10px] px-2 py-0.5 rounded ${
                                    s.threatLevel === 'critical' ? 'bg-cyber-rose/20 text-cyber-rose' :
                                    s.threatLevel === 'high' ? 'bg-orange-500/20 text-orange-500' :
                                    'bg-cyber-emerald/20 text-cyber-emerald'
                                  }`}>{s.threatLevel.toUpperCase()}</span>
                                </div>
                                <div className="text-gray-400 text-sm line-clamp-2 group-hover:text-white transition-colors">{s.question}</div>
                                <div className="flex gap-2 mt-2">
                                  {s.tags.slice(0, 3).map(tag => (
                                    <span key={tag} className="text-[10px] text-gray-500 bg-cyber-black/50 px-1 rounded">#{tag}</span>
                                  ))}
                                </div>
                              </div>
                            ))
                          )}
                        </div>
                      )}
                      {availableScenarios.length > 0 && (
                        <div className="mt-4 pt-4 border-t border-cyber-slate/30">
                          <button
                            onClick={() => {
                              const idx = Math.floor(Math.random() * availableScenarios.length);
                              startScenario(availableScenarios[idx].id);
                            }}
                            className="w-full bg-cyber-cyan hover:bg-cyber-cyan/80 text-cyber-black font-bold py-3 px-8 rounded flex items-center justify-center gap-2 transition-all hover:scale-[1.02]"
                          >
                            <Play className="w-5 h-5" /> ENGAGE RANDOM TARGET
                          </button>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex-1 p-6 flex flex-col">
                      <div className="flex justify-between items-start mb-6">
                        <div className="flex flex-col">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-bold text-cyber-rose bg-cyber-rose/10 px-2 py-1 rounded border border-cyber-rose/20">INCIDENT: {currentScenario.id}</span>
                            {currentScenario.objectiveCodes.map(oc => (
                              <span key={oc} className="text-[10px] font-mono text-cyber-cyan bg-cyber-cyan/10 px-1 py-0.5 rounded">OBJ {oc}</span>
                            ))}
                          </div>
                          <span className="text-xs text-gray-500">{currentScenario.domain}</span>
                        </div>
                      </div>

                      <h2 className="text-xl font-bold text-white mb-8 leading-relaxed">{currentScenario.question}</h2>

                      <div className="space-y-3 flex-1">
                        {currentScenario.options.map((opt, idx) => {
                          let optionClass = 'bg-cyber-dark/50 border-cyber-slate/50 hover:border-gray-500 text-gray-300';
                          if (quizFeedback) {
                            if (idx === currentScenario.correctIndex) optionClass = '!bg-cyber-emerald/20 !border-cyber-emerald !text-cyber-emerald';
                            else if (idx === quizOption && quizOption !== currentScenario.correctIndex) optionClass = '!bg-cyber-rose/20 !border-cyber-rose !text-cyber-rose';
                            else optionClass = 'bg-cyber-dark/30 border-cyber-slate/30 text-gray-600';
                          } else if (quizOption === idx) optionClass = 'bg-cyber-slate border-cyber-cyan text-cyber-cyan';

                          return (
                            <div key={idx} className="space-y-2">
                              <button
                                disabled={quizFeedback !== null}
                                onClick={() => setQuizOption(idx)}
                                className={`w-full text-left p-4 rounded border transition-all duration-200 ${optionClass}`}
                              >
                                <div className="flex items-center gap-3">
                                  <div className={`w-6 h-6 flex items-center justify-center rounded text-xs border ${
                                    quizFeedback && idx === currentScenario.correctIndex ? 'border-cyber-emerald' :
                                    quizFeedback && idx === quizOption ? 'border-cyber-rose' :
                                    quizOption === idx ? 'border-cyber-cyan' : 'border-gray-600'
                                  }`}>{String.fromCharCode(65 + idx)}</div>
                                  <span>{opt}</span>
                                </div>
                              </button>
                              {quizFeedback && (
                                <motion.div
                                  initial={{ opacity: 0, height: 0 }}
                                  animate={{ opacity: 1, height: 'auto' }}
                                  className={`text-xs pl-11 pr-4 py-2 border-l-2 ${
                                    idx === currentScenario.correctIndex ? 'border-cyber-emerald text-cyber-emerald/80' : 'border-cyber-slate text-gray-500'
                                  }`}
                                >{currentScenario.rationales[idx]}</motion.div>
                              )}
                            </div>
                          );
                        })}
                      </div>

                      <div className="mt-8 pt-4 border-t border-cyber-slate/50 flex justify-between items-center">
                        {quizFeedback === null ? (
                          <button
                            onClick={submitQuizAnswer}
                            disabled={quizOption === null}
                            className="ml-auto bg-cyber-cyan disabled:opacity-50 disabled:cursor-not-allowed hover:bg-cyber-cyan/80 text-cyber-black font-bold py-2 px-6 rounded transition-all"
                          >EXECUTE COUNTERMEASURE</button>
                        ) : (
                          <div className="w-full flex justify-between items-center">
                            <div className="flex items-center gap-2">
                              {quizFeedback === 'correct' ? (
                                <span className="flex items-center gap-2 text-cyber-emerald font-bold"><CheckCircle className="w-5 h-5" /> THREAT NEUTRALIZED</span>
                              ) : (
                                <span className="flex items-center gap-2 text-cyber-rose font-bold"><XCircle className="w-5 h-5" /> BREACH SUCCESSFUL</span>
                              )}
                            </div>
                            <button
                              onClick={() => setGameState(prev => ({ ...prev, currentScenarioId: null }))}
                              className="bg-cyber-slate hover:bg-cyber-slate/80 text-white font-bold py-2 px-6 rounded border border-cyber-slate transition-all"
                            >NEXT INCIDENT</button>
                          </div>
                        )}
                      </div>

                      <AnimatePresence>
                        {quizFeedback !== null && (
                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                            <div className="mt-4 bg-cyber-dark p-4 rounded border-l-4 border-cyber-cyan space-y-4">
                              <div>
                                <h4 className="text-cyber-cyan font-bold text-sm mb-1 flex items-center gap-2"><BookOpen className="w-4 h-4" /> ANALYSIS</h4>
                                <p className="text-sm text-gray-300 leading-relaxed">{currentScenario.explanation}</p>
                              </div>
                              <div className="flex gap-2">
                                {currentScenario.refs.map((ref, i) => (
                                  <span key={i} className="text-xs bg-cyber-slate/50 px-3 py-1 rounded text-cyber-cyan flex items-center gap-2 border border-cyber-cyan/20">
                                    <FileText className="w-3 h-3" /> {ref.source}: {ref.section}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}
                </>
              )}

            </div>
          </div>

          {/* Right Sidebar */}
          <div className="lg:col-span-3 space-y-6">
            <div>
              <h3 className="text-xs font-bold text-gray-500 mb-2 tracking-wider">NETWORK STATUS</h3>
              <NetworkMap active={isActive} threatLevel={activeThreatLevel} />
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

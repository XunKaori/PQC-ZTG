import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Cpu, 
  Lock, 
  Unlock, 
  Zap, 
  RefreshCcw,
  Network,
  ArrowRight,
  Server,
  Monitor
} from 'lucide-react';
import * as Kyber from 'crystals-kyber-ts';

// Helper for hex conversion
const toHex = (arr: number[] | Uint8Array) => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex: string) => Array.from(new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))));

// SPA Config
const SPA_SECRET = "pqc_demo_secret";

// Simple HMAC helper for browser (SHA256)
async function generateSPAPacket(clientId: string) {
  const t = Date.now();
  const n = Math.random().toString(36).substring(2);
  const payloadStr = `${t}:${clientId}:${n}`;
  
  const encoder = new TextEncoder();
  const keyData = encoder.encode(SPA_SECRET);
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payloadStr));
  const s = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  
  const packet = { t, id: clientId, n, s };
  return btoa(JSON.stringify(packet));
}

// --- Types ---
interface Status {
  gatewayStatus: 'HIDDEN' | 'OPEN' | 'ACTIVE';
  sessionCount: number;
  logs: string[];
}

interface Session {
  sessionId: string;
  sharedSecret: string;
}

export default function App() {
  const [status, setStatus] = useState<Status>({
    gatewayStatus: 'HIDDEN',
    sessionCount: 0,
    logs: []
  });
  const [sessionsMap, setSessionsMap] = useState<Record<string, Session>>({});
  const [activeIdentity, setActiveIdentity] = useState<'ALPHA' | 'BETA'>('ALPHA');
  const [peers, setPeers] = useState<{id: string, clientId: string}[]>([]);
  const [targetPeer, setTargetPeer] = useState<string>('');
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [messagesMap, setMessagesMap] = useState<Record<string, { sender: string, text: string, type?: 'file', fileName?: string, isSelf: boolean, peerId: string, content?: string }[]>>({
    ALPHA: [],
    BETA: []
  });
  const [isSimulating, setIsSimulating] = useState(false);
  const [inputText, setInputText] = useState('');
  const [lastResponse, setLastResponse] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Fetch status and peers periodically
  useEffect(() => {
    const timer = setInterval(() => {
      fetchStatus();
      fetchPeers();
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  // Poll for messages for all connected identities in background
  useEffect(() => {
    const pollAll = async () => {
      const activeIds = Object.keys(sessionsMap);
      for (const id of activeIds) {
        const clientId = id === 'ALPHA' ? 'Agent-Alpha' : 'Agent-Beta';
        try {
          const res = await fetch(`/api/messages/${clientId}`);
          const newMessages = await res.json();
          if (newMessages.length > 0) {
            setMessagesMap(prev => ({
              ...prev,
              [id]: [
                ...prev[id],
                ...newMessages.map((m: any) => {
                  // Find the session ID for the sender
                  const senderPeer = peers.find(p => p.clientId === m.from);
                  return {
                    sender: m.from,
                    text: m.type === 'file' ? `Received file: ${m.fileName}` : m.content,
                    type: m.type,
                    fileName: m.fileName,
                    content: m.type === 'file' ? m.content : undefined,
                    isSelf: false,
                    peerId: senderPeer ? senderPeer.id : 'RELAY'
                  };
                })
              ]
            }));
          }
        } catch (e) { console.error(e); }
      }
    };

    const msgTimer = setInterval(pollAll, 1500);
    return () => clearInterval(msgTimer);
  }, [sessionsMap, peers]);

  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollTop = consoleEndRef.current.scrollHeight;
    }
  }, [status.logs]);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollTop = chatEndRef.current.scrollHeight;
    }
  }, [messagesMap, activeIdentity, targetPeer]);

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      setStatus(data);
    } catch (e) {
      console.error("Failed to fetch status", e);
    }
  };

  const fetchPeers = async () => {
    try {
      const res = await fetch('/api/peers');
      const data = await res.json();
      setPeers(data);
    } catch (e) { console.error(e); }
  };

  const handleReset = async () => {
    await fetch('/api/reset', { method: 'POST' });
    setSessionsMap({});
    setCurrentSession(null);
    setMessagesMap({ ALPHA: [], BETA: [] });
    setLastResponse(null);
    fetchStatus();
  };

  const runSimulation = async (identityOverride?: 'ALPHA' | 'BETA') => {
    setIsSimulating(true);
    const targetIdentity = identityOverride || activeIdentity;
    const clientId = targetIdentity === 'ALPHA' ? 'Agent-Alpha' : 'Agent-Beta';
    
    try {
      // 1. Knock (Real SPA)
      const packet = await generateSPAPacket(clientId);
      const knockRes = await fetch('/api/simulate/knock', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packet })
      });
      const knockData = await knockRes.json();
      
      if (knockData.error) throw new Error(knockData.error);
      
      // Wait for UI to show "Gateway Open"
      await new Promise(r => setTimeout(r, 1000));
      
      // 2. Handshake Phase 1: Request Gateway Public Key
      const handshakeInitRes = await fetch('/api/simulate/handshake/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: knockData.sessionId })
      });
      const { publicKey } = await handshakeInitRes.json();
      
      // 3. Client Encapsulation
      const clientKyber = new Kyber.Kyber768Handshake();
      const ciphertextArr = clientKyber.generateCipherTextAndSharedSecret(fromHex(publicKey));
      const ssHex = toHex(clientKyber.sharedSecret);
      const ctHex = toHex(ciphertextArr);
      
      // 4. Handshake Phase 2: Send Ciphertext to Gateway
      await fetch('/api/simulate/handshake/finalize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          sessionId: knockData.sessionId,
          ciphertext: ctHex
        })
      });
      
      const newSess = {
        sessionId: knockData.sessionId,
        sharedSecret: ssHex
      };

      setSessionsMap(prev => ({ ...prev, [targetIdentity]: newSess }));
      if (activeIdentity === targetIdentity) setCurrentSession(newSess);
      
    } catch (e) {
      console.error(e);
    } finally {
      setIsSimulating(false);
    }
  };

  const sendData = async (type: 'text' | 'file' = 'text', fileData?: { name: string, content: string }) => {
    if (!currentSession) return;
    
    const payload = type === 'text' ? inputText : fileData?.content;
    const targetLabel = targetPeer ? peers.find(p => p.id === targetPeer)?.clientId : 'Quantum Relay';

    const msgObj = { 
      sender: activeIdentity === 'ALPHA' ? 'Agent-Alpha' : 'Agent-Beta', 
      text: type === 'text' ? inputText : `Sent file: ${fileData?.name}`,
      type, 
      fileName: fileData?.name,
      content: type === 'file' ? fileData?.content : undefined,
      isSelf: true,
      peerId: targetPeer || 'RELAY'
    };

    setMessagesMap(prev => ({
      ...prev,
      [activeIdentity]: [...prev[activeIdentity], msgObj]
    }));
    
    if (type === 'text') setInputText('');

    try {
      const res = await fetch('/api/simulate/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          sessionId: currentSession.sessionId,
          data: payload,
          type,
          fileName: fileData?.name,
          targetClientId: targetPeer
        })
      });
      const data = await res.json();
      if (data.response && targetPeer === '') {
        setMessagesMap(prev => ({
          ...prev,
          [activeIdentity]: [...prev[activeIdentity], { sender: 'System Relay', text: data.response, isSelf: false, peerId: 'RELAY' }]
        }));
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    setCurrentSession(sessionsMap[activeIdentity] || null);
  }, [activeIdentity, sessionsMap]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      const content = event.target?.result as string;
      await sendData('file', { name: file.name, content });
    };
    reader.readAsDataURL(file);
    // Reset input
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-[#e0e0e0] font-mono selection:bg-[#3b82f6] selection:text-white overflow-x-hidden">
      {/* Background Grid Accent */}
      <div className="fixed inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-10 pointer-events-none" />
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#3b82f6]/30 to-transparent" />

      <div className="max-w-7xl mx-auto px-6 py-12 relative z-10">
        {/* Header */}
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center mb-12 gap-6">
          <div>
            <motion.div 
              initial={{ x: -20, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              className="flex items-center gap-3 mb-2"
            >
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <Shield className="w-8 h-8 text-blue-500" />
              </div>
              <h1 className="text-3xl font-bold tracking-tight text-white">
                PQC-ZTG <span className="text-sm font-normal text-blue-500/60 ml-2">v1.0.4-LTS</span>
              </h1>
            </motion.div>
            <p className="text-gray-500 text-sm max-w-xl">
              Post-Quantum Cryptography & Zero Trust Gateway. 
              Protecting against "Harvest Now, Decrypt Later" with ML-KEM-768 and SPA.
            </p>
          </div>

          <div className="flex gap-4">
            <button 
              onClick={handleReset}
              className="flex items-center gap-2 px-4 py-2 bg-gray-900 border border-gray-800 rounded-md hover:bg-gray-800 transition-colors text-xs"
            >
              <RefreshCcw className="w-4 h-4" /> RESET SYSTEM
            </button>
            <div className={`flex items-center gap-2 px-4 py-2 border rounded-md text-xs font-bold transition-all duration-500 ${
              status.gatewayStatus === 'HIDDEN' ? 'border-red-900/50 bg-red-950/20 text-red-500' : 
              status.gatewayStatus === 'OPEN' ? 'border-yellow-900/50 bg-yellow-950/20 text-yellow-500' :
              'border-green-900/50 bg-green-950/20 text-green-500'
            }`}>
              <div className={`w-2 h-2 rounded-full animate-pulse ${
                status.gatewayStatus === 'HIDDEN' ? 'bg-red-500' : 
                status.gatewayStatus === 'OPEN' ? 'bg-yellow-500' : 'bg-green-500'
              }`} />
              GATEWAY: {status.gatewayStatus}
            </div>
          </div>
        </header>

        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Column 1: System Control */}
          <div className="space-y-8">
            <section className="bg-[#111114] border border-white/5 rounded-xl p-6 shadow-2xl relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/5 blur-3xl -mr-16 -mt-16 group-hover:bg-blue-500/10 transition-all" />
              <h2 className="text-sm font-bold text-gray-400 mb-6 flex items-center gap-2 uppercase tracking-widest">
                <Cpu className="w-4 h-4" /> Protocol Control
              </h2>
              
              <div className="space-y-6">
                <div>
                  <label className="text-[10px] text-gray-500 uppercase block mb-3">Operating Identity</label>
                  <div className="grid grid-cols-2 gap-2 p-1 bg-black/40 rounded-lg border border-white/5">
                    <button 
                      onClick={() => setActiveIdentity('ALPHA')}
                      className={`py-2 text-[10px] rounded font-bold transition-all ${activeIdentity === 'ALPHA' ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/40' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      AGENT-ALPHA
                    </button>
                    <button 
                      onClick={() => setActiveIdentity('BETA')}
                      className={`py-2 text-[10px] rounded font-bold transition-all ${activeIdentity === 'BETA' ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/40' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      AGENT-BETA
                    </button>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 uppercase block mb-2">Simulation Engine</label>
                  <button 
                    disabled={isSimulating || currentSession !== null}
                    onClick={() => runSimulation()}
                    className={`w-full py-4 rounded-lg flex items-center justify-center gap-3 transition-all ${
                      isSimulating || currentSession !== null ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/20'
                    }`}
                  >
                    {isSimulating ? (
                      <RefreshCcw className="w-5 h-5 animate-spin" />
                    ) : (
                      <Zap className="w-5 h-5" />
                    )}
                    {currentSession ? 'CHANNEL SECURE' : (isSimulating ? 'EXECUTING PIPELINE...' : `CONNECT ${activeIdentity}`)}
                  </button>
                </div>

                <div className="bg-black/40 rounded-lg p-4 border border-white/5">
                  <label className="text-[10px] text-gray-500 uppercase block mb-3">Post-Quantum Tunnel</label>
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-400">PQC Algorithm</span>
                      <span className="text-blue-400">ML-KEM-768</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-400">SPA Status</span>
                      <span className={status.gatewayStatus !== 'HIDDEN' ? 'text-green-500' : 'text-red-500'}>
                        {status.gatewayStatus !== 'HIDDEN' ? 'VERIFIED' : 'PENDING'}
                      </span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-400">Ephemeral Key</span>
                      <span className="text-green-500 truncate ml-4">
                        {currentSession?.sharedSecret ? `${currentSession.sharedSecret.slice(0, 12)}...` : 'NONE'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className="bg-[#111114] border border-white/5 rounded-xl p-6 shadow-2xl h-[500px] flex flex-col">
              <h2 className="text-sm font-bold text-gray-400 mb-6 flex items-center gap-2 uppercase tracking-widest">
                <Lock className="w-4 h-4" /> Secure Transmission
              </h2>

              <div className="mb-4">
                <label className="text-[9px] text-gray-500 uppercase block mb-2">Relay Target</label>
                <select 
                  value={targetPeer}
                  onChange={(e) => setTargetPeer(e.target.value)}
                  className="w-full bg-black/60 border border-white/10 rounded-lg px-2 py-2 text-[10px] text-blue-400 focus:outline-none"
                >
                  <option value="">QUANTUM RELAY (AUTO)</option>
                  {peers.filter(p => p.clientId !== (activeIdentity === 'ALPHA' ? 'Agent-Alpha' : 'Agent-Beta')).map(p => (
                    <option key={p.id} value={p.id}>{p.clientId} (SECURE)</option>
                  ))}
                </select>
              </div>
              
              {/* Chat View */}
              <div 
                ref={chatEndRef}
                className="flex-grow overflow-y-auto mb-4 space-y-4 pr-2"
              >
                <AnimatePresence>
                  {messagesMap[activeIdentity]
                    .filter(m => m.peerId === (targetPeer || 'RELAY'))
                    .map((m, i) => {
                    if (m.sender === 'System Relay') {
                      return (
                        <motion.div 
                          key={i}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          className="flex justify-center my-2"
                        >
                          <span className="text-[10px] text-gray-500 font-mono tracking-tighter bg-white/5 px-2 py-0.5 rounded uppercase">
                            [Relay] {m.text}
                          </span>
                        </motion.div>
                      );
                    }
                    return (
                      <motion.div 
                        key={i}
                        initial={{ y: 10, opacity: 0 }}
                        animate={{ y: 0, opacity: 1 }}
                        className={`flex flex-col ${m.isSelf ? 'items-end' : 'items-start'}`}
                      >
                        <span className="text-[9px] text-gray-600 mb-1 font-bold">{m.sender}</span>
                        <div className={`max-w-[80%] rounded-lg px-3 py-2 text-xs shadow-sm ${
                          m.isSelf ? 'bg-blue-600 text-white rounded-tr-none' : 'bg-[#1a1a1f] text-gray-300 border border-white/5 rounded-tl-none'
                        }`}>
                           {m.type === 'file' ? (
                             <div className="flex flex-col gap-2">
                                <div className="flex items-center gap-2">
                                  <Server className="w-3 h-3 text-blue-300" /> {m.text}
                                </div>
                                {!m.isSelf && (
                                  <button 
                                    onClick={() => {
                                      if (!m.content) return;
                                      const link = document.createElement('a');
                                      link.href = m.content;
                                      link.download = m.fileName || 'quantum_secure_file';
                                      document.body.appendChild(link);
                                      link.click();
                                      document.body.removeChild(link);
                                    }}
                                    className="text-[10px] text-blue-400 hover:underline text-left"
                                  >
                                    [RESTORE DATA]
                                  </button>
                                )}
                             </div>
                           ) : m.text}
                        </div>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
                {messagesMap[activeIdentity].filter(m => m.peerId === (targetPeer || 'RELAY')).length === 0 && (
                  <div className="h-full flex flex-col items-center justify-center text-center opacity-20">
                    <div className="p-4 rounded-full bg-white/5 mb-4">
                      <ShieldCheck className="w-12 h-12" />
                    </div>
                    <p className="text-xs uppercase tracking-widest font-bold">Encrypted Session Active</p>
                    <p className="text-[10px] mt-2">Waiting for quantum-safe traffic...</p>
                  </div>
                )}
              </div>

              <div className="space-y-4 pt-4 border-t border-white/5">
                <div className="flex gap-2">
                  <input 
                    type="text"
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && currentSession && sendData('text')}
                    disabled={!currentSession}
                    className="flex-grow bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-blue-500/50 transition-all text-gray-300"
                    placeholder="Enter message..."
                  />
                  <input 
                    type="file" 
                    ref={fileInputRef} 
                    className="hidden" 
                    onChange={handleFileUpload}
                  />
                  <button 
                    onClick={() => fileInputRef.current?.click()}
                    disabled={!currentSession}
                    className="p-2 bg-gray-900 border border-white/10 rounded-lg hover:bg-gray-800 disabled:opacity-30 transition-all"
                    title="Send File"
                  >
                    <Network className="w-4 h-4 text-blue-400" />
                  </button>
                </div>
                <button 
                  disabled={!currentSession || !inputText.trim()}
                  onClick={() => sendData('text')}
                  className="w-full py-2 bg-white text-black font-bold rounded-lg hover:bg-gray-200 disabled:bg-gray-800 disabled:text-gray-600 transition-all flex items-center justify-center gap-2 text-xs"
                >
                  SEND <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </section>
          </div>

          {/* Column 2: Visual Map */}
          <div className="lg:col-span-2 space-y-8 flex flex-col">
            <section className="bg-[#111114] border border-white/5 rounded-xl p-6 shadow-2xl flex-grow relative overflow-hidden">
               <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_transparent_0%,_#000_100%)] pointer-events-none opacity-40" />
               
               <h2 className="text-sm font-bold text-gray-400 mb-6 flex items-center gap-2 uppercase tracking-widest relative z-10">
                <Network className="w-4 h-4" /> Topology & Handshake
              </h2>

              <div className="relative h-64 flex items-center justify-around z-10">
                {/* Client Node */}
                <div className="flex flex-col items-center gap-3">
                  <div className={`p-4 rounded-2xl transition-all duration-700 shadow-2xl ${
                    status.gatewayStatus !== 'HIDDEN' ? 'bg-blue-600/20 border border-blue-500/50 text-blue-400 shadow-blue-500/20' : 'bg-gray-800 border border-white/5 text-gray-500'
                  }`}>
                    <Monitor className="w-12 h-12" />
                  </div>
                  <span className="text-[10px] font-bold tracking-widest">PQC_CLIENT</span>
                </div>

                {/* Connection Line */}
                <div className="flex-grow max-w-[200px] h-[2px] bg-gray-800 relative">
                   <div className={`absolute inset-0 h-full transition-all duration-1000 ${
                     status.gatewayStatus === 'ACTIVE' ? 'bg-gradient-to-r from-blue-500 via-green-500 to-blue-500 bg-[length:200%_100%] animate-[gradient_3s_linear_infinite]' : 'w-0'
                   }`} />
                   
                   {/* Moving Particles */}
                   {status.gatewayStatus === 'ACTIVE' && (
                     <motion.div 
                        animate={{ x: [0, 200] }}
                        transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                        className="absolute top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-white shadow-[0_0_10px_#fff]"
                     />
                   )}
                </div>

                {/* Gateway Node */}
                <div className="flex flex-col items-center gap-3">
                  <div className={`p-4 rounded-2xl transition-all duration-700 shadow-2xl relative ${
                    status.gatewayStatus === 'ACTIVE' ? 'bg-green-600/20 border border-green-500/50 text-green-400 shadow-green-500/20' : 
                    status.gatewayStatus === 'OPEN' ? 'border-yellow-500/50 text-yellow-500' :
                    'bg-gray-800 border border-white/5 text-gray-500 opacity-20 filter grayscale'
                  }`}>
                     <Server className="w-12 h-12" />
                     {status.gatewayStatus === 'HIDDEN' && (
                        <div className="absolute inset-0 flex items-center justify-center">
                           <ShieldAlert className="w-8 h-8 text-red-500/40" />
                        </div>
                     )}
                  </div>
                  <span className="text-[10px] font-bold tracking-widest">PQC_GATEWAY</span>
                </div>
              </div>

              {/* Protocol Visualizer */}
              <div className="mt-8 grid grid-cols-3 gap-4">
                 {[
                   { id: 'SPA', name: 'Identity Verified', done: status.gatewayStatus !== 'HIDDEN' },
                   { id: 'KEM', name: 'Quantum Tunnel', done: status.gatewayStatus === 'ACTIVE' },
                   { id: 'AES', name: 'Data Relay', done: currentSession !== null },
                 ].map((step) => (
                   <div key={step.id} className={`flex flex-col gap-2 p-3 rounded-lg border transition-all duration-500 ${
                     step.done ? 'bg-[#1a2e1d] border-green-900/50 text-green-400' : 'bg-black/40 border-white/5 text-gray-600'
                   }`}>
                     <div className="flex justify-between items-center">
                        <span className="text-[10px] font-bold uppercase">{step.id}</span>
                        {step.done ? <ShieldCheck className="w-4 h-4" /> : <div className="w-4 h-4 rounded-full border border-gray-700" />}
                     </div>
                     <span className="text-xs font-medium">{step.name}</span>
                   </div>
                 ))}
              </div>
            </section>

            {/* Console Bottom */}
            <section className="bg-[#050505] border border-white/10 rounded-xl overflow-hidden flex flex-col min-h-[300px]">
              <div className="bg-[#1a1a1f] px-4 py-2 flex items-center justify-between border-b border-white/5">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-500" />
                  <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">System Monitor :: STDOUT</span>
                </div>
                <div className="flex gap-4 text-[9px] uppercase font-bold text-gray-600">
                   <span>Throughput: 842 Mbps</span>
                   <span>Latency: 4.2ms</span>
                </div>
              </div>
              <div 
                ref={consoleEndRef}
                className="p-4 font-mono text-[11px] leading-relaxed overflow-y-auto max-h-[400px] flex-grow"
              >
                <AnimatePresence mode="popLayout">
                  {status.logs.map((log, i) => (
                    <motion.div 
                      key={i}
                      initial={{ x: -10, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      className={`mb-1 ${
                        log.includes('PQC:') ? 'text-blue-400' : 
                        log.includes('SPA:') ? 'text-yellow-400' : 
                        log.includes('DATA:') ? 'text-green-400' : 'text-gray-500'
                      }`}
                    >
                      <span className="opacity-30">[{i.toString().padStart(3, '0')}]</span> {log}
                    </motion.div>
                  ))}
                </AnimatePresence>
                {status.logs.length === 0 && (
                  <div className="text-gray-700 italic">No activity detected. Standby...</div>
                )}
              </div>
            </section>
          </div>

        </div>

        {/* Footer Info */}
        <footer className="mt-12 pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center text-[10px] text-gray-500 gap-4">
           <div>&copy; 2026 PQC-ZTG SECURITY FRAMEWORK • QUANTUM RESISTANCE: ACTIVE</div>
           <div className="flex gap-8">
              <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-blue-500" /> AUTH: ML-KEM-768</div>
              <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-yellow-500" /> INV: SPA-HMAC-256</div>
              <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500" /> CIPHER: CHACHA20-PQC</div>
           </div>
        </footer>
      </div>
    </div>
  );
}

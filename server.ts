import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import * as Kyber from 'crystals-kyber-ts';
import crypto from 'crypto';

// SPA Configuration
const SPA_SECRET = "pqc_demo_secret";
const SPA_WINDOW = 300000; // 5 minutes to account for clock skew in deployed env

// Simulation state
interface Session {
  id: string;
  clientId: string;
  startTime: number;
  status: 'KNOCKING' | 'HANDSHAKING' | 'SECURE' | 'CLOSED';
  lastLog: string;
  serverSecretKey?: string; // Hex
  sharedSecret?: string; // Hex
}

let gatewayStatus: 'HIDDEN' | 'OPEN' | 'ACTIVE' = 'HIDDEN';
let sessions: Session[] = [];
let logs: string[] = [];

function addLog(msg: string) {
  const log = `[${new IndianDate().toISOString().split('T')[1].split('.')[0]}] ${msg}`;
  logs.push(log);
  if (logs.length > 50) logs.shift();
  console.log(log);
}

// Utility for fake "IndianDate" as I don't want to use standard date for logs
class IndianDate extends Date {}

interface Message {
  from: string;
  to: string;
  content: string;
  type: 'text' | 'file';
  fileName?: string;
  timestamp: number;
}

let messageQueue: Message[] = [];

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  // --- API Routes ---

  app.get('/api/messages/:clientId', (req, res) => {
    const { clientId } = req.params;
    const clientMessages = messageQueue.filter(m => m.to === clientId);
    // Move delivered messages to a "read" state or remove them for simulation
    messageQueue = messageQueue.filter(m => m.to !== clientId);
    res.json(clientMessages);
  });

  app.get('/api/status', (req, res) => {
    res.json({
      gatewayStatus,
      sessionCount: sessions.filter(s => s.status !== 'CLOSED').length,
      logs: logs.slice(-20)
    });
  });

  app.post('/api/reset', (req, res) => {
    gatewayStatus = 'HIDDEN';
    sessions = [];
    logs = [];
    addLog("System Reset. Gateway is now HIDDEN.");
    res.json({ success: true });
  });

  app.post('/api/simulate/knock', (req, res) => {
    const { packet } = req.body;
    
    addLog(`SPA: Received UDP knock payload`);
    
    try {
      const decoded = JSON.parse(Buffer.from(packet, 'base64').toString());
      const { t, id, n, s } = decoded;
      
      // 1. Time window
      const now = Date.now();
      if (Math.abs(now - t) > SPA_WINDOW) {
        addLog(`SPA: REJECTED - Stale timestamp (skew: ${now - t}ms)`);
        return res.status(403).json({ error: 'Stale knock' });
      }
      
      // 2. HMAC Verify
      const payloadStr = `${t}:${id}:${n}`;
      const expectedSig = crypto.createHmac('sha256', SPA_SECRET)
        .update(payloadStr)
        .digest('hex');
        
      if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expectedSig))) {
        addLog(`SPA: REJECTED - Invalid signature for ${id}`);
        return res.status(403).json({ error: 'Auth failed' });
      }

      addLog(`SPA: VERIFIED client [${id}]. Nonce: ${n}`);
      gatewayStatus = 'OPEN';
      addLog(`SPA: Port 5000 temporary opened for ${id}.`);
      
      const newSession: Session = {
        id: uuidv4(),
        clientId: id,
        startTime: Date.now(),
        status: 'KNOCKING',
        lastLog: 'SPA Verified'
      };
      sessions.push(newSession);
      
      res.json({ success: true, sessionId: newSession.id });
    } catch (e) {
      addLog(`SPA: MALFORMED packet received`);
      res.status(400).json({ error: 'Malformed' });
    }
  });

  app.post('/api/simulate/handshake/init', (req, res) => {
    const { sessionId } = req.body;
    const session = sessions.find(s => s.id === sessionId);
    
    if (!session) return res.status(404).json({ error: 'Session not found' });

    addLog(`PQC: Handshake Phase 1 - Generating ML-KEM-768 Keypair`);
    session.status = 'HANDSHAKING';
    
    try {
      const kyber = new Kyber.Kyber768Handshake();
      // Accessing internal service to gen keys
      const [pk, sk] = (kyber as any).kyberService.generateKyberKeys();
      
      const pkHex = Buffer.from(pk).toString('hex');
      const skHex = Buffer.from(sk).toString('hex');
      
      session.serverSecretKey = skHex;
      
      addLog(`PQC: PK Generated! [${pkHex.slice(0, 32)}...] (1184 bytes)`);
      res.json({ success: true, publicKey: pkHex });
    } catch (e) {
      addLog(`ERR: PQC Key Generation failed: ${e}`);
      res.status(500).json({ error: 'Key generation failed' });
    }
  });

  app.post('/api/simulate/handshake/finalize', (req, res) => {
    const { sessionId, ciphertext } = req.body;
    const session = sessions.find(s => s.id === sessionId);
    
    if (!session || !session.serverSecretKey) {
      return res.status(404).json({ error: 'Session or Secret Key not found' });
    }

    addLog(`PQC: Received CT from Client: [${ciphertext.slice(0, 32)}...] (${ciphertext.length / 2} bytes)`);
    
    try {
      const ctArr = Array.from(Buffer.from(ciphertext, 'hex'));
      const skArr = Array.from(Buffer.from(session.serverSecretKey, 'hex'));
      
      const kyber = new Kyber.Kyber768Handshake();
      const ss = (kyber as any).kyberService.decrypt(ctArr, skArr);
      const ssHex = Buffer.from(ss).toString('hex');
      
      session.sharedSecret = ssHex;
      session.status = 'SECURE';
      gatewayStatus = 'ACTIVE';
      
      addLog(`PQC: Derived Shared Secret: [${ssHex.slice(0, 32)}...] (32 bytes)`);
      addLog(`PQC: Quantum-Safe Tunnel established successfully.`);
      
      res.json({ success: true, sharedSecret: ssHex });
    } catch (e) {
      addLog(`ERR: PQC Decapsulation failed: ${e}`);
      res.status(500).json({ error: 'Handshake finalization failed' });
    }
  });

  app.get('/api/peers', (req, res) => {
    const activePeers = sessions
      .filter(s => s.status === 'SECURE')
      .map(s => ({ id: s.id, clientId: s.clientId }));
    res.json(activePeers);
  });

  app.post('/api/simulate/send', (req, res) => {
    const { sessionId, data, type, fileName, targetClientId } = req.body;
    const session = sessions.find(s => s.id === sessionId);
    
    if (!session || session.status !== 'SECURE') {
      return res.status(403).json({ error: 'Channel not secure' });
    }

    if (type === 'file') {
      const targetSession = sessions.find(s => s.id === targetClientId);
      const targetName = targetSession ? targetSession.clientId : 'Relay';
      
      addLog(`DATA: ${session.clientId} sending file [${fileName}] to ${targetName}`);
      
      if (targetSession) {
        messageQueue.push({
          from: session.clientId,
          to: targetSession.clientId,
          content: data,
          type: 'file',
          fileName,
          timestamp: Date.now()
        });
      }

      setTimeout(() => {
        addLog(`DATA: File [${fileName}] delivered to ${targetName}.`);
        res.json({ success: true, response: targetSession ? `File delivered to ${targetSession.clientId}` : `File ${fileName} sent.` });
      }, 1000);
    } else {
      const targetSession = sessions.find(s => s.id === targetClientId);
      const targetName = targetSession ? targetSession.clientId : 'Target';
      addLog(`DATA: [${session.clientId}] -> [${targetName}]: ${data}`);
      
      if (targetSession) {
        messageQueue.push({
          from: session.clientId,
          to: targetSession.clientId,
          content: data,
          type: 'text',
          timestamp: Date.now()
        });
        
        setTimeout(() => {
          addLog(`DATA: Message delivered to ${targetSession.clientId} via Secure Relay.`);
          res.json({ success: true, response: `Delivered to ${targetSession.clientId}` });
        }, 800);
      } else {
        // Default: Just acknowledge the send without a relay reply
        setTimeout(() => {
          addLog(`DATA: [Relay] acknowledged secure traffic.`);
          res.json({ success: true });
        }, 500);
      }
    }
  });

  // --- Vite Integration ---

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    addLog(`PQC-ZTG Controller running on http://localhost:${PORT}`);
  });
}

startServer();

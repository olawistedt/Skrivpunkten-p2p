/**
 * Mycel — WebSocket Signaleringsserver
 * =====================================
 * Förmedlar WebRTC offer/answer/ICE-kandidater mellan peers.
 * Servern lagrar INGEN data — den vidarebefordrar bara meddelanden.
 *
 * Start:  node server.js
 * Port:   process.env.PORT || 8080
 *
 * Exponera publikt (för att nå från internet):
 *   npx localtunnel --port 8080
 *   eller: ngrok http 8080
 */

'use strict';

const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;

// ── HTTP-server (grundläggande hälsokontroll) ──────────────
const server = http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain',
    'Access-Control-Allow-Origin': '*'
  });
  res.end('Mycel Signaling Server — OK\n');
});

// ── WebSocket-server ───────────────────────────────────────
const wss = new WebSocketServer({ server });

/** Aktiva klienter: pubkey (hex-sträng) → WebSocket */
const clients = new Map();

wss.on('connection', (ws, req) => {
  let myPubkey = null;
  const remoteIp = req.socket.remoteAddress;

  ws.on('message', (raw) => {
    // Begränsa meddelandestorlek
    if (raw.length > 65536) return;

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (typeof msg !== 'object' || msg === null) return;

    switch (msg.type) {

      case 'register': {
        // Validera pubkey: hex-sträng, max 300 tecken
        if (typeof msg.pubkey !== 'string' ||
          !/^[0-9a-f]{10,300}$/i.test(msg.pubkey)) return;

        // Om pubkey redan registrerad (re-connect), ersätt
        if (myPubkey && clients.get(myPubkey) === ws) {
          clients.delete(myPubkey);
        }
        myPubkey = msg.pubkey;
        clients.set(myPubkey, ws);

        ws.send(JSON.stringify({ type: 'registered', pubkey: myPubkey }));
        console.log(`[+] ${myPubkey.slice(0, 16)}… registrerad  (online: ${clients.size})`);
        break;
      }

      case 'signal': {
        // Måste vara registrerad för att skicka
        if (!myPubkey) return;
        if (typeof msg.to !== 'string') return;

        const target = clients.get(msg.to);
        if (target && target.readyState === 1 /* OPEN */) {
          // Servern injicerar `from` — klienten kan inte förfalska det
          const { type, to, from: _ignored, ...rest } = msg;
          target.send(JSON.stringify({ ...rest, from: myPubkey }));
        }
        break;
      }

    }
  });

  ws.on('close', () => {
    if (myPubkey && clients.get(myPubkey) === ws) {
      clients.delete(myPubkey);
      console.log(`[-] ${myPubkey.slice(0, 16)}… frånkopplad (online: ${clients.size})`);
    }
  });

  ws.on('error', () => {
    if (myPubkey && clients.get(myPubkey) === ws) {
      clients.delete(myPubkey);
    }
  });
});

// ── Starta ────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log('');
  console.log('  🍄 Mycel signaleringsserver startad');
  console.log(`  ➜  ws://localhost:${PORT}`);
  console.log('');
  console.log('  För åtkomst utifrån:');
  console.log(`    npx localtunnel --port ${PORT}`);
  console.log('    (klistra in wss://...-adressen i Mycel-appen)');
  console.log('');
});

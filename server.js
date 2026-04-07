/**
 * MYCEL — Signalserver
 * =====================
 * Minimal WebSocket-server för WebRTC-parning.
 * Vidarebefordrar SDP offer/answer utan att ta del av innehållet.
 * All faktisk data skickas sedan direkt peer-to-peer via WebRTC.
 *
 * Start:  node server.js
 * Kräver: npm install ws
 *
 * Protokoll (JSON-meddelanden):
 *  Klient → Server: { type:"join",   pubkey, name, room }
 *  Server → Klient: { type:"welcome", peers:[{pubkey,name}] }
 *  Server → Klient: { type:"peer_joined", pubkey, name }
 *  Server → Klient: { type:"peer_left",   pubkey }
 *  Klient → Server: { type:"signal", to, payload }       ← skicka offer/answer
 *  Server → Klient: { type:"relay",  from, payload }     ← mottag offer/answer
 */

'use strict';

const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;

// rooms: Map<roomId, Map<pubkey, { ws, pubkey, name }>>
const rooms = new Map();

const wss = new WebSocketServer({ port: PORT });

console.log(`🔌 Mycel signalserver lyssnar på ws://0.0.0.0:${PORT}`);

wss.on('connection', (ws) => {
  let clientPubkey = null;
  let clientRoom = null;

  const send = (data) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(data));
  };

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      // ── Peer går med i ett rum ──────────────────────────
      case 'join': {
        const { pubkey, name, room } = msg;
        if (!pubkey || !name || !room) return;
        if (clientPubkey) return; // redan registrerad

        clientPubkey = pubkey;
        clientRoom = room;

        if (!rooms.has(room)) rooms.set(room, new Map());
        const roomPeers = rooms.get(room);

        // Svara med lista av existerande peers i rummet
        const peerList = [...roomPeers.values()].map(p => ({ pubkey: p.pubkey, name: p.name }));
        send({ type: 'welcome', peers: peerList });

        // Meddela befintliga peers om den nya
        const joinMsg = JSON.stringify({ type: 'peer_joined', pubkey, name });
        for (const [, peer] of roomPeers) {
          if (peer.ws.readyState === 1 /* OPEN */) peer.ws.send(joinMsg);
        }

        roomPeers.set(pubkey, { ws, pubkey, name });
        console.log(`+ ${name} (${pubkey.slice(0, 8)}…) gick med i rum "${room}" — ${roomPeers.size} i rummet`);
        break;
      }

      // ── Vidarebefordra signal (offer/answer) ─────────────
      case 'signal': {
        const { to, payload } = msg;
        if (!to || !payload || !clientRoom) return;

        const roomPeers = rooms.get(clientRoom);
        const target = roomPeers?.get(to);
        if (!target) return;

        if (target.ws.readyState === 1 /* OPEN */) {
          target.ws.send(JSON.stringify({
            type: 'relay',
            from: clientPubkey,
            payload
          }));
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    if (!clientPubkey || !clientRoom) return;
    const roomPeers = rooms.get(clientRoom);
    if (!roomPeers) return;

    roomPeers.delete(clientPubkey);
    console.log(`- ${clientPubkey.slice(0, 8)}… lämnade rum "${clientRoom}" — ${roomPeers.size} kvar`);

    // Meddela kvarvarande peers
    const leaveMsg = JSON.stringify({ type: 'peer_left', pubkey: clientPubkey });
    for (const [, peer] of roomPeers) {
      if (peer.ws.readyState === 1) peer.ws.send(leaveMsg);
    }

    if (roomPeers.size === 0) rooms.delete(clientRoom);
  });

  ws.on('error', (err) => console.error('WS-fel:', err.message));
});

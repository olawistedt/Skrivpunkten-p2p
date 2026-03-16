/**
 * MYCEL — Decentraliserat Socialt Nätverk
 * =========================================
 * Arkitektur (enligt specifikationen):
 *  1. Asymmetrisk kryptografi (ECDSA P-256) för identitet & signering
 *  2. IndexedDB för offline-first lokal lagring
 *  3. WebRTC (RTCPeerConnection + RTCDataChannel) för P2P
 *  4. Gossip-protokoll för dataspridning
 *  5. Social Recovery via Shamir-liknande nyckeldelning (simulerad)
 *  6. PWA Service Worker
 */

'use strict';

// ┌─────────────────────────────────────────────────────────┐
// │  KONFIGURATION                                            │
// └─────────────────────────────────────────────────────────┘
const STUN_SERVERS = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
};

// ══════════════════════════════════════════════════════════
// 1. KRYPTOGRAFI — WebCrypto API (ECDSA P-256)
// ══════════════════════════════════════════════════════════
const Crypto = {
  /** Generera nytt nyckelpar */
  async generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,  // exporterbart
      ['sign', 'verify']
    );
    return kp;
  },

  /** Exportera publik nyckel som hex-sträng */
  async exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey('spki', key);
    return Array.from(new Uint8Array(raw))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /** Exportera privat nyckel som JWK (för lagring) */
  async exportPrivateKey(key) {
    return crypto.subtle.exportKey('jwk', key);
  },

  /** Importera privat nyckel från JWK */
  async importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['sign']
    );
  },

  /** Importera publik nyckel från hex */
  async importPublicKey(hex) {
    const bytes = new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
    return crypto.subtle.importKey(
      'spki', bytes.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify']
    );
  },

  /** Signera ett meddelande (returnerar hex) */
  async sign(privateKey, message) {
    const data = new TextEncoder().encode(message);
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey, data
    );
    return Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /** Verifiera signatur */
  async verify(publicKey, message, signatureHex) {
    try {
      const pubKey = await Crypto.importPublicKey(publicKey);
      const data = new TextEncoder().encode(message);
      const sigBytes = new Uint8Array(signatureHex.match(/.{2}/g).map(b => parseInt(b, 16)));
      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pubKey, sigBytes.buffer, data
      );
    } catch { return false; }
  },

  /** Hash (SHA-256) → hex */
  async hash(str) {
    const data = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /** Generera slumpmässigt UUID */
  uuid() {
    return crypto.randomUUID ? crypto.randomUUID()
      : ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
        (c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16));
  }
};

// ══════════════════════════════════════════════════════════
// 2. LOKAL DATABAS — IndexedDB (Offline-First)
// ══════════════════════════════════════════════════════════
const DB = {
  db: null,
  DB_NAME: 'mycel-v1',
  VERSION: 1,

  async open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB.DB_NAME, DB.VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('posts')) {
          const ps = db.createObjectStore('posts', { keyPath: 'id' });
          ps.createIndex('by_timestamp', 'timestamp');
          ps.createIndex('by_author', 'authorPubkey');
        }
        if (!db.objectStoreNames.contains('peers')) {
          db.createObjectStore('peers', { keyPath: 'pubkey' });
        }
        if (!db.objectStoreNames.contains('seen')) {
          db.createObjectStore('seen', { keyPath: 'id' }); // gossip dedup
        }
      };
      req.onsuccess = e => { DB.db = e.target.result; resolve(DB.db); };
      req.onerror = e => reject(e.target.error);
    });
  },

  async put(store, obj) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readwrite');
      tx.objectStore(store).put(obj).onsuccess = e => resolve(e.target.result);
      tx.onerror = e => reject(e.target.error);
    });
  },

  async get(store, key) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readonly');
      tx.objectStore(store).get(key).onsuccess = e => resolve(e.target.result);
      tx.onerror = () => resolve(null);
    });
  },

  async getAll(store, index = null, query = null) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readonly');
      const s = tx.objectStore(store);
      const req = index ? s.index(index).getAll(query) : s.getAll();
      req.onsuccess = e => resolve(e.target.result || []);
      req.onerror = () => resolve([]);
    });
  },

  async delete(store, key) {
    return new Promise((resolve) => {
      const tx = DB.db.transaction(store, 'readwrite');
      tx.objectStore(store).delete(key).onsuccess = () => resolve();
    });
  },

  async clear(store) {
    return new Promise((resolve) => {
      const tx = DB.db.transaction(store, 'readwrite');
      tx.objectStore(store).clear().onsuccess = () => resolve();
    });
  }
};

// ══════════════════════════════════════════════════════════
// 3. IDENTITETSHANTERING
// ══════════════════════════════════════════════════════════
const Identity = {
  current: null,
  privateKey: null,

  async create(name, bio = '') {
    UI.setKeyGenStatus('Genererar kryptografiska nycklar...');
    const kp = await Crypto.generateKeyPair();
    const pubkey = await Crypto.exportPublicKey(kp.publicKey);
    const privkeyJwk = await Crypto.exportPrivateKey(kp.privateKey);
    const id = {
      id: 'self',
      name,
      bio,
      pubkey,
      privkeyJwk,
      createdAt: Date.now()
    };
    await DB.put('identity', id);
    Identity.current = id;
    Identity.privateKey = kp.privateKey;
    UI.setKeyGenStatus('✓ Nycklar genererade och sparade lokalt');
    return id;
  },

  async load() {
    const id = await DB.get('identity', 'self');
    if (!id) return null;
    Identity.current = id;
    Identity.privateKey = await Crypto.importPrivateKey(id.privkeyJwk);
    return id;
  },

  async sign(message) {
    if (!Identity.privateKey) throw new Error('Ingen privat nyckel laddad');
    return Crypto.sign(Identity.privateKey, message);
  },

  shortKey(pubkey) {
    if (!pubkey) return '???';
    return pubkey.slice(0, 8) + '…' + pubkey.slice(-6);
  },

  avatarEmoji(pubkey) {
    const emojis = ['🌱', '🌿', '🍀', '🌲', '🍄', '🌾', '🌸', '🌺', '🌻', '🌼', '🍁', '🦋', '🐝', '🐞', '🦎', '🐸', '🦊', '🐺', '🦁', '🐬'];
    const idx = parseInt((pubkey || '0').slice(-4), 16) % emojis.length;
    return emojis[idx];
  },

  /** Social Recovery — dela privat nyckel i N fragment */
  async createRecoveryShards(n = 3) {
    const jwkStr = JSON.stringify(Identity.current.privkeyJwk);
    // Simulerad Shamir-delning: XOR-baserad för demo
    const encoder = new TextEncoder();
    const data = encoder.encode(jwkStr);
    const shards = [];
    let xorAccum = new Uint8Array(data.length);

    for (let i = 0; i < n - 1; i++) {
      const rand = crypto.getRandomValues(new Uint8Array(data.length));
      shards.push(Array.from(rand).map(b => b.toString(16).padStart(2, '0')).join(''));
      for (let j = 0; j < data.length; j++) xorAccum[j] ^= rand[j];
    }
    // Sista shard = data XOR alla övriga
    const lastShard = new Uint8Array(data.length);
    for (let j = 0; j < data.length; j++) lastShard[j] = data[j] ^ xorAccum[j];
    shards.push(Array.from(lastShard).map(b => b.toString(16).padStart(2, '0')).join(''));

    return shards;
  }
};

// ══════════════════════════════════════════════════════════
// 4. INLÄGG (Posts)
// ══════════════════════════════════════════════════════════
const Posts = {
  async create(text) {
    if (!Identity.current) throw new Error('Inte inloggad');
    const id = Crypto.uuid();
    const timestamp = Date.now();
    const payload = JSON.stringify({ id, text, authorPubkey: Identity.current.pubkey, timestamp });
    const signature = await Identity.sign(payload);

    const post = {
      id, text,
      authorPubkey: Identity.current.pubkey,
      authorName: Identity.current.name,
      timestamp,
      signature,
      hops: 0,
      local: true
    };

    await DB.put('posts', post);
    await DB.put('seen', { id }); // markera som sedd (gossip-dedup)
    return post;
  },

  async getAll() {
    const posts = await DB.getAll('posts');
    return posts.sort((a, b) => b.timestamp - a.timestamp);
  },

  async delete(id) {
    await DB.delete('posts', id);
    // I ett riktigt system: skicka delete-signal via gossip
    Gossip.broadcast({ type: 'delete', id });
  },

  async receiveFromGossip(post) {
    // Deduplika
    const seen = await DB.get('seen', post.id);
    if (seen) return false;

    // Verifiera signatur
    const payload = JSON.stringify({
      id: post.id, text: post.text,
      authorPubkey: post.authorPubkey,
      timestamp: post.timestamp
    });
    const valid = await Crypto.verify(post.authorPubkey, payload, post.signature);
    if (!valid) {
      console.warn('Ogiltig signatur på inlägg:', post.id);
      UI.toast('⚠️ Mottog inlägg med ogiltig signatur', 'error');
      return false;
    }

    post.hops = (post.hops || 0) + 1;
    post.local = false;
    await DB.put('posts', post);
    await DB.put('seen', { id: post.id });
    return true;
  }
};

// ══════════════════════════════════════════════════════════
// 5. PEER-HANTERING
// ══════════════════════════════════════════════════════════
const Peers = {
  connections: new Map(), // pubkey → { channel, lastSeen, name }

  async getAll() {
    return DB.getAll('peers');
  },

  async add(peer) {
    await DB.put('peers', {
      pubkey: peer.pubkey,
      name: peer.name || 'Okänd',
      addedAt: Date.now(),
      lastSeen: peer.lastSeen || Date.now()
    });
  },

  /** Skapa identitetskod (pubkey+namn) att visa som QR/text för lokal återkänning */
  identityInfo() {
    if (!Identity.current) return '';
    return btoa(JSON.stringify({
      pk: Identity.current.pubkey,
      n: Identity.current.name
    }));
  },

  onlineCount() {
    let count = 0;
    for (const [, conn] of Peers.connections) {
      if (conn.channel?.readyState === 'open') count++;
    }
    return count;
  }
};

// ══════════════════════════════════════════════════════════
// 6. MANUELL SIGNALERING — serverlös WebRTC
// ══════════════════════════════════════════════════════════
// Flöde:
//   Steg 1 (A): createOffer()  → kopierar kod → skickar till B via SMS/etc.
//   Steg 2 (B): acceptOffer() → kopierar kod → skickar tillbaka till A
//   Steg 3 (A): acceptAnswer() → anslutning öppnas
// Ingen server krävs. Signaleringen sker via valfri kanal.
const ManualSignaling = {
  _pending: new Map(), // tempId → { pc, peerRef }
  _rcCodes: new Map(), // peerPubkey → { name, code } — automatiskt genererade återanslutningskoder

  /** Bygger localStorage-nyckel för auto-återanslutning */
  _lsKey(type, fromSlice, toSlice) {
    return `mycel-rc-${type}-${fromSlice}-${toSlice}`;
  },

  /**
   * Körs vid sidladdning för varje känd peer.
   * Försöker återansluta automatiskt via localStorage (samma enhet)
   * och genererar nya offer-koder att skicka manuellt (olika enheter).
   */
  async autoReconnect(savedPeers) {
    if (!savedPeers.length || !Identity.current) return;
    const myPk = Identity.current.pubkey;
    const mySlice = myPk.slice(0, 16);

    // Rensa utgångna localStorage-poster (> 2 h)
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (!k?.startsWith('mycel-rc-')) continue;
      try {
        const val = JSON.parse(localStorage.getItem(k));
        if (val.ts && Date.now() - val.ts > 7200000) localStorage.removeItem(k);
      } catch { localStorage.removeItem(k); }
    }

    // Lyssna på storage-events — automatiskt utbyte om båda flikar/fönster är öppna
    window.addEventListener('storage', async (e) => {
      if (!e.key?.startsWith('mycel-rc-') || !e.newValue) return;
      const curPk = Identity.current?.pubkey;
      if (!curPk) return;
      const curSlice = curPk.slice(0, 16);

      for (const peer of (await Peers.getAll())) {
        const peerSlice = peer.pubkey.slice(0, 16);
        // Inkommande offer (från peer till mig) — jag är responder
        if (e.key === ManualSignaling._lsKey('o', peerSlice, curSlice)) {
          try {
            const { code } = JSON.parse(e.newValue);
            const answerCode = await ManualSignaling.acceptOffer(code);
            localStorage.setItem(
              ManualSignaling._lsKey('a', curSlice, peerSlice),
              JSON.stringify({ code: answerCode, ts: Date.now() })
            );
            localStorage.removeItem(e.key);
          } catch { }
          return;
        }
        // Inkommande answer (från peer till mig) — jag är initiator
        if (e.key === ManualSignaling._lsKey('a', peerSlice, curSlice)) {
          try {
            const { code } = JSON.parse(e.newValue);
            await ManualSignaling.acceptAnswer(code);
            localStorage.removeItem(e.key);
            ManualSignaling._rcCodes.delete(peer.pubkey);
            UI.renderPeers();
          } catch { }
          return;
        }
      }
    });

    // Hantera varje känd peer
    for (const peer of savedPeers) {
      const peerSlice = peer.pubkey.slice(0, 16);
      const conn = Peers.connections.get(peer.pubkey);
      if (conn?.channel?.readyState === 'open') continue; // redan ansluten

      // Bokstavsordning avgör vem som initerar (stabilt, undviker dubbla offer)
      const iAmInitiator = myPk < peer.pubkey;

      if (iAmInitiator) {
        // Kolla om peer redan svarat på ett offer från den här sessionen
        const savedAnswer = localStorage.getItem(ManualSignaling._lsKey('a', peerSlice, mySlice));
        if (savedAnswer) {
          try {
            const { code } = JSON.parse(savedAnswer);
            await ManualSignaling.acceptAnswer(code);
            localStorage.removeItem(ManualSignaling._lsKey('a', peerSlice, mySlice));
            continue;
          } catch {
            localStorage.removeItem(ManualSignaling._lsKey('a', peerSlice, mySlice));
          }
        }
        // Generera ett nytt offer (skriver över eventuellt gammalt)
        try {
          const { code } = await ManualSignaling.createOffer();
          localStorage.setItem(
            ManualSignaling._lsKey('o', mySlice, peerSlice),
            JSON.stringify({ code, ts: Date.now() })
          );
          ManualSignaling._rcCodes.set(peer.pubkey, { name: peer.name, code });
        } catch { }
      } else {
        // Jag är responder — kolla om initiatorns offer finns redan
        const savedOffer = localStorage.getItem(ManualSignaling._lsKey('o', peerSlice, mySlice));
        if (savedOffer) {
          try {
            const { code } = JSON.parse(savedOffer);
            const answerCode = await ManualSignaling.acceptOffer(code);
            localStorage.setItem(
              ManualSignaling._lsKey('a', mySlice, peerSlice),
              JSON.stringify({ code: answerCode, ts: Date.now() })
            );
            localStorage.removeItem(ManualSignaling._lsKey('o', peerSlice, mySlice));
            continue;
          } catch { }
        }
        // Inget offer hittades ännu — storage-listener tar hand om det när det dyker upp
      }
    }

    UI.renderPeers(); // Uppdatera UI med eventuella återanslutningskoder
  },

  /** Skapar en WebRTC RTCPeerConnection och kopplar datalyssnare */
  _makePC(isInitiator, connKey, peerRef) {
    const pc = new RTCPeerConnection(STUN_SERVERS);

    const setupChannel = (ch) => {
      const onOpen = () => {
        const pubkey = peerRef.pubkey;
        const entry = Peers.connections.get(connKey) || {};
        entry.channel = ch;
        entry.name = peerRef.name;
        entry.lastSeen = Date.now();
        Peers.connections.set(pubkey, entry);
        if (connKey !== pubkey) Peers.connections.delete(connKey);
        UI.updateConnectionStatus(true);
        UI.renderPeers();
        UI.updateStats();
        UI.toast(`✓ Direkt P2P-koppling öppen med ${peerRef.name || pubkey.slice(0, 8)}`, 'success');
        setTimeout(() => Gossip.syncWithPeer(pubkey), 300);
      };

      if (ch.readyState === 'open') {
        onOpen();
      } else {
        ch.onopen = onOpen;
      }

      ch.onclose = () => {
        const entry = Peers.connections.get(peerRef.pubkey);
        if (entry) entry.channel = null;
        UI.renderPeers();
        UI.updateConnectionStatus(Peers.onlineCount() > 0);
      };
      ch.onmessage = async (e) => {
        let msg; try { msg = JSON.parse(e.data); } catch { return; }
        await Gossip.handleMessage(msg, peerRef.pubkey);
      };
    };

    if (isInitiator) {
      setupChannel(pc.createDataChannel('mycel', { ordered: false }));
    } else {
      pc.ondatachannel = (e) => setupChannel(e.channel);
    }

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        const entry = Peers.connections.get(peerRef.pubkey);
        if (entry) { entry.channel = null; UI.renderPeers(); }
      }
    };

    return pc;
  },

  /** Väntar tills ICE-insamling är klar (alla noder funna), max 6 s */
  _waitForIce(pc) {
    return new Promise(resolve => {
      if (pc.iceGatheringState === 'complete') { resolve(); return; }
      const handler = () => {
        if (pc.iceGatheringState === 'complete') {
          pc.removeEventListener('icegatheringstatechange', handler);
          resolve();
        }
      };
      pc.addEventListener('icegatheringstatechange', handler);
      setTimeout(resolve, 6000);
    });
  },

  /**
   * Steg 1 — du skapar en inbjudningskod att skicka till din vän.
   * Returnerar { code, tempId }
   */
  async createOffer() {
    const tempId = 'p_' + Date.now();
    const peerRef = { pubkey: null, name: null };
    Peers.connections.set(tempId, { name: '…', _pendingOffer: true });

    const pc = ManualSignaling._makePC(true, tempId, peerRef);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await ManualSignaling._waitForIce(pc);

    ManualSignaling._pending.set(tempId, { pc, peerRef });

    return {
      code: btoa(JSON.stringify({
        v: 1, t: 'o',
        sdp: pc.localDescription.sdp,
        pk: Identity.current.pubkey,
        n: Identity.current.name,
        id: tempId
      })),
      tempId
    };
  },

  /**
   * Steg 2 — din vän klistrar in din kod, får en svarskod att skicka tillbaka.
   * Returnerar svarskoden.
   */
  async acceptOffer(encoded) {
    let data;
    try { data = JSON.parse(atob(encoded.replace(/\s+/g, ''))); } catch { throw new Error('Ogiltig inbjudningskod'); }
    if (data.t !== 'o') throw new Error('Det här är ett svar, inte en inbjudan');
    if (data.pk === Identity.current?.pubkey) throw new Error('Det är din egen nyckel!');

    const peerPubkey = data.pk;
    const name = data.n;
    const peerRef = { pubkey: peerPubkey, name };
    Peers.connections.set(peerPubkey, { name, _pendingOffer: true });

    const pc = ManualSignaling._makePC(false, peerPubkey, peerRef);
    await pc.setRemoteDescription({ type: 'offer', sdp: data.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await ManualSignaling._waitForIce(pc);

    await Peers.add({ pubkey: peerPubkey, name });
    Network.addNode(peerPubkey, name);
    UI.renderPeers();

    return btoa(JSON.stringify({
      v: 1, t: 'a',
      sdp: pc.localDescription.sdp,
      pk: Identity.current.pubkey,
      n: Identity.current.name,
      id: data.id
    }));
  },

  /**
   * Steg 3 — du klistrar in svarskoden från din vän, anslutningen öppnas.
   */
  async acceptAnswer(encoded) {
    let data;
    try { data = JSON.parse(atob(encoded.replace(/\s+/g, ''))); } catch { throw new Error('Ogiltig svarskod'); }
    if (data.t !== 'a') throw new Error('Det här är en inbjudan, inte ett svar');

    const pending = ManualSignaling._pending.get(data.id);
    if (!pending) throw new Error('Ingen matchande inbjudan. Skapa en ny.');
    ManualSignaling._pending.delete(data.id);

    pending.peerRef.pubkey = data.pk;
    pending.peerRef.name = data.n;

    // Flytta connection-entry till rätt nyckel (tempId → pubkey)
    const byId = Peers.connections.get(data.id);
    if (byId) { Peers.connections.delete(data.id); Peers.connections.set(data.pk, byId); }
    // Hantera fallet att onopen hann köra innan acceptAnswer (sparades under null-nyckeln)
    const byNull = Peers.connections.get(null);
    if (byNull) {
      Peers.connections.delete(null);
      Peers.connections.set(data.pk, byNull);
      byNull.name = data.n;
      if (byNull.channel?.readyState === 'open') {
        setTimeout(() => Gossip.syncWithPeer(data.pk), 100);
      }
    }

    await pending.pc.setRemoteDescription({ type: 'answer', sdp: data.sdp });
    await Peers.add({ pubkey: data.pk, name: data.n });
    Network.addNode(data.pk, data.n);
    UI.renderPeers();
  },

  /** Autodetektera om inklistrad kod är inbjudan eller svar, kör rätt funktion */
  async handlePastedCode(encoded) {
    const clean = encoded.replace(/\s+/g, '');
    // Utfärda hjälpsamt felmeddelande om användaren klistrat in sin pubkey istället
    if (/^[0-9a-f]{40,}$/i.test(clean)) {
      throw new Error('Det här är en publik nyckel, inte en anslutningskod. Anslutningskoden får du genom att din vän klickar \u201cSkapa inbjudningskod\u201d.');
    }
    let data;
    try { data = JSON.parse(atob(clean)); } catch { throw new Error('Ogiltig kod — se till att kopiera hela koden utan radbrytningar.'); }
    if (data.t === 'o') {
      const answerCode = await ManualSignaling.acceptOffer(encoded);
      return { action: 'answered', code: answerCode };
    }
    if (data.t === 'a') {
      await ManualSignaling.acceptAnswer(encoded);
      return { action: 'connected' };
    }
    throw new Error('Okänd kodtyp');
  }
};

// ══════════════════════════════════════════════════════════
// 7. GOSSIP-PROTOKOLL
// ══════════════════════════════════════════════════════════
const Gossip = {
  active: true,

  init() {
    // Inget att initiera — anslutningar görs manuellt via ManualSignaling
  },

  async handleMessage(msg, fromPubkey) {
    if (!msg || !msg.type) return;
    switch (msg.type) {
      case 'post':
        if (Gossip.active && msg.post) {
          const isNew = await Posts.receiveFromGossip(msg.post);
          if (isNew) {
            UI.renderFeed();
            UI.toast(`📨 Nytt inlägg från ${msg.post.authorName || 'okänd'}`, 'info');
            // Vidarebefordra till andra peers (gossip hop)
            Gossip.forwardToOthers(msg, fromPubkey);
          }
        }
        break;

      case 'sync_request': {
        const posts = await Posts.getAll();
        const conn = Peers.connections.get(fromPubkey);
        if (conn?.channel?.readyState === 'open') {
          conn.channel.send(JSON.stringify({
            type: 'sync_response',
            from: Identity.current.pubkey,
            posts
          }));
        }
        break;
      }

      case 'sync_response':
        if (msg.posts && Array.isArray(msg.posts)) {
          let newCount = 0;
          for (const post of msg.posts) {
            const isNew = await Posts.receiveFromGossip(post);
            if (isNew) newCount++;
          }
          if (newCount > 0) {
            UI.renderFeed();
            UI.toast(`🔄 Synkroniserade ${newCount} nya inlägg`, 'info');
          }
        }
        break;

      case 'delete':
        if (msg.id) {
          await DB.delete('posts', msg.id);
          UI.renderFeed();
        }
        break;
    }
  },

  broadcast(message) {
    if (!Gossip.active) return;
    for (const [pubkey, conn] of Peers.connections) {
      if (conn.channel?.readyState === 'open') {
        try {
          conn.channel.send(JSON.stringify({
            ...message,
            from: Identity.current?.pubkey
          }));
        } catch (err) {
          console.warn('Kunde inte skicka till peer:', pubkey, err);
        }
      }
    }
  },

  async syncWithPeer(pubkey) {
    const conn = Peers.connections.get(pubkey);
    if (!conn?.channel || conn.channel.readyState !== 'open') return;
    conn.channel.send(JSON.stringify({
      type: 'sync_request',
      from: Identity.current.pubkey
    }));
  },

  forwardToOthers(msg, exceptPubkey) {
    if (msg.post && msg.post.hops >= 6) return; // max 6 hopp
    for (const [pubkey, conn] of Peers.connections) {
      if (pubkey === exceptPubkey) continue;
      if (conn.channel?.readyState === 'open') {
        try {
          conn.channel.send(JSON.stringify({
            ...msg,
            from: Identity.current?.pubkey
          }));
        } catch { }
      }
    }
  }
};

// ══════════════════════════════════════════════════════════
// 7. NÄTVERKSVISUALISERING (Canvas)
// ══════════════════════════════════════════════════════════
const Network = {
  nodes: new Map(), // pubkey → { x, y, name, emoji }
  edges: [],
  animFrame: null,

  init() {
    const canvas = document.getElementById('network-canvas');
    if (!canvas) return;
    Network.canvas = canvas;
    Network.ctx = canvas.getContext('2d');

    // Lägg till self-nod
    if (Identity.current) {
      Network.addNode(Identity.current.pubkey, Identity.current.name, true);
    }
    Network.startRender();
  },

  addNode(pubkey, name, isSelf = false) {
    if (Network.nodes.has(pubkey)) return;
    const canvas = document.getElementById('network-canvas');
    const W = canvas?.clientWidth || 400;
    const H = canvas?.clientHeight || 200;
    const angle = Math.random() * Math.PI * 2;
    const r = 40 + Math.random() * 60;
    Network.nodes.set(pubkey, {
      x: W / 2 + Math.cos(angle) * (isSelf ? 0 : r),
      y: H / 2 + Math.sin(angle) * (isSelf ? 0 : r),
      name, isSelf,
      emoji: Identity.avatarEmoji(pubkey),
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5
    });

    if (!isSelf && Identity.current) {
      Network.edges.push({ a: Identity.current.pubkey, b: pubkey });
    }
  },

  startRender() {
    if (Network.animFrame) cancelAnimationFrame(Network.animFrame);
    const tick = () => {
      Network.draw();
      Network.animFrame = requestAnimationFrame(tick);
    };
    tick();
  },

  draw() {
    const canvas = Network.canvas;
    if (!canvas || !Network.ctx) return;
    const ctx = Network.ctx;
    const W = canvas.clientWidth || canvas.width;
    const H = canvas.clientHeight || canvas.height;
    canvas.width = W; canvas.height = H;

    ctx.clearRect(0, 0, W, H);

    // Physics: gentle drift
    for (const [, node] of Network.nodes) {
      node.x += node.vx;
      node.y += node.vy;
      if (node.x < 20 || node.x > W - 20) node.vx *= -1;
      if (node.y < 20 || node.y > H - 20) node.vy *= -1;
    }

    // Repulsion
    const arr = [...Network.nodes.values()];
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        const dx = arr[j].x - arr[i].x;
        const dy = arr[j].y - arr[i].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 80) {
          const f = (80 - dist) / 80 * 0.3;
          arr[i].vx -= dx / dist * f;
          arr[i].vy -= dy / dist * f;
          arr[j].vx += dx / dist * f;
          arr[j].vy += dy / dist * f;
        }
      }
    }

    // Draw edges
    for (const edge of Network.edges) {
      const a = Network.nodes.get(edge.a);
      const b = Network.nodes.get(edge.b);
      if (!a || !b) continue;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = 'rgba(58,122,66,0.4)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Animated data packet
      const t = (Date.now() / 1200) % 1;
      const px = a.x + (b.x - a.x) * t;
      const py = a.y + (b.y - a.y) * t;
      ctx.beginPath();
      ctx.arc(px, py, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(124,252,138,0.8)';
      ctx.fill();
    }

    // Draw nodes
    for (const [pubkey, node] of Network.nodes) {
      const isSelected = pubkey === Identity.current?.pubkey;
      ctx.beginPath();
      ctx.arc(node.x, node.y, isSelected ? 14 : 10, 0, Math.PI * 2);
      ctx.fillStyle = isSelected ? 'rgba(124,252,138,0.2)' : 'rgba(26,26,40,0.9)';
      ctx.strokeStyle = isSelected ? '#7cfc8a' : '#3a3a60';
      ctx.lineWidth = isSelected ? 2 : 1;
      ctx.fill();
      ctx.stroke();

      // Emoji
      ctx.font = `${isSelected ? 14 : 12}px serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(node.emoji, node.x, node.y);

      // Name
      ctx.font = '9px Space Mono, monospace';
      ctx.fillStyle = 'rgba(112,112,160,0.8)';
      ctx.fillText(node.name?.slice(0, 12) || '?', node.x, node.y + 18);
    }
  }
};

// ══════════════════════════════════════════════════════════
// 8. QR-KOD GENERATOR (ren Canvas-implementation)
// ══════════════════════════════════════════════════════════
const QR = {
  /** Minimalistisk QR-kod via URL-omdirigering
   *  Skapar en stiliserad representation */
  drawInviteCode(canvas, text) {
    const ctx = canvas.getContext('2d');
    const size = canvas.width;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);

    // Använd en visuell kod istället för riktig QR
    // (riktig QR kräver ett externt bibliotek)
    ctx.fillStyle = '#000000';

    // Rita ett enkelt unikt mönster baserat på texten
    const hash = [...text].reduce((h, c) => ((h << 5) - h + c.charCodeAt(0)) | 0, 0);
    const seed = Math.abs(hash);

    const cells = 21;
    const cellSize = size / (cells + 4);
    const offset = cellSize * 2;

    // Finder patterns (hörn)
    const drawFinder = (x, y) => {
      ctx.fillRect(x, y, cellSize * 7, cellSize * 7);
      ctx.fillStyle = '#fff';
      ctx.fillRect(x + cellSize, y + cellSize, cellSize * 5, cellSize * 5);
      ctx.fillStyle = '#000';
      ctx.fillRect(x + cellSize * 2, y + cellSize * 2, cellSize * 3, cellSize * 3);
    };
    drawFinder(offset, offset);
    drawFinder(size - offset - cellSize * 7, offset);
    drawFinder(offset, size - offset - cellSize * 7);

    // Data-celler (pseudo-slumpmässiga baserat på texten)
    let rng = seed;
    for (let row = 0; row < cells; row++) {
      for (let col = 0; col < cells; col++) {
        // Hoppa över finder-pattern-zoner
        if ((row < 9 && col < 9) || (row < 9 && col > cells - 9) || (row > cells - 9 && col < 9)) continue;
        rng = (rng * 1664525 + 1013904223) & 0xffffffff;
        if (rng % 3 === 0) {
          ctx.fillStyle = '#000';
          ctx.fillRect(offset + col * cellSize, offset + row * cellSize, cellSize - 0.5, cellSize - 0.5);
        }
      }
    }

    // Label
    ctx.fillStyle = '#333';
    ctx.font = `bold 8px monospace`;
    ctx.textAlign = 'center';
    ctx.fillText('MYCEL', size / 2, size - 4);
  }
};

// ══════════════════════════════════════════════════════════
// 9. UI
// ══════════════════════════════════════════════════════════
const UI = {
  currentScreen: 'feed',

  toast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    document.getElementById('toast-container').appendChild(el);
    setTimeout(() => el.remove(), 3500);
  },

  setKeyGenStatus(msg) {
    const el = document.getElementById('key-gen-status');
    if (el) el.textContent = msg;
  },

  showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const target = document.getElementById(`screen-${name}`);
    if (target) target.classList.add('active');

    document.querySelectorAll('.nav-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.screen === name);
    });
    UI.currentScreen = name;

    if (name === 'feed') UI.renderFeed();
    if (name === 'peers') { UI.renderPeers(); UI.renderQR(); }
    if (name === 'identity') UI.renderIdentity();
  },

  showMainApp() {
    document.getElementById('screen-onboard').classList.remove('active');
    document.getElementById('bottom-nav').style.display = 'block';
    UI.showScreen('feed');
  },

  renderFeed() {
    Posts.getAll().then(posts => {
      const container = document.getElementById('feed-list');
      const label = document.getElementById('feed-label');
      if (!container) return;

      label.textContent = `Flöde — ${posts.length} inlägg`;

      if (posts.length === 0) {
        container.innerHTML = `
          <div class="card text-muted text-center" style="font-size:13px;padding:32px;">
            Inga inlägg ännu.<br>
            <span style="font-size:11px;margin-top:8px;display:block;">
              Skriv ditt första inlägg ovan, eller anslut till en peer för att se deras flöde.
            </span>
          </div>`;
        return;
      }

      container.innerHTML = posts.map(p => `
        <div class="post-card" data-id="${p.id}">
          <div class="post-header">
            <div class="avatar">${Identity.avatarEmoji(p.authorPubkey)}</div>
            <div class="post-author">
              <strong>${escHtml(p.authorName || 'Okänd')}</strong>
              <span>${Identity.shortKey(p.authorPubkey)} · ${timeAgo(p.timestamp)}</span>
            </div>
            <div class="post-sig" title="Kryptografiskt signerat inlägg">
              🔏 verifierat
            </div>
          </div>
          <div class="post-content">${escHtml(p.text)}</div>
          <div class="post-footer">
            <button class="post-action-btn" onclick="UI.likePost('${p.id}')">
              ♡ gilla
            </button>
            <button class="post-action-btn" onclick="UI.gossipPost('${p.id}')">
              📡 gossip
            </button>
            ${p.local ? `<button class="post-action-btn" onclick="UI.deletePost('${p.id}')">🗑 radera</button>` : ''}
            <span class="hops">${p.hops > 0 ? `${p.hops} hopp` : 'lokalt'}</span>
          </div>
        </div>
      `).join('');
    });
  },

  async likePost(id) {
    UI.toast('♥ Gilla-signal skickas via gossip…', 'info');
    Gossip.broadcast({ type: 'like', postId: id });
  },

  async gossipPost(id) {
    const posts = await Posts.getAll();
    const post = posts.find(p => p.id === id);
    if (!post) return;
    Gossip.broadcast({ type: 'post', post });
    UI.toast('📡 Inlägg skickades vidare till alla peers', 'success');
  },

  async deletePost(id) {
    if (!confirm('Radera detta inlägg?')) return;
    await Posts.delete(id);
    UI.renderFeed();
    UI.toast('🗑 Inlägg raderat', 'info');
  },

  renderPeers() {
    const list = document.getElementById('peers-list');
    if (!list) return;
    Peers.getAll().then(peers => {
      if (peers.length === 0) {
        list.innerHTML = `<div class="card text-muted text-center" style="font-size:12px;">
          Inga peers ännu — dela din QR-kod för att komma igång.
        </div>`;
        return;
      }
      list.innerHTML = peers.map(p => {
        const conn = Peers.connections.get(p.pubkey);
        const isOnline = conn?.channel?.readyState === 'open';
        const statusClass = isOnline ? 'online' : '';
        const statusText = isOnline ? 'online' : 'frånkopplad';
        const rc = ManualSignaling._rcCodes.get(p.pubkey);
        const rcSection = (!isOnline && rc) ? `
          <div style="width:100%;margin-top:10px;border-top:1px solid var(--border);padding-top:10px;">
            <div style="font-size:10px;color:var(--text-muted);margin-bottom:6px;">
              📡 Återanslutningskod — skicka till ${escHtml(p.name)}:
            </div>
            <div style="font-family:monospace;font-size:9px;word-break:break-all;background:var(--bg-secondary);padding:6px 8px;border-radius:6px;max-height:56px;overflow:auto;user-select:all;">${escHtml(rc.code)}</div>
            <button class="btn btn-ghost btn-sm w-full" style="margin-top:6px;" onclick="navigator.clipboard?.writeText(${JSON.stringify(rc.code)}).then(()=>UI.toast('📋 Återanslutningskod kopierad!','success'))">
              📋 Kopiera kod
            </button>
          </div>
        ` : '';
        return `
          <div class="peer-card" style="flex-wrap:wrap;align-items:flex-start;">
            <div style="display:flex;align-items:center;gap:10px;width:100%;">
              <div class="avatar">${Identity.avatarEmoji(p.pubkey)}</div>
              <div class="peer-info">
                <strong>${escHtml(p.name)}</strong>
                <span>${Identity.shortKey(p.pubkey)}</span>
              </div>
              <span class="peer-status ${statusClass}">${statusText}</span>
            </div>
            ${rcSection}
          </div>
        `;
      }).join('');

      // Uppdatera badge
      const badge = document.getElementById('peer-badge');
      if (peers.length > 0) {
        badge.style.display = 'flex';
        badge.textContent = peers.length;
      }
    });
  },

  renderQR() {
    const canvas = document.getElementById('qr-canvas');
    const identityText = document.getElementById('identity-info-text');
    if (!canvas || !Identity.current) return;
    const info = `${Identity.current.name} · ${Identity.shortKey(Identity.current.pubkey)}`;
    QR.drawInviteCode(canvas, info);
    if (identityText) identityText.textContent = Identity.current.pubkey;
  },

  renderIdentity() {
    if (!Identity.current) return;
    const id = Identity.current;
    const emoji = Identity.avatarEmoji(id.pubkey);

    document.getElementById('id-avatar').textContent = emoji;
    document.getElementById('id-name').textContent = id.name;
    document.getElementById('id-bio').textContent = id.bio || 'Ingen biografi';
    document.getElementById('id-pubkey-full').textContent = id.pubkey;

    // Recovery shards UI
    const shardList = document.getElementById('recovery-shards-list');
    const shards = JSON.parse(localStorage.getItem('mycel-recovery-shards') || '[]');
    if (shards.length > 0) {
      shardList.innerHTML = shards.map((_, i) => `
        <div class="recovery-shard">
          <div class="shard-peer">Fragment ${i + 1} av ${shards.length}</div>
          <div class="shard-hash">${shards[i].slice(0, 32)}…</div>
        </div>
      `).join('');
    } else {
      shardList.innerHTML = '<p class="text-muted" style="font-size:11px;">Ingen recovery konfigurerad.</p>';
    }

    UI.updateStats();
  },

  async updateStats() {
    const posts = await Posts.getAll();
    const peers = await Peers.getAll();
    const kb = JSON.stringify(posts).length / 1024;

    const sp = document.getElementById('stat-posts');
    const spe = document.getElementById('stat-peers');
    const sk = document.getElementById('stat-kb');
    if (sp) sp.textContent = posts.length;
    if (spe) spe.textContent = peers.length;
    if (sk) sk.textContent = kb.toFixed(1);
  },

  updateConnectionStatus(online) {
    const dot = document.getElementById('connection-dot');
    const label = document.getElementById('connection-label');
    if (dot) dot.className = `status-dot ${online ? 'online' : ''}`;
    if (label) label.textContent = online ? `Online · ${Peers.onlineCount()} peers` : 'Offline';
  },

  updateHeaderCompose() {
    if (!Identity.current) return;
    const av = document.getElementById('compose-avatar');
    const nm = document.getElementById('compose-name-display');
    const pk = document.getElementById('compose-pubkey-short');
    if (av) av.textContent = Identity.avatarEmoji(Identity.current.pubkey);
    if (nm) nm.textContent = Identity.current.name;
    if (pk) pk.textContent = Identity.shortKey(Identity.current.pubkey);
  }
};

// ══════════════════════════════════════════════════════════
// 10. PWA SERVICE WORKER
// ══════════════════════════════════════════════════════════
const SW = {
  async register() {
    if ('serviceWorker' in navigator) {
      try {
        const reg = await navigator.serviceWorker.register('sw.js');
        const el = document.getElementById('sw-status');
        if (el) el.textContent = reg.active ? 'Aktiv ✓' : 'Registrerad';
        return true;
      } catch (err) {
        const el = document.getElementById('sw-status');
        if (el) el.textContent = 'Ej tillgänglig';
        return false;
      }
    }
    return false;
  }
};

// ══════════════════════════════════════════════════════════
// HJÄLPFUNKTIONER
// ══════════════════════════════════════════════════════════
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just nu';
  if (s < 3600) return `${Math.floor(s / 60)} min sedan`;
  if (s < 86400) return `${Math.floor(s / 3600)} h sedan`;
  return `${Math.floor(s / 86400)} d sedan`;
}

// ══════════════════════════════════════════════════════════
// BOOTSTRAP — Huvudinitialisering
// ══════════════════════════════════════════════════════════
async function init() {
  await DB.open();
  const id = await Identity.load();

  if (id) {
    // Befintlig användare
    UI.updateHeaderCompose();
    UI.showMainApp();
    Gossip.init();
    Network.init();
    SW.register();

    // Automatisk återanslutning till kända peers
    Peers.getAll().then(savedPeers => ManualSignaling.autoReconnect(savedPeers));

    // Rensa peer-param ur URL om den finns kvar från en gammal session
    const url = new URL(location.href);
    if (url.searchParams.has('peer')) {
      history.replaceState({}, '', location.pathname);
    }

    // Periodisk status-uppdatering
    setInterval(() => {
      UI.updateConnectionStatus(navigator.onLine || Peers.onlineCount() > 0);
    }, 3000);
    UI.updateConnectionStatus(navigator.onLine);
  } else {
    // Ny användare — visa onboarding
    document.getElementById('screen-onboard').classList.add('active');
  }

  // ── Event Listeners ──

  // Onboarding
  document.getElementById('btn-create-identity').addEventListener('click', async () => {
    const name = document.getElementById('onboard-name').value.trim();
    if (!name) { UI.toast('Fyll i ditt namn', 'error'); return; }
    const bio = document.getElementById('onboard-bio').value.trim();
    const btn = document.getElementById('btn-create-identity');
    btn.disabled = true;
    try {
      await Identity.create(name, bio);
      UI.updateHeaderCompose();
      UI.showMainApp();
      Gossip.init();
      Network.init();
      SW.register();

      // Demo-inlägg
      const welcome = await Posts.create(
        `Hej världen! 🌿 Det här är mitt första inlägg på Skrivpunkten — det decentraliserade nätverket som jag äger. Inga servrar. Inga mellanhänder. Bara ren kryptografi och skvaller.`
      );
      UI.renderFeed();
      UI.toast('🎉 Välkommen till Skrivpunkten!', 'success');
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
      btn.disabled = false;
    }
  });

  // Compose
  const composeText = document.getElementById('compose-text');
  composeText?.addEventListener('input', () => {
    const len = composeText.value.length;
    const cc = document.getElementById('char-count');
    if (cc) {
      cc.textContent = `${len} / 500`;
      cc.className = `char-count ${len > 450 ? 'warn' : ''}`;
    }
  });

  document.getElementById('btn-post')?.addEventListener('click', async () => {
    const text = composeText.value.trim();
    if (!text) { UI.toast('Skriv något först', 'error'); return; }
    if (!Identity.current) { UI.toast('Inte inloggad', 'error'); return; }
    const btn = document.getElementById('btn-post');
    btn.disabled = true;
    try {
      const post = await Posts.create(text);
      composeText.value = '';
      document.getElementById('char-count').textContent = '0 / 500';
      UI.renderFeed();
      // Gossip till peers
      Gossip.broadcast({ type: 'post', post });
      UI.toast('✓ Inlägg publicerat och gossipat', 'success');
      UI.updateStats();
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('btn-broadcast-offline')?.addEventListener('click', () => {
    UI.toast('📴 Offline-läge: Inlägg sparas lokalt och gossipas vid nästa synk', 'info');
  });

  // Nav
  document.querySelectorAll('.nav-btn[data-screen]').forEach(btn => {
    btn.addEventListener('click', () => UI.showScreen(btn.dataset.screen));
  });

  // Peers
  // Peers — Skapa inbjudan
  document.getElementById('btn-create-offer')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-create-offer');
    btn.disabled = true;
    try {
      UI.toast('⏳ Samlar nätverksvägar…', 'info');
      const { code } = await ManualSignaling.createOffer();
      const box = document.getElementById('offer-output-box');
      const pre = document.getElementById('offer-output-code');
      if (pre) pre.textContent = code;
      if (box) box.style.display = 'block';
      UI.toast('✔ Inbjudningskod skapad — kopiera och skicka!', 'success');
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('btn-copy-offer')?.addEventListener('click', () => {
    const code = document.getElementById('offer-output-code')?.textContent;
    if (code) navigator.clipboard?.writeText(code).then(() => UI.toast('📋 Kopierat!', 'success'));
  });

  // Peers — Klistra in kod (inbjudan eller svar)
  document.getElementById('btn-handle-code')?.addEventListener('click', async () => {
    const input = document.getElementById('peer-code-input');
    const code = input?.value.trim();
    if (!code) return;
    const btn = document.getElementById('btn-handle-code');
    btn.disabled = true;
    try {
      const result = await ManualSignaling.handlePastedCode(code);
      if (result.action === 'answered') {
        const box = document.getElementById('answer-output-box');
        const pre = document.getElementById('answer-output-code');
        if (pre) pre.textContent = result.code;
        if (box) box.style.display = 'block';
        input.value = '';
        UI.toast('✔ Svarskod skapad — skicka tillbaka till din vän!', 'success');
      } else if (result.action === 'connected') {
        input.value = '';
        document.getElementById('answer-output-box').style.display = 'none';
        document.getElementById('offer-output-box').style.display = 'none';
        UI.toast('⏳ Upprättar direkt P2P-koppling…', 'info');
      }
    } catch (err) {
      UI.toast('⚠ ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('btn-copy-answer')?.addEventListener('click', () => {
    const code = document.getElementById('answer-output-code')?.textContent;
    if (code) navigator.clipboard?.writeText(code).then(() => UI.toast('📋 Kopierat!', 'success'));
  });

  // Identity
  document.getElementById('btn-export-key')?.addEventListener('click', async () => {
    if (!Identity.current) return;
    const data = JSON.stringify({ name: Identity.current.name, pubkey: Identity.current.pubkey, privkeyJwk: Identity.current.privkeyJwk }, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mycel-identity.json';
    a.click();
    UI.toast('💾 Nyckel exporterad', 'success');
  });

  document.getElementById('btn-edit-profile')?.addEventListener('click', () => {
    const name = prompt('Nytt visningsnamn:', Identity.current?.name);
    if (!name?.trim()) return;
    const bio = prompt('Ny biografi:', Identity.current?.bio || '');
    Identity.current.name = name.trim();
    Identity.current.bio = bio?.trim() || '';
    DB.put('identity', Identity.current);
    UI.renderIdentity();
    UI.updateHeaderCompose();
    UI.toast('✓ Profil uppdaterad', 'success');
  });

  document.getElementById('btn-setup-recovery')?.addEventListener('click', async () => {
    UI.toast('🛡 Genererar 3 återställningsfragment...', 'info');
    const shards = await Identity.createRecoveryShards(3);
    localStorage.setItem('mycel-recovery-shards', JSON.stringify(shards));
    UI.renderIdentity();
    UI.toast('✓ 3 fragment skapade — dela med betrodda vänner', 'success');
  });

  document.getElementById('btn-reset-identity')?.addEventListener('click', async () => {
    if (!confirm('⚠ Detta raderar din identitet och ALL data. Kan inte ångras. Fortsätta?')) return;
    await DB.clear('identity');
    await DB.clear('posts');
    await DB.clear('peers');
    await DB.clear('seen');
    localStorage.clear();
    location.reload();
  });

  // PWA install
  let deferredInstall = null;
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    deferredInstall = e;
    document.getElementById('install-banner')?.classList.add('show');
  });
  document.getElementById('btn-install')?.addEventListener('click', () => {
    deferredInstall?.prompt();
  });
  document.getElementById('btn-install-dismiss')?.addEventListener('click', () => {
    document.getElementById('install-banner')?.classList.remove('show');
  });

  document.getElementById('btn-toggle-gossip')?.addEventListener('click', (e) => {
    Gossip.active = !Gossip.active;
    e.target.textContent = Gossip.active ? 'Aktivt ✓' : 'Inaktivt';
    UI.toast(Gossip.active ? '📡 Gossip-protokoll aktiverat' : '🔇 Gossip pausat', 'info');
  });
}

// Start
document.addEventListener('DOMContentLoaded', init);

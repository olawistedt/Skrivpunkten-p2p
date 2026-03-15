/**
 * MYCEL — Decentraliserat Socialt Nätverk
 * =========================================
 * Arkitektur (enligt specifikationen):
 *  1. Asymmetrisk kryptografi (ECDSA P-256) för identitet & signering
 *  2. IndexedDB för offline-first lokal lagring
 *  3. BroadcastChannel + simulerad WebRTC-signaleringskanal för P2P
 *  4. Gossip-protokoll för dataspridning
 *  5. Social Recovery via Shamir-liknande nyckeldelning (simulerad)
 *  6. PWA Service Worker
 */

'use strict';

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
      : ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
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
    const emojis = ['🌱','🌿','🍀','🌲','🍄','🌾','🌸','🌺','🌻','🌼','🍁','🦋','🐝','🐞','🦎','🐸','🦊','🐺','🦁','🐬'];
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
      shards.push(Array.from(rand).map(b => b.toString(16).padStart(2,'0')).join(''));
      for (let j = 0; j < data.length; j++) xorAccum[j] ^= rand[j];
    }
    // Sista shard = data XOR alla övriga
    const lastShard = new Uint8Array(data.length);
    for (let j = 0; j < data.length; j++) lastShard[j] = data[j] ^ xorAccum[j];
    shards.push(Array.from(lastShard).map(b => b.toString(16).padStart(2,'0')).join(''));

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
    if (!valid) { console.warn('Ogiltig signatur på inlägg:', post.id); return false; }

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

  /** Skapa inbjudningslänk med publik nyckel */
  createInviteLink() {
    if (!Identity.current) return '';
    const data = btoa(JSON.stringify({
      pubkey: Identity.current.pubkey,
      name: Identity.current.name,
      ts: Date.now()
    }));
    return `${location.origin}${location.pathname}?peer=${data}`;
  },

  /** Parsa inbjudningslänk */
  parseInviteLink(url) {
    try {
      const u = new URL(url);
      const p = u.searchParams.get('peer');
      if (!p) return null;
      return JSON.parse(atob(p));
    } catch { return null; }
  },

  /** Simulera WebRTC-anslutning via BroadcastChannel */
  async connectToPeer(peerData) {
    const { pubkey, name } = peerData;
    if (Peers.connections.has(pubkey)) return;
    if (pubkey === Identity.current?.pubkey) {
      UI.toast('Det är din egen nyckel!', 'error'); return;
    }

    // I produktion: WebRTC offer/answer exchange
    // Här simulerar vi med BroadcastChannel
    const channel = new BroadcastChannel(`mycel-p2p-${pubkey}`);
    Peers.connections.set(pubkey, { channel, name, lastSeen: Date.now() });

    channel.onmessage = async (e) => {
      await Gossip.handleMessage(e.data, pubkey);
    };

    await Peers.add({ pubkey, name });

    // Skicka handshake
    channel.postMessage({
      type: 'handshake',
      from: Identity.current.pubkey,
      name: Identity.current.name,
      ts: Date.now()
    });

    // Skicka egna inlägg som gossip
    setTimeout(() => Gossip.syncWithPeer(pubkey), 500);
    UI.toast(`✓ Ansluten till ${name}`, 'success');
    Network.addNode(pubkey, name);
    UI.renderPeers();
    UI.updateStats();
    return true;
  },

  onlineCount() {
    return Peers.connections.size;
  }
};

// ══════════════════════════════════════════════════════════
// 6. GOSSIP-PROTOKOLL
// ══════════════════════════════════════════════════════════
const Gossip = {
  active: true,
  selfChannel: null, // lyssnar på alla kanaler

  init() {
    // Lyssna på vår egna pubkey-kanal
    if (!Identity.current) return;
    Gossip.selfChannel = new BroadcastChannel(`mycel-p2p-${Identity.current.pubkey}`);
    Gossip.selfChannel.onmessage = async (e) => {
      await Gossip.handleMessage(e.data, e.data.from);
    };
  },

  async handleMessage(msg, fromPubkey) {
    if (!msg || !msg.type) return;
    switch (msg.type) {
      case 'handshake':
        if (!Peers.connections.has(fromPubkey)) {
          const ch = new BroadcastChannel(`mycel-p2p-${fromPubkey}`);
          Peers.connections.set(fromPubkey, {
            channel: ch, name: msg.name, lastSeen: Date.now()
          });
          await Peers.add({ pubkey: fromPubkey, name: msg.name });
          Network.addNode(fromPubkey, msg.name);
          UI.renderPeers();
          UI.updateStats();
          UI.toast(`📡 ${msg.name} anslöt sig`, 'info');
          setTimeout(() => Gossip.syncWithPeer(fromPubkey), 300);
        }
        break;

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

      case 'sync_request':
        // Svara med alla dina inlägg
        const posts = await Posts.getAll();
        const conn = Peers.connections.get(fromPubkey);
        if (conn) {
          conn.channel.postMessage({
            type: 'sync_response',
            from: Identity.current.pubkey,
            posts
          });
        }
        break;

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
      try {
        conn.channel.postMessage({
          ...message,
          from: Identity.current?.pubkey
        });
      } catch (err) {
        console.warn('Kunde inte skicka till peer:', pubkey, err);
      }
    }
  },

  async syncWithPeer(pubkey) {
    const conn = Peers.connections.get(pubkey);
    if (!conn) return;
    conn.channel.postMessage({
      type: 'sync_request',
      from: Identity.current.pubkey
    });
  },

  forwardToOthers(msg, exceptPubkey) {
    if (msg.post && msg.post.hops >= 6) return; // max 6 hopp
    for (const [pubkey, conn] of Peers.connections) {
      if (pubkey === exceptPubkey) continue;
      try {
        conn.channel.postMessage({
          ...msg,
          from: Identity.current?.pubkey
        });
      } catch {}
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
      x: W/2 + Math.cos(angle) * (isSelf ? 0 : r),
      y: H/2 + Math.sin(angle) * (isSelf ? 0 : r),
      name, isSelf,
      emoji: Identity.avatarEmoji(pubkey),
      vx: (Math.random()-0.5)*0.5,
      vy: (Math.random()-0.5)*0.5
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
      if (node.x < 20 || node.x > W-20) node.vx *= -1;
      if (node.y < 20 || node.y > H-20) node.vy *= -1;
    }

    // Repulsion
    const arr = [...Network.nodes.values()];
    for (let i = 0; i < arr.length; i++) {
      for (let j = i+1; j < arr.length; j++) {
        const dx = arr[j].x - arr[i].x;
        const dy = arr[j].y - arr[i].y;
        const dist = Math.sqrt(dx*dx+dy*dy) || 1;
        if (dist < 80) {
          const f = (80-dist)/80 * 0.3;
          arr[i].vx -= dx/dist*f;
          arr[i].vy -= dy/dist*f;
          arr[j].vx += dx/dist*f;
          arr[j].vy += dy/dist*f;
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
      ctx.arc(px, py, 2.5, 0, Math.PI*2);
      ctx.fillStyle = 'rgba(124,252,138,0.8)';
      ctx.fill();
    }

    // Draw nodes
    for (const [pubkey, node] of Network.nodes) {
      const isSelected = pubkey === Identity.current?.pubkey;
      ctx.beginPath();
      ctx.arc(node.x, node.y, isSelected ? 14 : 10, 0, Math.PI*2);
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
      ctx.fillText(node.name?.slice(0,12) || '?', node.x, node.y + 18);
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
      ctx.fillRect(x, y, cellSize*7, cellSize*7);
      ctx.fillStyle = '#fff';
      ctx.fillRect(x+cellSize, y+cellSize, cellSize*5, cellSize*5);
      ctx.fillStyle = '#000';
      ctx.fillRect(x+cellSize*2, y+cellSize*2, cellSize*3, cellSize*3);
    };
    drawFinder(offset, offset);
    drawFinder(size - offset - cellSize*7, offset);
    drawFinder(offset, size - offset - cellSize*7);

    // Data-celler (pseudo-slumpmässiga baserat på texten)
    let rng = seed;
    for (let row = 0; row < cells; row++) {
      for (let col = 0; col < cells; col++) {
        // Hoppa över finder-pattern-zoner
        if ((row < 9 && col < 9) || (row < 9 && col > cells-9) || (row > cells-9 && col < 9)) continue;
        rng = (rng * 1664525 + 1013904223) & 0xffffffff;
        if (rng % 3 === 0) {
          ctx.fillStyle = '#000';
          ctx.fillRect(offset + col * cellSize, offset + row * cellSize, cellSize-0.5, cellSize-0.5);
        }
      }
    }

    // Label
    ctx.fillStyle = '#333';
    ctx.font = `bold 8px monospace`;
    ctx.textAlign = 'center';
    ctx.fillText('MYCEL', size/2, size - 4);
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
        const isOnline = Peers.connections.has(p.pubkey);
        const statusClass = isOnline ? 'online' : '';
        const statusText = isOnline ? 'online' : 'frånkopplad';
        return `
          <div class="peer-card">
            <div class="avatar">${Identity.avatarEmoji(p.pubkey)}</div>
            <div class="peer-info">
              <strong>${escHtml(p.name)}</strong>
              <span>${Identity.shortKey(p.pubkey)}</span>
            </div>
            <span class="peer-status ${statusClass}">${statusText}</span>
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
    const inviteText = document.getElementById('invite-link-text');
    if (!canvas || !Identity.current) return;
    const link = Peers.createInviteLink();
    QR.drawInviteCode(canvas, link);
    if (inviteText) inviteText.textContent = link;
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
          <div class="shard-peer">Fragment ${i+1} av ${shards.length}</div>
          <div class="shard-hash">${shards[i].slice(0,32)}…</div>
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
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just nu';
  if (s < 3600) return `${Math.floor(s/60)} min sedan`;
  if (s < 86400) return `${Math.floor(s/3600)} h sedan`;
  return `${Math.floor(s/86400)} d sedan`;
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

    // Kontrollera URL för peer-inbjudan
    const url = new URL(location.href);
    const peerParam = url.searchParams.get('peer');
    if (peerParam) {
      try {
        const peerData = JSON.parse(atob(peerParam));
        setTimeout(() => {
          if (confirm(`Anslut till ${peerData.name}?`)) {
            Peers.connectToPeer(peerData);
          }
        }, 800);
        // Rensa URL
        history.replaceState({}, '', location.pathname);
      } catch {}
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
        `Hej världen! 🌿 Det här är mitt första inlägg på Mycel — det decentraliserade nätverket som jag äger. Inga servrar. Inga mellanhänder. Bara ren kryptografi och skvaller.`
      );
      UI.renderFeed();
      UI.toast('🎉 Välkommen till Mycel!', 'success');
    } catch(err) {
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
    } catch(err) {
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
  document.getElementById('btn-connect-peer')?.addEventListener('click', async () => {
    const val = document.getElementById('peer-invite-input').value.trim();
    if (!val) return;
    const data = Peers.parseInviteLink(val);
    if (!data) { UI.toast('Ogiltig inbjudningslänk', 'error'); return; }
    await Peers.connectToPeer(data);
    document.getElementById('peer-invite-input').value = '';
  });

  document.getElementById('btn-copy-invite')?.addEventListener('click', () => {
    const link = Peers.createInviteLink();
    navigator.clipboard?.writeText(link).then(() => UI.toast('📋 Länk kopierad!', 'success'));
  });

  document.getElementById('btn-share-invite')?.addEventListener('click', () => {
    const link = Peers.createInviteLink();
    if (navigator.share) {
      navigator.share({ title: 'Gå med i Mycel', url: link });
    } else {
      navigator.clipboard?.writeText(link);
      UI.toast('📋 Länk kopierad!', 'success');
    }
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

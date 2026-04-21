const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jetbattle-secret-change-in-production';

// Database setup
const db = new Database('jetbattle.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS games (
    id TEXT PRIMARY KEY,
    host_id INTEGER,
    guest_id INTEGER,
    status TEXT DEFAULT 'waiting',
    settings TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// In-memory game state (active games)
const activeGames = new Map();
// Map of userId -> WebSocket
const userSockets = new Map();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── AUTH ROUTES ────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    const result = stmt.run(username, hash);
    const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(400).json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid username or password' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

// ─── GAME ROUTES ────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/games', authMiddleware, (req, res) => {
  const gameId = uuidv4().slice(0, 8).toUpperCase();
  const settings = req.body.settings || { bs: 9, na: 3, apt: 1 };

  db.prepare('INSERT INTO games (id, host_id, settings) VALUES (?, ?, ?)').run(
    gameId, req.user.id, JSON.stringify(settings)
  );

  activeGames.set(gameId, {
    id: gameId,
    hostId: req.user.id,
    hostName: req.user.username,
    guestId: null,
    guestName: null,
    settings,
    status: 'waiting',
    state: null
  });

  res.json({ gameId, link: `/game/${gameId}` });
});

app.get('/api/games/:id', (req, res) => {
  const game = activeGames.get(req.params.id.toUpperCase());
  if (!game) return res.status(404).json({ error: 'Game not found' });
  res.json({
    id: game.id,
    hostName: game.hostName,
    guestName: game.guestName,
    status: game.status,
    settings: game.settings
  });
});

// ─── WEBSOCKET ──────────────────────────────────────────────────

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function broadcast(gameId, msg, excludeUserId = null) {
  const game = activeGames.get(gameId);
  if (!game) return;
  [game.hostId, game.guestId].forEach(uid => {
    if (uid && uid !== excludeUserId) {
      const ws = userSockets.get(uid);
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msg));
      }
    }
  });
}

function sendTo(userId, msg) {
  const ws = userSockets.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

wss.on('connection', (ws) => {
  let userId = null;
  let currentGameId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // AUTH
    if (msg.type === 'auth') {
      const user = verifyToken(msg.token);
      if (!user) { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); return; }
      userId = user.id;
      userSockets.set(userId, ws);
      ws.send(JSON.stringify({ type: 'authed', username: user.username }));
      return;
    }

    if (!userId) { ws.send(JSON.stringify({ type: 'error', message: 'Not authenticated' })); return; }

    // JOIN GAME
    if (msg.type === 'join') {
      const gameId = msg.gameId.toUpperCase();
      const game = activeGames.get(gameId);
      if (!game) { ws.send(JSON.stringify({ type: 'error', message: 'Game not found' })); return; }

      currentGameId = gameId;

      if (game.hostId === userId) {
        // Host rejoining
        ws.send(JSON.stringify({ type: 'joined', role: 'host', game: sanitizeGame(game) }));
        return;
      }

      if (game.guestId && game.guestId !== userId) {
        ws.send(JSON.stringify({ type: 'error', message: 'Game is full' })); return;
      }

      if (!game.guestId) {
        const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
        game.guestId = userId;
        game.guestName = user ? user.username : 'Guest';
        game.status = 'placement';
        game.state = initGameState(game);
        db.prepare('UPDATE games SET guest_id = ?, status = ? WHERE id = ?').run(userId, 'placement', gameId);
      }

      ws.send(JSON.stringify({ type: 'joined', role: 'guest', game: sanitizeGame(game) }));
      broadcast(gameId, { type: 'game_start', game: sanitizeGame(game) }, userId);
      return;
    }

    // PLACE AIRCRAFT
    if (msg.type === 'place') {
      const game = activeGames.get(currentGameId);
      if (!game || !game.state) return;
      const role = game.hostId === userId ? 'host' : 'guest';
      const player = game.state[role];
      if (player.placed.length >= game.settings.na) return;

      const { r, c, dir } = msg;
      const cells = getAircraftCells(dir, r, c);
      const allPlaced = player.placed.flatMap(a => getAircraftCells(a.dir, a.r, a.c));
      if (!isValidPlacement(cells, game.settings.bs) || hasOverlap(cells, allPlaced)) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid placement' })); return;
      }

      player.placed.push({ r, c, dir });

      if (player.placed.length === game.settings.na) {
        player.ready = true;
        player.placementTime = Date.now() - player.placementStart;
      }

      sendTo(userId, JSON.stringify({ type: 'placed', placed: player.placed, ready: player.ready }));

      // Both ready — start battle
      if (game.state.host.ready && game.state.guest.ready) {
        // Fastest placement goes first
        const hostFirst = game.state.host.placementTime <= game.state.guest.placementTime;
        game.state.currentTurn = hostFirst ? 'host' : 'guest';
        game.state.attemptsLeft = game.settings.apt;
        game.status = 'battle';

        [game.hostId, game.guestId].forEach(uid => {
          const role2 = uid === game.hostId ? 'host' : 'guest';
          sendTo(uid, {
            type: 'battle_start',
            yourTurn: game.state.currentTurn === role2,
            firstPlayer: hostFirst ? game.hostName : game.guestName,
            attemptsLeft: game.state.attemptsLeft
          });
        });
      }
      return;
    }

    // SHOOT
    if (msg.type === 'shoot') {
      const game = activeGames.get(currentGameId);
      if (!game || !game.state || game.status !== 'battle') return;
      const role = game.hostId === userId ? 'host' : 'guest';
      if (game.state.currentTurn !== role) { ws.send(JSON.stringify({ type: 'error', message: 'Not your turn' })); return; }

      const { r, c } = msg;
      const key = `${r},${c}`;
      const shooter = game.state[role];
      const oppRole = role === 'host' ? 'guest' : 'host';
      const opp = game.state[oppRole];

      if (shooter.shots[key]) { ws.send(JSON.stringify({ type: 'error', message: 'Already shot here' })); return; }

      // Determine result
      let result = 'M';
      for (const ac of opp.placed) {
        const cells = getAircraftCells(ac.dir, ac.r, ac.c);
        const head = getAircraftHead(ac.dir, ac.r, ac.c);
        if (cells.some(([br, bc]) => br === r && bc === c)) {
          result = (head[0] === r && head[1] === c) ? 'D' : 'H';
          break;
        }
      }

      shooter.shots[key] = result;
      if (result === 'D') shooter.destroyed++;

      const shotMsg = { type: 'shot_result', r, c, result, shooter: role, destroyed: shooter.destroyed };

      // Check win
      if (shooter.destroyed >= game.settings.na) {
        game.status = 'finished';
        shotMsg.gameOver = true;
        shotMsg.winner = role === 'host' ? game.hostName : game.guestName;
        // Reveal both fleets
        shotMsg.hostFleet = game.state.host.placed;
        shotMsg.guestFleet = game.state.guest.placed;
        sendTo(game.hostId, shotMsg);
        sendTo(game.guestId, shotMsg);
        return;
      }

      game.state.attemptsLeft--;
      if (game.state.attemptsLeft <= 0) {
        game.state.currentTurn = oppRole;
        game.state.attemptsLeft = game.settings.apt;
        shotMsg.turnChange = true;
        shotMsg.nextTurn = oppRole;
        shotMsg.attemptsLeft = game.settings.apt;
      } else {
        shotMsg.attemptsLeft = game.state.attemptsLeft;
      }

      sendTo(game.hostId, shotMsg);
      sendTo(game.guestId, shotMsg);
      return;
    }

    // CHAT
    if (msg.type === 'chat') {
      const game = activeGames.get(currentGameId);
      if (!game) return;
      const senderName = game.hostId === userId ? game.hostName : game.guestName;
      broadcast(currentGameId, { type: 'chat', from: senderName, text: msg.text.slice(0, 200) });
    }
  });

  ws.on('close', () => {
    if (userId) userSockets.delete(userId);
    if (currentGameId) {
      broadcast(currentGameId, { type: 'opponent_disconnected' }, userId);
    }
  });
});

// ─── GAME LOGIC HELPERS ─────────────────────────────────────────

const SHAPE_UP    = { cells: [[0,2],[1,0],[1,1],[1,2],[1,3],[1,4],[2,2],[3,1],[3,2],[3,3]], headIdx: 0 };
const SHAPE_DOWN  = { cells: [[0,1],[0,2],[0,3],[1,2],[2,0],[2,1],[2,2],[2,3],[2,4],[3,2]], headIdx: 9 };
const SHAPE_RIGHT = { cells: [[2,3],[0,2],[1,2],[2,2],[3,2],[4,2],[2,1],[1,0],[2,0],[3,0]], headIdx: 0 };
const SHAPE_LEFT  = { cells: [[2,0],[1,3],[2,3],[3,3],[2,2],[0,1],[1,1],[2,1],[3,1],[4,1]], headIdx: 0 };
const SHAPES = { up: SHAPE_UP, down: SHAPE_DOWN, right: SHAPE_RIGHT, left: SHAPE_LEFT };

function getAircraftCells(dir, or, oc) {
  return SHAPES[dir].cells.map(([r, c]) => [or + r, oc + c]);
}
function getAircraftHead(dir, or, oc) {
  const [r, c] = SHAPES[dir].cells[SHAPES[dir].headIdx];
  return [or + r, oc + c];
}
function isValidPlacement(cells, gridSize) {
  return cells.every(([r, c]) => r >= 0 && r < gridSize && c >= 0 && c < gridSize);
}
function hasOverlap(cells, others) {
  const set = new Set(others.map(([r, c]) => `${r},${c}`));
  return cells.some(([r, c]) => set.has(`${r},${c}`));
}

function initGameState(game) {
  return {
    host: { placed: [], shots: {}, destroyed: 0, ready: false, placementStart: Date.now(), placementTime: 0 },
    guest: { placed: [], shots: {}, destroyed: 0, ready: false, placementStart: Date.now(), placementTime: 0 },
    currentTurn: null,
    attemptsLeft: game.settings.apt
  };
}

function sanitizeGame(game) {
  return {
    id: game.id,
    hostName: game.hostName,
    guestName: game.guestName,
    status: game.status,
    settings: game.settings
  };
}

// ─── CATCH-ALL FOR SPA ──────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`Jet Battle running on port ${PORT}`);
});

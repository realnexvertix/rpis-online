const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

/* ==================== БАЗА ДАННЫХ ==================== */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance INTEGER NOT NULL DEFAULT 500,
      total_earned INTEGER NOT NULL DEFAULT 0
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS inventory (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      item_id TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, item_id)
    );
  `);
  console.log('✅ База готова');
}

/* ==================== ДАННЫЕ ИГРЫ ==================== */

const RARITIES = {
  common:    { name: 'Обычный',     order: 5 },
  uncommon:  { name: 'Необычный',   order: 4 },
  rare:      { name: 'Редкий',      order: 3 },
  legendary: { name: 'Легендарный', order: 2 },
  mythic:    { name: 'Мифический',  order: 1 }
};

const ITEMS = {
  item_gray_ball: { id: 'item_gray_ball', name: 'Серый шар', display: '●',    rarity: 'common',   value: 5,   desc: '«Он круглый. Наверное.»' },
  item_68:        { id: 'item_68',        name: '68',        display: '68',   rarity: 'uncommon', value: 10,  desc: '«Шестьдесят восемь. Что ещё сказать?»' },
  item_1722:      { id: 'item_1722',      name: '1722',      display: '1722', rarity: 'rare',     value: 25,  desc: '«Тысяча семьсот двадцать два. Красиво.»' },
  ai_dropout:     { id: 'ai_dropout',     name: 'Нейросеть-двоечник', display: 'AI?',  rarity: 'common',    value: 10,  desc: '«Обучалась на мемах.»' },
  ai_prompts:     { id: 'ai_prompts',     name: 'Флешка с промптами', display: '512',  rarity: 'uncommon',  value: 20,  desc: '«Внутри 512 промптов. Все плохие.»' },
  ai_cyber_brain: { id: 'ai_cyber_brain', name: 'Мозг-киборг',        display: 'CPU',  rarity: 'rare',      value: 75,  desc: '«Работает на 3%. Оптимально.»' },
  ai_quantum:     { id: 'ai_quantum',     name: 'Квантовый чип',      display: 'QBT',  rarity: 'legendary', value: 200, desc: '«Считает быстрее, чем ты думаешь. То есть медленно.»' },
  ai_eye:         { id: 'ai_eye',         name: 'Око ИИ',             display: 'EYE',  rarity: 'mythic',    value: 600, desc: '«Оно видит всё. Оно не понимает ничего.»' }
};

const CRATES = {
  common_crate: {
    id: 'common_crate', name: 'Обычный ящик', desc: 'Внутри что-то есть. Наверное.', price: 100,
    drops: [
      { item: 'item_gray_ball', chance: 70 },
      { item: 'item_68',        chance: 25 },
      { item: 'item_1722',      chance: 5  }
    ]
  },
  ai_crate: {
    id: 'ai_crate', name: 'ИИ-ящик', desc: 'Сгенерировано нейросетью. Не факт, что работает.', price: 2000,
    drops: [
      { item: 'ai_dropout',     chance: 50 },
      { item: 'ai_prompts',     chance: 25 },
      { item: 'ai_cyber_brain', chance: 15 },
      { item: 'ai_quantum',     chance: 8  },
      { item: 'ai_eye',         chance: 2  }
    ]
  }
};

const CLICK_REWARD = 2;

/* ==================== ХЕЛПЕРЫ ==================== */

const signToken = (uid) => jwt.sign({ uid }, JWT_SECRET, { expiresIn: '30d' });

async function auth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try {
    const { uid } = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [uid]);
    if (!rows[0]) return res.status(401).json({ error: 'Не авторизован' });
    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: 'Не авторизован' });
  }
}

async function packUser(user) {
  const { rows } = await pool.query('SELECT item_id, count FROM inventory WHERE user_id = $1', [user.id]);
  const inventory = {};
  for (const r of rows) inventory[r.item_id] = r.count;
  return {
    id: user.id, username: user.username,
    balance: user.balance, totalEarned: user.total_earned,
    inventory
  };
}

function setAuthCookie(res, uid) {
  res.cookie('token', signToken(uid), {
    httpOnly: true, sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

/* ==================== MIDDLEWARE ==================== */

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* ==================== АВТОРИЗАЦИЯ ==================== */

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string')
      return res.status(400).json({ error: 'Неверные данные' });
    const name = username.trim();
    if (name.length < 3 || name.length > 20)
      return res.status(400).json({ error: 'Имя: 3–20 символов' });
    if (!/^[a-zA-Zа-яА-Я0-9_]+$/.test(name))
      return res.status(400).json({ error: 'Только буквы, цифры, _' });
    if (password.length < 4)
      return res.status(400).json({ error: 'Пароль: минимум 4 символа' });
    const exists = await pool.query('SELECT 1 FROM users WHERE username = $1', [name]);
    if (exists.rows[0]) return res.status(409).json({ error: 'Имя занято' });
    const hash = bcrypt.hashSync(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *',
      [name, hash]
    );
    setAuthCookie(res, rows[0].id);
    res.json({ user: await packUser(rows[0]) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string')
      return res.status(400).json({ error: 'Неверные данные' });
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username.trim()]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Неверное имя или пароль' });
    setAuthCookie(res, user.id);
    res.json({ user: await packUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  res.json({ user: await packUser(req.user) });
});

/* ==================== ИГРА ==================== */

app.get('/api/game-data', (req, res) => {
  res.json({ RARITIES, ITEMS, CRATES, CLICK_REWARD });
});

app.post('/api/click', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'UPDATE users SET balance = balance + $1, total_earned = total_earned + $1 WHERE id = $2 RETURNING balance, total_earned',
      [CLICK_REWARD, req.user.id]
    );
    res.json({ reward: CLICK_REWARD, balance: rows[0].balance, totalEarned: rows[0].total_earned });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/open-crate', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const crate = CRATES[req.body?.crateId];
    if (!crate) return res.status(400).json({ error: 'Нет такого ящика' });
    await client.query('BEGIN');
    const { rows } = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = rows[0];
    if (user.balance < crate.price) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Не хватает монет' });
    }
    const roll = Math.random() * 100;
    let acc = 0;
    let itemId = crate.drops[crate.drops.length - 1].item;
    for (const d of crate.drops) {
      acc += d.chance;
      if (roll < acc) { itemId = d.item; break; }
    }
    await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [crate.price, user.id]);
    await client.query(`
      INSERT INTO inventory (user_id, item_id, count) VALUES ($1, $2, 1)
      ON CONFLICT (user_id, item_id) DO UPDATE SET count = inventory.count + 1
    `, [user.id, itemId]);
    await client.query('COMMIT');
    const updated = (await pool.query('SELECT * FROM users WHERE id = $1', [user.id])).rows[0];
    res.json({ item: ITEMS[itemId], user: await packUser(updated) });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  } finally { client.release(); }
});

app.post('/api/sell-item', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const itemId = req.body?.itemId;
    const item = ITEMS[itemId];
    if (!item) return res.status(400).json({ error: 'Нет такого предмета' });
    await client.query('BEGIN');
    const { rows } = await client.query(
      'SELECT count FROM inventory WHERE user_id = $1 AND item_id = $2 FOR UPDATE',
      [req.user.id, itemId]
    );
    if (!rows[0] || rows[0].count <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Нет такого предмета в инвентаре' });
    }
    if (rows[0].count === 1) {
      await client.query('DELETE FROM inventory WHERE user_id = $1 AND item_id = $2', [req.user.id, itemId]);
    } else {
      await client.query('UPDATE inventory SET count = count - 1 WHERE user_id = $1 AND item_id = $2', [req.user.id, itemId]);
    }
    await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [item.value, req.user.id]);
    await client.query('COMMIT');
    const updated = (await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
    res.json({ sold: item, reward: item.value, user: await packUser(updated) });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  } finally { client.release(); }
});

app.get('/api/leaderboard', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.username, i.item_id, i.count
      FROM users u LEFT JOIN inventory i ON i.user_id = u.id
    `);
    const players = {};
    for (const row of rows) {
      if (!players[row.id]) players[row.id] = { id: row.id, username: row.username, totalValue: 0 };
      if (row.item_id && ITEMS[row.item_id]) {
        players[row.id].totalValue += ITEMS[row.item_id].value * row.count;
      }
    }
    const sorted = Object.values(players)
      .sort((a, b) => b.totalValue - a.totalValue)
      .slice(0, 50)
      .map((p, idx) => ({ ...p, rank: idx + 1 }));
    res.json({ leaderboard: sorted, me: req.user.id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

/* ==================== ПОИСК ИГРОКА И ОНЛАЙН ==================== */

app.get('/api/find-player/:username', auth, async (req, res) => {
  try {
    const name = req.params.username.trim();
    const { rows } = await pool.query('SELECT id, username FROM users WHERE username = $1', [name]);
    if (!rows[0]) return res.status(404).json({ error: 'Игрок не найден' });
    if (rows[0].id === req.user.id) return res.status(400).json({ error: 'Это ты сам' });
    res.json({ player: rows[0], online: onlineUsers.has(rows[0].id) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/online-players', auth, async (req, res) => {
  try {
    const ids = [...onlineUsers.keys()].filter(id => id !== req.user.id);
    if (!ids.length) return res.json({ players: [] });
    const { rows } = await pool.query(
      'SELECT id, username FROM users WHERE id = ANY($1::int[])',
      [ids]
    );
    res.json({ players: rows });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка сервера' }); }
});

/* ==================== SOCKET.IO — ТРЕЙДЫ ==================== */

const onlineUsers = new Map();     // userId -> socketId
const activeTrades = new Map();    // tradeId -> trade
const pendingRequests = new Map(); // targetId -> { requestId, fromId, fromName }

const makeTradeId = () => 'tr_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
const makeRequestId = () => 'rq_' + Math.random().toString(36).slice(2, 10);

function emitTo(userId, event, data) {
  const sid = onlineUsers.get(Number(userId)) || onlineUsers.get(userId);
  if (sid) io.to(sid).emit(event, data);
}

io.on('connection', (socket) => {
  let currentUserId = null;

  socket.on('auth', async ({ token }) => {
    try {
      const { uid } = jwt.verify(token, JWT_SECRET);
      const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [uid]);
      if (!rows[0]) return socket.emit('auth-error', { error: 'Игрок не найден' });

      currentUserId = Number(uid);
      onlineUsers.set(currentUserId, socket.id);

      socket.emit('auth-ok', { username: rows[0].username });
      io.emit('online-changed', { players: [...onlineUsers.keys()] });
    } catch (e) {
      socket.emit('auth-error', { error: 'Неверный токен' });
    }
  });

  /* ----- ЗАПРОС НА ТРЕЙД ----- */
  socket.on('trade-request', async ({ targetId }) => {
    if (!currentUserId) return;
    targetId = Number(targetId);
    if (targetId === currentUserId) return;
    if (!onlineUsers.has(targetId)) {
      return socket.emit('trade-error', { error: 'Игрок не в сети' });
    }
    if (pendingRequests.has(targetId)) {
      return socket.emit('trade-error', { error: 'У игрока уже есть запрос' });
    }

    const { rows } = await pool.query('SELECT username FROM users WHERE id = $1', [currentUserId]);
    const requestId = makeRequestId();

    pendingRequests.set(targetId, {
      requestId,
      fromId: currentUserId,
      fromName: rows[0].username
    });

    emitTo(targetId, 'trade-request-received', {
      requestId,
      fromId: currentUserId,
      fromName: rows[0].username
    });
  });

  /* ----- ОТВЕТ НА ЗАПРОС ----- */
  socket.on('trade-respond', async ({ requestId, accept }) => {
    if (!currentUserId) return;
    const req = pendingRequests.get(currentUserId);
    if (!req || req.requestId !== requestId) return;
    pendingRequests.delete(currentUserId);

    if (!accept) {
      emitTo(req.fromId, 'trade-declined', { byName: req.fromName });
      return;
    }

    const tradeId = makeTradeId();
    const trade = {
      id: tradeId,
      players: {
        [req.fromId]: { id: req.fromId, items: {}, inventory: {}, confirmed: false },
        [currentUserId]: { id: currentUserId, items: {}, inventory: {}, confirmed: false }
      }
    };
    activeTrades.set(tradeId, trade);

    const playerInfo = {};
    for (const pid of Object.keys(trade.players)) {
      const { rows } = await pool.query('SELECT item_id, count FROM inventory WHERE user_id = $1', [pid]);
      const inv = {};
      for (const r of rows) inv[r.item_id] = r.count;
      trade.players[pid].inventory = inv;

      const u = await pool.query('SELECT username FROM users WHERE id = $1', [pid]);
      playerInfo[pid] = u.rows[0].username;
    }

    for (const pid of Object.keys(trade.players)) {
      emitTo(pid, 'trade-started', buildTradePayload(trade, pid, playerInfo));
    }
  });

  /* ----- ДОБАВИТЬ ПРЕДМЕТ ----- */
  socket.on('trade-add-item', async ({ tradeId, itemId }) => {
    if (!currentUserId) return;
    const trade = activeTrades.get(tradeId);
    if (!trade || !trade.players[currentUserId]) return;
    const me = trade.players[currentUserId];
    if (me.confirmed) return;

    const have = me.inventory[itemId] || 0;
    const added = me.items[itemId] || 0;
    if (added >= have) return socket.emit('trade-error', { error: 'Больше нет этого предмета' });

    me.items[itemId] = added + 1;
    for (const p of Object.values(trade.players)) p.confirmed = false;

    await broadcastTrade(trade);
  });

  /* ----- УБРАТЬ ПРЕДМЕТ ----- */
  socket.on('trade-remove-item', async ({ tradeId, itemId }) => {
    if (!currentUserId) return;
    const trade = activeTrades.get(tradeId);
    if (!trade || !trade.players[currentUserId]) return;
    const me = trade.players[currentUserId];
    if (me.confirmed) return;

    const added = me.items[itemId] || 0;
    if (added <= 0) return;
    if (added === 1) delete me.items[itemId];
    else me.items[itemId] = added - 1;

    for (const p of Object.values(trade.players)) p.confirmed = false;

    await broadcastTrade(trade);
  });

  /* ----- ПОДТВЕРДИТЬ ----- */
  socket.on('trade-confirm', async ({ tradeId }) => {
    if (!currentUserId) return;
    const trade = activeTrades.get(tradeId);
    if (!trade || !trade.players[currentUserId]) return;

    const me = trade.players[currentUserId];
    const totalItems = Object.values(me.items).reduce((s, c) => s + c, 0);
    if (totalItems === 0) return socket.emit('trade-error', { error: 'Добавь хотя бы 1 предмет' });

    me.confirmed = true;

    const players = Object.values(trade.players);
    if (players.every(p => p.confirmed)) {
      try {
        await executeTrade(trade);
        for (const p of players) {
          emitTo(p.id, 'trade-completed', {});
          const u = await pool.query('SELECT * FROM users WHERE id = $1', [p.id]);
          emitTo(p.id, 'inventory-updated', { user: await packUser(u.rows[0]) });
        }
      } catch (e) {
        console.error('Trade error:', e);
        for (const p of players) emitTo(p.id, 'trade-error', { error: 'Ошибка обмена' });
      }
      activeTrades.delete(tradeId);
      return;
    }

    await broadcastTrade(trade);
  });

  /* ----- ОТМЕНА ----- */
  socket.on('trade-cancel', ({ tradeId }) => {
    if (!currentUserId) return;
    const trade = activeTrades.get(tradeId);
    if (!trade) return;
    for (const p of Object.values(trade.players)) {
      emitTo(p.id, 'trade-cancelled', { byId: currentUserId });
    }
    activeTrades.delete(tradeId);
  });

  /* ----- ОТКЛЮЧЕНИЕ ----- */
  socket.on('disconnect', () => {
    if (!currentUserId) return;
    onlineUsers.delete(currentUserId);
    pendingRequests.delete(currentUserId);

    for (const [tid, trade] of activeTrades.entries()) {
      if (trade.players[currentUserId]) {
        for (const p of Object.values(trade.players)) {
          if (p.id !== currentUserId) emitTo(p.id, 'trade-cancelled', { byId: currentUserId });
        }
        activeTrades.delete(tid);
      }
    }
    io.emit('online-changed', { players: [...onlineUsers.keys()] });
  });
});

function buildTradePayload(trade, myId, playerInfo) {
  myId = Number(myId);
  const otherId = Object.keys(trade.players).map(Number).find(id => id !== myId);
  const me = trade.players[myId];
  const other = trade.players[otherId];

  return {
    tradeId: trade.id,
    me: {
      id: myId, name: playerInfo[myId],
      items: me.items, inventory: me.inventory, confirmed: me.confirmed
    },
    other: {
      id: otherId, name: playerInfo[otherId],
      items: other.items, confirmed: other.confirmed
    }
  };
}

async function broadcastTrade(trade) {
  const playerInfo = {};
  for (const pid of Object.keys(trade.players)) {
    const u = await pool.query('SELECT username FROM users WHERE id = $1', [pid]);
    playerInfo[pid] = u.rows[0]?.username || '???';
  }
  for (const pid of Object.keys(trade.players)) {
    emitTo(pid, 'trade-update', buildTradePayload(trade, pid, playerInfo));
  }
}

async function executeTrade(trade) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const players = Object.values(trade.players);

    for (const p of players) {
      const { rows } = await client.query('SELECT item_id, count FROM inventory WHERE user_id = $1 FOR UPDATE', [p.id]);
      const inv = {};
      for (const r of rows) inv[r.item_id] = r.count;
      for (const [itemId, cnt] of Object.entries(p.items)) {
        if ((inv[itemId] || 0) < cnt) throw new Error(`Не хватает ${itemId}`);
      }
    }

    for (const p of players) {
      for (const [itemId, cnt] of Object.entries(p.items)) {
        const { rows } = await client.query(
          'SELECT count FROM inventory WHERE user_id = $1 AND item_id = $2',
          [p.id, itemId]
        );
        const newCount = rows[0].count - cnt;
        if (newCount === 0) {
          await client.query('DELETE FROM inventory WHERE user_id = $1 AND item_id = $2', [p.id, itemId]);
        } else {
          await client.query('UPDATE inventory SET count = $1 WHERE user_id = $2 AND item_id = $3', [newCount, p.id, itemId]);
        }
      }
    }

    for (const p of players) {
      const other = players.find(x => x.id !== p.id);
      for (const [itemId, cnt] of Object.entries(other.items)) {
        await client.query(`
          INSERT INTO inventory (user_id, item_id, count) VALUES ($1, $2, $3)
          ON CONFLICT (user_id, item_id) DO UPDATE SET count = inventory.count + $3
        `, [p.id, itemId, cnt]);
      }
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally { client.release(); }
}

/* ==================== FALLBACK ==================== */

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ==================== СТАРТ ==================== */

initDB().then(() => {
  server.listen(PORT, () => console.log(`🎮 Порт ${PORT}`));
});

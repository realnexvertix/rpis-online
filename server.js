const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const path = require('path');

const app = express();
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
  // === Обычный ящик ===
  item_gray_ball: { id: 'item_gray_ball', name: 'Серый шар', display: '●',    rarity: 'common',   value: 5,   desc: '«Он круглый. Наверное.»' },
  item_68:        { id: 'item_68',        name: '68',        display: '68',   rarity: 'uncommon', value: 10,  desc: '«Шестьдесят восемь. Что ещё сказать?»' },
  item_1722:      { id: 'item_1722',      name: '1722',      display: '1722', rarity: 'rare',     value: 25,  desc: '«Тысяча семьсот двадцать два. Красиво.»' },

  // === ИИ-ящик ===
  ai_dropout:     { id: 'ai_dropout',     name: 'Нейросеть-двоечник', display: 'AI?',  rarity: 'common',    value: 10,  desc: '«Обучалась на мемах.»' },
  ai_prompts:     { id: 'ai_prompts',     name: 'Флешка с промптами', display: '512',  rarity: 'uncommon',  value: 20,  desc: '«Внутри 512 промптов. Все плохие.»' },
  ai_cyber_brain: { id: 'ai_cyber_brain', name: 'Мозг-киборг',        display: 'CPU',  rarity: 'rare',      value: 75,  desc: '«Работает на 3%. Оптимально.»' },
  ai_quantum:     { id: 'ai_quantum',     name: 'Квантовый чип',      display: 'QBT',  rarity: 'legendary', value: 200, desc: '«Считает быстрее, чем ты думаешь. То есть медленно.»' },
  ai_eye:         { id: 'ai_eye',         name: 'Око ИИ',             display: 'EYE',  rarity: 'mythic',    value: 600, desc: '«Оно видит всё. Оно не понимает ничего.»' }
};

const CRATES = {
  common_crate: {
    id: 'common_crate',
    name: 'Обычный ящик',
    desc: 'Внутри что-то есть. Наверное.',
    price: 100,
    drops: [
      { item: 'item_gray_ball', chance: 70 },
      { item: 'item_68',        chance: 25 },
      { item: 'item_1722',      chance: 5  }
    ]
  },
  ai_crate: {
    id: 'ai_crate',
    name: 'ИИ-ящик',
    desc: 'Сгенерировано нейросетью. Не факт, что работает.',
    price: 2000,
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
  const { rows } = await pool.query(
    'SELECT item_id, count FROM inventory WHERE user_id = $1',
    [user.id]
  );
  const inventory = {};
  for (const r of rows) inventory[r.item_id] = r.count;

  return {
    id: user.id,
    username: user.username,
    balance: user.balance,
    totalEarned: user.total_earned,
    inventory
  };
}

function setAuthCookie(res, uid) {
  res.cookie('token', signToken(uid), {
    httpOnly: true,
    sameSite: 'lax',
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
    const user = rows[0];

    setAuthCookie(res, user.id);
    res.json({ user: await packUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
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
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
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
    res.json({
      reward: CLICK_REWARD,
      balance: rows[0].balance,
      totalEarned: rows[0].total_earned
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
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

    // Ролл
    const roll = Math.random() * 100;
    let acc = 0;
    let itemId = crate.drops[crate.drops.length - 1].item;
    for (const d of crate.drops) {
      acc += d.chance;
      if (roll < acc) { itemId = d.item; break; }
    }

    await client.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [crate.price, user.id]
    );
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
  } finally {
    client.release();
  }
});

/* ==================== FALLBACK ==================== */

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ==================== СТАРТ ==================== */

initDB().then(() => {
  app.listen(PORT, () => console.log(`🎮 Порт ${PORT}`));
});

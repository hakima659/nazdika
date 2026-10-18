
const ALLOWED_ORIGIN = "https://hakima659.github.io";

const PLANS = {
  free: { name: "رایگان", price: 0, days: 0 },
  plus: { name: "پلاس", price: 199000, days: 30 },
  special: { name: "ویژه", price: 399000, days: 30 }
};

function response(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Secret",
      "Cache-Control": "no-store"
    }
  });
}

function jsonBody(request) {
  return request.json().catch(() => ({}));
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex) {
  const salt = saltHex
    ? Uint8Array.from(saltHex.match(/.{2}/g) || [], x => parseInt(x, 16))
    : crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  const hash = Array.from(new Uint8Array(bits), b =>
    b.toString(16).padStart(2, "0")
  ).join("");

  return {
    salt: Array.from(salt, b => b.toString(16).padStart(2, "0")).join(""),
    hash
  };
}

async function initDB(db) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      age INTEGER NOT NULL,
      city TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user INTEGER NOT NULL,
      to_user INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(from_user, to_user)
    )`,
    `CREATE TABLE IF NOT EXISTS blocks (
      blocker_id INTEGER NOT NULL,
      blocked_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(blocker_id, blocked_id)
    )`,
    `CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reporter_id INTEGER NOT NULL,
      reported_id INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user INTEGER NOT NULL,
      to_user INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan TEXT NOT NULL,
      amount INTEGER NOT NULL,
      receipt TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TEXT,
      expires_at TEXT
    )`
  ];

  for (const sql of statements) await db.prepare(sql).run();
}

async function currentUser(request, db) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;

  const row = await db.prepare(
    `SELECT u.id, u.name, u.phone, u.age, u.city, u.bio
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > ?`
  ).bind(token, Date.now()).first();

  return row ? { ...row, token } : null;
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    age: user.age,
    city: user.city,
    bio: user.bio
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const corsOrigin = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": corsOrigin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Secret",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    if (!env.DB) return response({ error: "DB_BINDING_MISSING" }, 500, corsOrigin);

    try {
      await initDB(env.DB);
      const path = url.pathname;
      const method = request.method;

      if (path === "/health" && method === "GET") {
        return response({ ok: true, service: "nazdika-api" }, 200, corsOrigin);
      }

      if (path === "/api/plans" && method === "GET") {
        return response({ plans: PLANS }, 200, corsOrigin);
      }

      if (path === "/api/payment-info" && method === "GET") {
        return response({
          cardNumber: env.PAYMENT_CARD_NUMBER || "",
          cardHolder: env.PAYMENT_CARD_HOLDER || ""
        }, 200, corsOrigin);
      }

      if (path === "/api/register" && method === "POST") {
        const body = await jsonBody(request);
        const name = String(body.name || "").trim();
        const phone = String(body.phone || "").replace(/[^\d+]/g, "");
        const password = String(body.password || "");
        const age = Number(body.age);
        const city = String(body.city || "").trim().slice(0, 80);

        if (name.length < 2 || name.length > 60)
          return response({ error: "نام باید بین ۲ تا ۶۰ حرف باشد." }, 400, corsOrigin);
        if (!/^(\+98|0)?9\d{9}$/.test(phone.replace(/^\+98/, "0")))
          return response({ error: "شماره موبایل معتبر نیست." }, 400, corsOrigin);
        if (password.length < 8)
          return response({ error: "رمز عبور باید حداقل ۸ نویسه باشد." }, 400, corsOrigin);
        if (!Number.isInteger(age) || age < 18 || age > 100)
          return response({ error: "ثبت‌نام فقط برای افراد ۱۸ سال به بالا است." }, 400, corsOrigin);

        const normalizedPhone = phone.startsWith("+98")
          ? "0" + phone.slice(3)
          : phone;

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE phone = ?"
        ).bind(normalizedPhone).first();

        if (existing)
          return response({ error: "این شماره قبلاً ثبت‌نام کرده است." }, 409, corsOrigin);

        const pass = await hashPassword(password);
        const result = await env.DB.prepare(
          `INSERT INTO users (name, phone, password_hash, password_salt, age, city)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(name, normalizedPhone, pass.hash, pass.salt, age, city).run();

        const token = randomToken();
        await env.DB.prepare(
          "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(token, result.meta.last_row_id, Date.now() + 30 * 86400000).run();

        return response({
          ok: true,
          token,
          user: {
            id: result.meta.last_row_id,
            name,
            age,
            city,
            bio: ""
          },
          note: "شماره موبایل هنوز با پیامک تأیید نشده است."
        }, 201, corsOrigin);
      }

      if (path === "/api/login" && method === "POST") {
        const body = await jsonBody(request);
        const phone = String(body.phone || "").replace(/[^\d+]/g, "");
        const normalizedPhone = phone.startsWith("+98")
          ? "0" + phone.slice(3)
          : phone;
        const password = String(body.password || "");

        const user = await env.DB.prepare(
          "SELECT * FROM users WHERE phone = ?"
        ).bind(normalizedPhone).first();

        if (!user)
          return response({ error: "شماره یا رمز عبور اشتباه است." }, 401, corsOrigin);

        const pass = await hashPassword(password, user.password_salt);
        if (pass.hash !== user.password_hash)
          return response({ error: "شماره یا رمز عبور اشتباه است." }, 401, corsOrigin);

        const token = randomToken();
        await env.DB.prepare(
          "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(token, user.id, Date.now() + 30 * 86400000).run();

        return response({ ok: true, token, user: safeUser(user) }, 200, corsOrigin);
      }

      const user = await currentUser(request, env.DB);

      if (path === "/api/me" && method === "GET") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const sub = await env.DB.prepare(
          `SELECT plan, status, expires_at FROM subscriptions
           WHERE user_id = ? AND status = 'approved'
           ORDER BY id DESC LIMIT 1`
        ).bind(user.id).first();
        return response({
          user: safeUser(user),
          subscription: sub || { plan: "free", status: "active" }
        }, 200, corsOrigin);
      }

      if (path === "/api/logout" && method === "POST") {
        const header = request.headers.get("Authorization") || "";
        const token = header.startsWith("Bearer ") ? header.slice(7) : "";
        if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
        return response({ ok: true }, 200, corsOrigin);
      }

      if (path === "/api/profile" && method === "POST") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const body = await jsonBody(request);
        const bio = String(body.bio || "").trim().slice(0, 500);
        const city = String(body.city || "").trim().slice(0, 80);
        await env.DB.prepare(
          "UPDATE users SET bio = ?, city = ? WHERE id = ?"
        ).bind(bio, city, user.id).run();
        return response({ ok: true }, 200, corsOrigin);
      }

      if (path === "/api/profiles" && method === "GET") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const rows = await env.DB.prepare(
          `SELECT id, name, age, city, bio FROM users
           WHERE id != ?
           AND id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
           AND id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
           ORDER BY id DESC LIMIT 100`
        ).bind(user.id, user.id, user.id).all();
        return response({ profiles: rows.results || [] }, 200, corsOrigin);
      }

      if (path === "/api/like" && method === "POST") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const body = await jsonBody(request);
        const targetId = Number(body.userId);
        if (!Number.isInteger(targetId) || targetId === user.id)
          return response({ error: "شناسه کاربر نامعتبر است." }, 400, corsOrigin);

        const target = await env.DB.prepare("SELECT id FROM users WHERE id = ?")
          .bind(targetId).first();
        if (!target) return response({ error: "کاربر پیدا نشد." }, 404, corsOrigin);

        const blocked = await env.DB.prepare(
          `SELECT 1 AS found FROM blocks
           WHERE (blocker_id = ? AND blocked_id = ?)
           OR (blocker_id = ? AND blocked_id = ?) LIMIT 1`
        ).bind(user.id, targetId, targetId, user.id).first();
        if (blocked) return response({ error: "امکان پسندیدن این کاربر وجود ندارد." }, 403, corsOrigin);

        await env.DB.prepare(
          "INSERT OR IGNORE INTO likes (from_user, to_user) VALUES (?, ?)"
        ).bind(user.id, targetId).run();

        const mutual = await env.DB.prepare(
          "SELECT 1 AS found FROM likes WHERE from_user = ? AND to_user = ?"
        ).bind(targetId, user.id).first();

        return response({ ok: true, matched: !!mutual }, 200, corsOrigin);
      }

      if (path === "/api/matches" && method === "GET") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const rows = await env.DB.prepare(
          `SELECT u.id, u.name, u.age, u.city, u.bio
           FROM likes a
           JOIN likes b ON b.from_user = a.to_user AND b.to_user = a.from_user
           JOIN users u ON u.id = a.to_user
           WHERE a.from_user = ?
           AND u.id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
           AND u.id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)`
        ).bind(user.id, user.id, user.id).all();
        return response({ matches: rows.results || [] }, 200, corsOrigin);
      }

      if (path === "/api/messages" && method === "GET") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const otherId = Number(url.searchParams.get("userId"));
        const matched = await env.DB.prepare(
          `SELECT 1 AS found FROM likes a JOIN likes b
           ON b.from_user = a.to_user AND b.to_user = a.from_user
           WHERE a.from_user = ? AND a.to_user = ?`
        ).bind(user.id, otherId).first();
        if (!matched) return response({ error: "ابتدا باید پسند دوطرفه ایجاد شود." }, 403, corsOrigin);

        const rows = await env.DB.prepare(
          `SELECT id, from_user, to_user, body, created_at FROM messages
           WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
           ORDER BY id ASC LIMIT 200`
        ).bind(user.id, otherId, otherId, user.id).all();
        return response({ messages: rows.results || [] }, 200, corsOrigin);
      }

      if (path === "/api/messages" && method === "POST") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const body = await jsonBody(request);
        const otherId = Number(body.userId);
        const message = String(body.message || "").trim();

        if (!Number.isInteger(otherId) || otherId === user.id || !message || message.length > 2000)
          return response({ error: "متن یا گیرنده پیام معتبر نیست." }, 400, corsOrigin);

        const matched = await env.DB.prepare(
          `SELECT 1 AS found FROM likes a JOIN likes b
           ON b.from_user = a.to_user AND b.to_user = a.from_user
           WHERE a.from_user = ? AND a.to_user = ?`
        ).bind(user.id, otherId).first();
        if (!matched) return response({ error: "پیام فقط پس از پسند دوطرفه مجاز است." }, 403, corsOrigin);

        const blocked = await env.DB.prepare(
          `SELECT 1 AS found FROM blocks
           WHERE (blocker_id = ? AND blocked_id = ?)
           OR (blocker_id = ? AND blocked_id = ?) LIMIT 1`
        ).bind(user.id, otherId, otherId, user.id).first();
        if (blocked) return response({ error: "ارسال پیام مجاز نیست." }, 403, corsOrigin);

        await env.DB.prepare(
          "INSERT INTO messages (from_user, to_user, body) VALUES (?, ?, ?)"
        ).bind(user.id, otherId, message).run();
        return response({ ok: true }, 201, corsOrigin);
      }

      if (path === "/api/block" && method === "POST") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const body = await jsonBody(request);
        const otherId = Number(body.userId);
        if (!Number.isInteger(otherId) || otherId === user.id)
          return response({ error: "شناسه کاربر نامعتبر است." }, 400, corsOrigin);
        await env.DB.prepare(
          "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)"
        ).bind(user.id, otherId).run();
        return response({ ok: true }, 200, corsOrigin);
      }

      if (path === "/api/report" && method === "POST") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const body = await jsonBody(request);
        const otherId = Number(body.userId);
        const reason = String(body.reason || "").trim().slice(0, 500);
        if (!Number.isInteger(otherId) || otherId === user.id || !reason)
          return response({ error: "گزارش معتبر نیست." }, 400, corsOrigin);
        await env.DB.prepare(
          "INSERT INTO reports (reporter_id, reported_id, reason) VALUES (?, ?, ?)"
        ).bind(user.id, otherId, reason).run();
        return response({ ok: true }, 201, corsOrigin);
      }

      if (path === "/api/subscriptions/request" && method === "POST") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const body = await jsonBody(request);
        const planKey = String(body.plan || "");
        const receipt = String(body.receipt || "").trim().slice(0, 500);
        const plan = PLANS[planKey];

        if (!plan || planKey === "free")
          return response({ error: "پلن انتخابی معتبر نیست." }, 400, corsOrigin);
        if (receipt.length < 3)
          return response({ error: "شماره پیگیری یا توضیح رسید را وارد کنید." }, 400, corsOrigin);

        const pending = await env.DB.prepare(
          "SELECT id FROM subscriptions WHERE user_id = ? AND status = 'pending' LIMIT 1"
        ).bind(user.id).first();
        if (pending) return response({ error: "یک درخواست پرداخت در انتظار بررسی دارید." }, 409, corsOrigin);

        const result = await env.DB.prepare(
          `INSERT INTO subscriptions (user_id, plan, amount, receipt, status)
           VALUES (?, ?, ?, ?, 'pending')`
        ).bind(user.id, planKey, plan.price, receipt).run();
        return response({
          ok: true,
          requestId: result.meta.last_row_id,
          status: "pending",
          message: "درخواست ثبت شد؛ اشتراک فقط پس از تأیید مدیر فعال می‌شود."
        }, 201, corsOrigin);
      }

      if (path === "/api/subscriptions/mine" && method === "GET") {
        if (!user) return response({ error: "UNAUTHORIZED" }, 401, corsOrigin);
        const rows = await env.DB.prepare(
          `SELECT id, plan, amount, status, created_at, expires_at
           FROM subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 20`
        ).bind(user.id).all();
        return response({ subscriptions: rows.results || [] }, 200, corsOrigin);
      }

      if (path === "/api/admin/subscriptions" && method === "GET") {
        if (!env.ADMIN_SECRET ||
            request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) {
          return response({ error: "FORBIDDEN" }, 403, corsOrigin);
        }
        const rows = await env.DB.prepare(
          `SELECT s.id, s.user_id, u.name, u.phone, s.plan, s.amount,
                  s.receipt, s.status, s.created_at
           FROM subscriptions s JOIN users u ON u.id = s.user_id
           ORDER BY s.id DESC LIMIT 100`
        ).all();
        return response({ subscriptions: rows.results || [] }, 200, corsOrigin);
      }

      if (path === "/api/admin/subscriptions/review" && method === "POST") {
        if (!env.ADMIN_SECRET ||
            request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) {
          return response({ error: "FORBIDDEN" }, 403, corsOrigin);
        }
        const body = await jsonBody(request);
        const id = Number(body.id);
        const action = String(body.action || "");
        if (!Number.isInteger(id) || !["approve", "reject"].includes(action))
          return response({ error: "درخواست بررسی معتبر نیست." }, 400, corsOrigin);

        const sub = await env.DB.prepare(
          "SELECT * FROM subscriptions WHERE id = ?"
        ).bind(id).first();
        if (!sub) return response({ error: "درخواست پیدا نشد." }, 404, corsOrigin);
        if (sub.status !== "pending")
          return response({ error: "این درخواست قبلاً بررسی شده است." }, 409, corsOrigin);

        if (action === "approve") {
          const plan = PLANS[sub.plan];
          const expiry = new Date(Date.now() + plan.days * 86400000).toISOString();
          await env.DB.prepare(
            `UPDATE subscriptions SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP,
             expires_at = ? WHERE id = ?`
          ).bind(expiry, id).run();
        } else {
          await env.DB.prepare(
            `UPDATE subscriptions SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP
             WHERE id = ?`
          ).bind(id).run();
        }
        return response({ ok: true, status: action === "approve" ? "approved" : "rejected" }, 200, corsOrigin);
      }

      return response({ error: "NOT_FOUND", path }, 404, corsOrigin);
    } catch (error) {
      return response({
        error: "SERVER_ERROR",
        message: String(error?.message || error).slice(0, 300)
      }, 500, corsOrigin);
    }
  }
};

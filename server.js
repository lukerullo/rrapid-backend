import "dotenv/config";
import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { z } from "zod";

/* ================= CONFIG ================= */
const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("Missing JWT_SECRET environment variable");
}

const DB_PATH = process.env.DATABASE_PATH || "rrapid.db";

// Comma-separated allowlist, e.g. "https://app.com,https://www.app.com"
const CORS_ORIGIN = (process.env.CORS_ORIGIN || "").trim();

// Optional secrets for admin/seed protection
const ADMIN_INVITE_KEY = process.env.ADMIN_INVITE_KEY || "";
const SEED_KEY = process.env.SEED_KEY || "";

/* ================= DB ================= */
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT CHECK(role IN ('customer','driver','admin')),
  name TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS restaurants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  address TEXT
);

CREATE TABLE IF NOT EXISTS menu_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  restaurant_id INTEGER,
  name TEXT,
  price_cents INTEGER
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER,
  restaurant_id INTEGER,
  driver_id INTEGER,
  status TEXT,
  delivery_address TEXT,

  subtotal_cents INTEGER,
  delivery_fee_cents INTEGER,
  platform_fee_cents INTEGER,
  insurance_fee_cents INTEGER,
  tax_cents INTEGER,
  tip_cents INTEGER,
  total_cents INTEGER,

  insurance_selected INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER,
  menu_item_id INTEGER,
  qty INTEGER,
  unit_price_cents INTEGER
);

CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER,
  type TEXT,
  amount_cents INTEGER,
  note TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER,
  category TEXT,
  details TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

/* ================= APP ================= */
const app = express();

// CORS: allow only configured origins in production.
// If CORS_ORIGIN is empty, deny cross-origin by default.
let corsOriginOption = false;
if (!CORS_ORIGIN) {
  corsOriginOption = false;
} else {
  const allow = CORS_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean);
  corsOriginOption = allow.length === 1 ? allow[0] : allow;
}
app.use(cors({ origin: corsOriginOption }));

app.use(express.json());

/* ================= HEALTH ================= */
app.get("/health", (req, res) => res.json({ ok: true }));

/* ================= AUTH HELPERS ================= */
function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "14d" });
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

function requireHeaderSecret(headerName, expectedValue, missingMessage = "Server misconfigured") {
  return (req, res, next) => {
    if (!expectedValue) return res.status(500).json({ error: missingMessage });
    const actual = req.headers[headerName];
    if (actual !== expectedValue) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

/* ================= PRICING ================= */
function pricing({ subtotal, tip = 0, insurance }) {
  const delivery = 399;
  const platform = 350; // $3.50
  const tax = Math.round(subtotal * 0.06);
  const insuranceFee = insurance && subtotal >= 5000 ? 300 : 0;

  return {
    delivery,
    platform,
    tax,
    insuranceFee,
    total: subtotal + delivery + platform + tax + insuranceFee + tip
  };
}

/* ================= AUTH ROUTES ================= */
app.post("/register", async (req, res) => {
  const schema = z.object({
    role: z.enum(["customer", "driver", "admin"]),
    name: z.string(),
    email: z.string().email(),
    password: z.string().min(8)
  });

  let d;
  try {
    d = schema.parse(req.body);
  } catch (e) {
    return res.status(400).json({ error: "Invalid payload" });
  }

  // Prevent public creation of admin accounts without invite key
  if (d.role === "admin") {
    const invite = req.headers["x-admin-invite"];
    if (!ADMIN_INVITE_KEY) return res.status(500).json({ error: "ADMIN_INVITE_KEY not configured" });
    if (invite !== ADMIN_INVITE_KEY) return res.status(403).json({ error: "Forbidden" });
  }

  const hash = await bcrypt.hash(d.password, 10);

  try {
    db.prepare("INSERT INTO users (role,name,email,password_hash) VALUES (?,?,?,?)")
      .run(d.role, d.name, d.email, hash);
  } catch {
    return res.status(409).json({ error: "Email already in use" });
  }

  res.json({ ok: true });
});

app.post("/login", async (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(req.body.email);
  if (!u || !(await bcrypt.compare(req.body.password, u.password_hash))) {
    return res.status(401).json({ error: "Invalid" });
  }
  res.json({ token: signToken(u) });
});

/* ================= RESTAURANTS ================= */
app.get("/restaurants", (req, res) => {
  res.json(db.prepare("SELECT * FROM restaurants").all());
});

// Admin-only
app.post("/restaurants", auth, requireRole("admin"), (req, res) => {
  const id = db.prepare("INSERT INTO restaurants (name,address) VALUES (?,?)")
    .run(req.body.name, req.body.address).lastInsertRowid;
  res.json({ id });
});

// Admin-only
app.post("/menu", auth, requireRole("admin"), (req, res) => {
  const id = db.prepare("INSERT INTO menu_items (restaurant_id,name,price_cents) VALUES (?,?,?)")
    .run(req.body.restaurant_id, req.body.name, req.body.price_cents).lastInsertRowid;
  res.json({ id });
});

app.get("/menu/:rid", (req, res) => {
  res.json(
    db.prepare("SELECT * FROM menu_items WHERE restaurant_id=?").all(req.params.rid)
  );
});

/* ================= ORDERS ================= */
// Any authenticated user can place an order; if you want customers only, add requireRole("customer")
app.post("/orders", auth, (req, res) => {
  if (!Array.isArray(req.body.items) || req.body.items.length === 0) {
    return res.status(400).json({ error: "Missing items" });
  }

  let subtotal = 0;
  for (const i of req.body.items) {
    const m = db.prepare("SELECT price_cents FROM menu_items WHERE id=?").get(i.menu_item_id);
    if (!m) return res.status(400).json({ error: "Invalid menu_item_id" });
    subtotal += m.price_cents * i.qty;
  }

  const p = pricing({
    subtotal,
    tip: req.body.tip_cents || 0,
    insurance: req.body.insurance_selected
  });

  const orderId = db.prepare(`
    INSERT INTO orders (
      customer_id, restaurant_id, status, delivery_address,
      subtotal_cents, delivery_fee_cents, platform_fee_cents,
      insurance_fee_cents, tax_cents, tip_cents, total_cents,
      insurance_selected
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    req.user.id,
    req.body.restaurant_id,
    "PLACED",
    req.body.delivery_address,
    subtotal,
    p.delivery,
    p.platform,
    p.insuranceFee,
    p.tax,
    req.body.tip_cents || 0,
    p.total,
    p.insuranceFee > 0 ? 1 : 0
  ).lastInsertRowid;

  for (const i of req.body.items) {
    const m = db.prepare("SELECT price_cents FROM menu_items WHERE id=?").get(i.menu_item_id);
    db.prepare(
      "INSERT INTO order_items (order_id,menu_item_id,qty,unit_price_cents) VALUES (?,?,?,?)"
    ).run(orderId, i.menu_item_id, i.qty, m.price_cents);
  }

  db.prepare("INSERT INTO ledger (order_id,type,amount_cents,note) VALUES (?,?,?,?)")
    .run(orderId, "PLATFORM", p.platform, "RRapid fee");

  res.json({ orderId, pricing: p });
});

/* ================= DRIVER FLOW ================= */
// Driver-only
app.get("/driver/orders", auth, requireRole("driver"), (req, res) => {
  res.json(
    db.prepare("SELECT * FROM orders WHERE status='PLACED' AND driver_id IS NULL").all()
  );
});

// Driver-only
app.post("/driver/accept/:id", auth, requireRole("driver"), (req, res) => {
  db.prepare(
    "UPDATE orders SET driver_id=?, status='ACCEPTED' WHERE id=? AND driver_id IS NULL"
  ).run(req.user.id, req.params.id);
  res.json({ ok: true });
});

// Driver-only
app.post("/driver/delivered/:id", auth, requireRole("driver"), (req, res) => {
  db.prepare(
    "UPDATE orders SET status='DELIVERED' WHERE id=? AND driver_id=?"
  ).run(req.params.id, req.user.id);
  res.json({ ok: true });
});

/* ================= ISSUES ================= */
app.post("/issues/:orderId", auth, (req, res) => {
  db.prepare("INSERT INTO issues (order_id,category,details) VALUES (?,?,?)")
    .run(req.params.orderId, req.body.category, req.body.details || "");
  res.json({ ok: true });
});

/* ================= SEED ================= */
// Protected: admin + seed key header
app.post(
  "/seed",
  auth,
  requireRole("admin"),
  requireHeaderSecret("x-seed-key", SEED_KEY, "SEED_KEY not configured"),
  (req, res) => {
    const r = db.prepare("INSERT INTO restaurants (name,address) VALUES (?,?)");
    const m = db.prepare("INSERT INTO menu_items (restaurant_id,name,price_cents) VALUES (?,?,?)");
    const id = r.run("RRapid Test Kitchen", "123 Main St").lastInsertRowid;
    m.run(id, "Burger", 1099);
    m.run(id, "Fries", 399);
    res.json({ ok: true });
  }
);

/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`RRapid backend running on port ${PORT}`);
});

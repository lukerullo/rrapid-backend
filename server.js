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

/* ================= DB ================= */
const DB_PATH = process.env.DATABASE_PATH || "rrapid.db";
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
app.use(cors());
app.use(express.json());

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
    role: z.enum(["customer","driver","admin"]),
    name: z.string(),
    email: z.string().email(),
    password: z.string().min(8)
  });
  const d = schema.parse(req.body);
  const hash = await bcrypt.hash(d.password, 10);
  db.prepare(
    "INSERT INTO users (role,name,email,password_hash) VALUES (?,?,?,?)"
  ).run(d.role, d.name, d.email, hash);
  res.json({ ok: true });
});

app.post("/login", async (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(req.body.email);
  if (!u || !(await bcrypt.compare(req.body.password, u.password_hash)))
    return res.status(401).json({ error: "Invalid" });
  res.json({ token: signToken(u) });
});

/* ================= RESTAURANTS ================= */
app.get("/restaurants", (req, res) => {
  res.json(db.prepare("SELECT * FROM restaurants").all());
});

app.post("/restaurants", auth, (req, res) => {
  const id = db.prepare(
    "INSERT INTO restaurants (name,address) VALUES (?,?)"
  ).run(req.body.name, req.body.address).lastInsertRowid;
  res.json({ id });
});

app.post("/menu", auth, (req, res) => {
  const id = db.prepare(
    "INSERT INTO menu_items (restaurant_id,name,price_cents) VALUES (?,?,?)"
  ).run(req.body.restaurant_id, req.body.name, req.body.price_cents).lastInsertRowid;
  res.json({ id });
});

app.get("/menu/:rid", (req, res) => {
  res.json(db.prepare(
    "SELECT * FROM menu_items WHERE restaurant_id=?"
  ).all(req.params.rid));
});

/* ================= ORDERS ================= */
app.post("/orders", auth, (req, res) => {
  let subtotal = 0;
  req.body.items.forEach(i => {
    const m = db.prepare("SELECT price_cents FROM menu_items WHERE id=?").get(i.menu_item_id);
    subtotal += m.price_cents * i.qty;
  });

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

  req.body.items.forEach(i => {
    const m = db.prepare("SELECT price_cents FROM menu_items WHERE id=?").get(i.menu_item_id);
    db.prepare(
      "INSERT INTO order_items (order_id,menu_item_id,qty,unit_price_cents) VALUES (?,?,?,?)"
    ).run(orderId, i.menu_item_id, i.qty, m.price_cents);
  });

  db.prepare(
    "INSERT INTO ledger (order_id,type,amount_cents,note) VALUES (?,?,?,?)"
  ).run(orderId,"PLATFORM",p.platform,"RRapid fee");

  res.json({ orderId, pricing: p });
});

/* ================= DRIVER FLOW ================= */
app.get("/driver/orders", auth, (req, res) => {
  res.json(db.prepare(
    "SELECT * FROM orders WHERE status='PLACED' AND driver_id IS NULL"
  ).all());
});

app.post("/driver/accept/:id", auth, (req, res) => {
  db.prepare(
    "UPDATE orders SET driver_id=?, status='ACCEPTED' WHERE id=? AND driver_id IS NULL"
  ).run(req.user.id, req.params.id);
  res.json({ ok: true });
});

app.post("/driver/delivered/:id", auth, (req, res) => {
  db.prepare(
    "UPDATE orders SET status='DELIVERED' WHERE id=? AND driver_id=?"
  ).run(req.params.id, req.user.id);
  res.json({ ok: true });
});

/* ================= ISSUES ================= */
app.post("/issues/:orderId", auth, (req, res) => {
  db.prepare(
    "INSERT INTO issues (order_id,category,details) VALUES (?,?,?)"
  ).run(req.params.orderId, req.body.category, req.body.details || "");
  res.json({ ok: true });
});

/* ================= SEED ================= */
app.post("/seed", (req, res) => {
  const r = db.prepare("INSERT INTO restaurants (name,address) VALUES (?,?)");
  const m = db.prepare("INSERT INTO menu_items (restaurant_id,name,price_cents) VALUES (?,?,?)");
  const id = r.run("RRapid Test Kitchen","123 Main St").lastInsertRowid;
  m.run(id,"Burger",1099);
  m.run(id,"Fries",399);
  res.json({ ok: true });
});

/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`🚀 RRapid backend running at http://localhost:${PORT}`);
});

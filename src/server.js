import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuid } from "uuid";
import crypto from "crypto";

import { Blockchain } from "./blockchain.js";
import { getDb } from "./db.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));
app.use(express.static("public"));

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const DB_FILE = process.env.DB_FILE;
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10);

const chain = new Blockchain();
const dbPromise = getDb(DB_FILE);

// JWT auth helpers
function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}
function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Register
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  const db = await dbPromise;
  const id = uuid();
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const created_at = new Date().toISOString();
  try {
    await db.run(
      "INSERT INTO voters VALUES (?,?,?,?,?)",
      id,
      name,
      email.toLowerCase(),
      hash,
      created_at
    );
    res.json({ id, name, email });
  } catch {
    res.status(400).json({ error: "Email already registered" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const db = await dbPromise;
  const row = await db.get("SELECT * FROM voters WHERE email=?", [
    email.toLowerCase(),
  ]);
  if (!row) return res.status(400).json({ error: "Invalid credentials" });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });
  const token = signJwt({ id: row.id, email: row.email });
  res.json({ token });
});

// Create election
app.post("/elections", auth, async (req, res) => {
  const { name, candidates } = req.body;
  const db = await dbPromise;
  const id = uuid();
  const created_at = new Date().toISOString();
  await db.run(
    "INSERT INTO elections VALUES (?,?,?,?,?,?,?)",
    id,
    name,
    JSON.stringify(candidates),
    new Date().toISOString(),
    new Date(Date.now() + 86400000).toISOString(),
    req.user.id,
    created_at
  );
  res.json({ id, name, candidates });
});

// Vote
app.post("/vote", auth, async (req, res) => {
  const { electionId, candidate } = req.body;
  const db = await dbPromise;
  const already = await db.get(
    "SELECT * FROM votes_guard WHERE election_id=? AND voter_id=?",
    electionId,
    req.user.id
  );
  if (already) return res.status(400).json({ error: "Already voted" });
  const voterHash = sha256(req.user.id + electionId);
  chain.addTransaction({ electionId, candidate, voterHash });
  await db.run("INSERT INTO votes_guard VALUES (?,?,?)", electionId, req.user.id, new Date().toISOString());
  res.json({ ok: true });
});

// Mine
app.post("/mine", auth, (req, res) => {
  const block = chain.minePendingTransactions();
  if (!block) return res.json({ message: "No pending votes" });
  res.json(block);
});

// Tally
app.get("/tally/:id", (req, res) => {
  res.json(chain.tally(req.params.id));
});

// Chain view
app.get("/chain", (req, res) => {
  res.json(chain.chain);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

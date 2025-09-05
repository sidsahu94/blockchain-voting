require("dotenv").config();
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const sqlite = require("sqlite");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const morgan = require("morgan");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));
app.use(express.static("public"));

// --- SQLite setup ---
let db;
(async () => {
  db = await sqlite.open({ filename: "voting.db", driver: sqlite3.Database });

  // users table
  await db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);

  // elections table
  await db.run(`
    CREATE TABLE IF NOT EXISTS elections (
      id TEXT PRIMARY KEY,
      name TEXT,
      candidates TEXT
    )
  `);

  // votes table
  await db.run(`
    CREATE TABLE IF NOT EXISTS votes (
      id TEXT PRIMARY KEY,
      electionId TEXT,
      userId TEXT,
      candidate TEXT,
      UNIQUE(electionId, userId)
    )
  `);
})();

// --- Blockchain simulation ---
let blockchain = [
  { index: 0, timestamp: Date.now(), votes: [], prevHash: "0", hash: "genesis" }
];
let pendingVotes = [];

function createBlock(votes, prevHash) {
  return {
    index: blockchain.length,
    timestamp: Date.now(),
    votes,
    prevHash,
    hash: uuidv4()
  };
}

// --- Auth Middleware ---
function auth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "No token" });
  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// --- Routes ---

// Register
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const hashed = await bcrypt.hash(password, 10);
  try {
    await db.run("INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)",
      [uuidv4(), name, email, hashed]);
    res.json({ message: "User registered" });
  } catch {
    res.status(400).json({ error: "Email already registered" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "1h"
  });
  res.json({ token });
});

// Create election
app.post("/elections", auth, async (req, res) => {
  const { name, candidates } = req.body;
  if (!name || !candidates || candidates.length === 0)
    return res.status(400).json({ error: "Missing fields" });

  const id = uuidv4();
  await db.run("INSERT INTO elections (id, name, candidates) VALUES (?, ?, ?)",
    [id, name, JSON.stringify(candidates)]);
  res.json({ id, name, candidates });
});

// List elections
app.get("/elections", async (req, res) => {
  const elections = await db.all("SELECT * FROM elections");
  elections.forEach(e => e.candidates = JSON.parse(e.candidates));
  res.json(elections);
});

// Cast vote (one per election)
app.post("/vote", auth, async (req, res) => {
  const { electionId, candidate } = req.body;

  // Check election exists
  const election = await db.get("SELECT * FROM elections WHERE id = ?", [electionId]);
  if (!election) return res.status(400).json({ error: "Invalid election" });

  // Check candidate valid
  const candidates = JSON.parse(election.candidates);
  if (!candidates.includes(candidate))
    return res.status(400).json({ error: "Invalid candidate" });

  // Check if already voted
  const existing = await db.get(
    "SELECT * FROM votes WHERE electionId = ? AND userId = ?",
    [electionId, req.user.id]
  );
  if (existing) return res.status(400).json({ error: "You already voted in this election" });

  const voteId = uuidv4();
  await db.run("INSERT INTO votes (id, electionId, userId, candidate) VALUES (?, ?, ?, ?)",
    [voteId, electionId, req.user.id, candidate]);

  pendingVotes.push({ electionId, candidate, voter: req.user.id });
  res.json({ message: "Vote submitted" });
});

// Mine votes
app.post("/mine", auth, (req, res) => {
  if (pendingVotes.length === 0)
    return res.json({ message: "No votes to mine" });

  const prevHash = blockchain[blockchain.length - 1].hash;
  const block = createBlock(pendingVotes, prevHash);
  blockchain.push(block);
  pendingVotes = [];
  res.json({ message: "Block mined", block });
});

// Tally votes
app.get("/tally/:electionId", async (req, res) => {
  const { electionId } = req.params;
  const votes = await db.all("SELECT candidate FROM votes WHERE electionId = ?", [electionId]);

  const tally = {};
  votes.forEach(v => {
    tally[v.candidate] = (tally[v.candidate] || 0) + 1;
  });

  res.json(Object.entries(tally).map(([candidate, votes]) => ({ candidate, votes })));
});

// Blockchain view
app.get("/chain", (req, res) => {
  res.json(blockchain);
});

// --- Start server ---
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));

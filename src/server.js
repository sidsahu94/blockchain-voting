import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import fs from "fs";
import { createServer } from "http";
import { Server } from "socket.io";

dotenv.config();
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: "*" } });

const PORT = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || "supersecret";

// Middleware
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());
app.use(express.static(path.join(process.cwd(), "public")));

// Database with auto-create
let db;
(async () => {
  const dbFile = process.env.DB_FILE || "./voting.db";
  const dbExists = fs.existsSync(dbFile);

  db = await open({
    filename: dbFile,
    driver: sqlite3.Database
  });

  // Auto-create tables if DB is new
  if (!dbExists) {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'voter'
      );
      CREATE TABLE IF NOT EXISTS elections (
        id TEXT PRIMARY KEY,
        name TEXT,
        candidates TEXT
      );
      CREATE TABLE IF NOT EXISTS votes (
        id TEXT PRIMARY KEY,
        electionId TEXT,
        candidate TEXT,
        userId TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ New voting.db created with tables.");
  } else {
    console.log("✅ Existing voting.db loaded.");
  }
})();

// Blockchain
class Block {
  constructor(index, timestamp, data, previousHash = "") {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.hash = this.calculateHash();
  }
  calculateHash() {
    return `${this.index}${this.timestamp}${JSON.stringify(this.data)}${this.previousHash}`;
  }
}

class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
    this.pendingVotes = [];
  }
  createGenesisBlock() {
    return new Block(0, Date.now(), "Genesis Block", "0");
  }
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }
  addBlock(block) {
    block.previousHash = this.getLatestBlock().hash;
    block.hash = block.calculateHash();
    this.chain.push(block);
  }
  minePendingVotes() {
    if (this.pendingVotes.length === 0) return null;
    const block = new Block(
      this.chain.length,
      Date.now(),
      this.pendingVotes,
      this.getLatestBlock().hash
    );
    this.addBlock(block);
    this.pendingVotes = [];
    return block;
  }
}

const votingBlockchain = new Blockchain();

// Auth middleware
function authenticateToken(req, res, next) {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// Routes
app.post("/auth/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const hash = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS || 10));
  try {
    await db.run(
      "INSERT INTO users (id,name,email,password,role) VALUES (?,?,?,?,?)",
      [uuidv4(), name, email, hash, role || "voter"]
    );
    res.json({ message: "User registered" });
  } catch (e) {
    res.status(400).json({ error: "User already exists" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE email=?", [email]);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, {
    expiresIn: "2h"
  });
  res.json({ token, role: user.role });
});

// Elections
app.get("/elections", authenticateToken, async (req, res) => {
  const rows = await db.all("SELECT * FROM elections");
  res.json(rows.map(r => ({ ...r, candidates: safeParse(r.candidates) })));
});

app.post("/elections", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Only admin" });
  const { name, candidates } = req.body;
  await db.run("INSERT INTO elections (id,name,candidates) VALUES (?,?,?)", [
    uuidv4(),
    name,
    JSON.stringify(candidates)
  ]);
  res.json({ message: "Election created" });
});

// Voting
app.post("/vote", authenticateToken, async (req, res) => {
  const { electionId, candidate } = req.body;
  const exists = await db.get("SELECT * FROM votes WHERE electionId=? AND userId=?", [
    electionId,
    req.user.id
  ]);
  if (exists) return res.status(400).json({ error: "Already voted" });
  await db.run(
    "INSERT INTO votes (id,electionId,candidate,userId) VALUES (?,?,?,?)",
    [uuidv4(), electionId, candidate, req.user.id]
  );
  votingBlockchain.pendingVotes.push({ electionId, candidate, userId: req.user.id });
  io.emit("voteUpdate", { electionId });
  res.json({ message: "Vote submitted" });
});

// Tally
app.get("/tally/:id", async (req, res) => {
  const rows = await db.all(
    "SELECT candidate, COUNT(*) as votes FROM votes WHERE electionId=? GROUP BY candidate",
    [req.params.id]
  );
  res.json(rows);
});

// Mine
app.post("/mine", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Only admin can mine" });
  const block = votingBlockchain.minePendingVotes();
  if (!block) return res.json({ message: "No pending votes" });
  io.emit("mineUpdate", { block });
  res.json({ message: "Block mined", block });
});

// Blockchain
app.get("/chain", (req, res) => res.json(votingBlockchain.chain));

// Votes
app.get("/votes/me", authenticateToken, async (req, res) => {
  const rows = await db.all(
    "SELECT v.*,e.name as electionName FROM votes v JOIN elections e ON v.electionId=e.id WHERE v.userId=?",
    [req.user.id]
  );
  res.json(rows);
});

app.get("/votes/download/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Only admin" });
  const rows = await db.all(
    "SELECT v.*,e.name as electionName,u.email as userEmail FROM votes v JOIN elections e ON v.electionId=e.id JOIN users u ON v.userId=u.id WHERE v.electionId=?",
    [req.params.id]
  );
  res.json(rows);
});

// Safe JSON parse
function safeParse(str) {
  try { return JSON.parse(str); } 
  catch { return []; }
}

// Start server
httpServer.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

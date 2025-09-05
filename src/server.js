import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import { v4 as uuidv4 } from "uuid";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || "supersecret";

// middleware
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());
app.use(express.static("public"));

// DB setup
let db;
(async () => {
  db = await open({
    filename: "./voting.db",
    driver: sqlite3.Database,
  });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT
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
      userId TEXT
    );
  `);
})();

// Blockchain setup
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

// auth middleware
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

// routes
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const id = uuidv4();
    await db.run("INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)", [
      id,
      name,
      email,
      hash,
    ]);
    res.json({ message: "User registered" });
  } catch {
    res.status(400).json({ error: "User already exists" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});

app.post("/elections", authenticateToken, async (req, res) => {
  const { name, candidates } = req.body;
  const id = uuidv4();
  await db.run("INSERT INTO elections (id, name, candidates) VALUES (?, ?, ?)", [
    id,
    name,
    JSON.stringify(candidates),
  ]);
  res.json({ id, name, candidates });
});

app.post("/vote", authenticateToken, async (req, res) => {
  const { electionId, candidate } = req.body;
  const voteId = uuidv4();
  await db.run("INSERT INTO votes (id, electionId, candidate, userId) VALUES (?, ?, ?, ?)", [
    voteId,
    electionId,
    candidate,
    req.user.id,
  ]);
  votingBlockchain.pendingVotes.push({ electionId, candidate, userId: req.user.id });
  res.json({ message: "Vote submitted" });
});

app.post("/mine", authenticateToken, (req, res) => {
  const block = votingBlockchain.minePendingVotes();
  res.json({ message: "Block mined", block });
});

app.get("/tally/:id", async (req, res) => {
  const { id } = req.params;
  const rows = await db.all("SELECT candidate, COUNT(*) as votes FROM votes WHERE electionId = ? GROUP BY candidate", [id]);
  res.json(rows);
});

app.get("/chain", (req, res) => {
  res.json(votingBlockchain.chain);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

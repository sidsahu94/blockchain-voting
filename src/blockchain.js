import crypto from "crypto";

export class Block {
  constructor(index, timestamp, transactions, previousHash = "") {
    this.index = index;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.nonce = 0;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    const data =
      this.index +
      this.timestamp +
      JSON.stringify(this.transactions) +
      this.previousHash +
      this.nonce;
    return crypto.createHash("sha256").update(data).digest("hex");
  }

  mine(difficulty = 3) {
    const prefix = "0".repeat(difficulty);
    while (!this.hash.startsWith(prefix)) {
      this.nonce++;
      this.hash = this.calculateHash();
    }
  }
}

export class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
    this.pendingTransactions = [];
    this.difficulty = 3;
  }

  createGenesisBlock() {
    return new Block(0, new Date().toISOString(), [{ genesis: true }], "0");
  }

  addTransaction(tx) {
    if (!tx.electionId || !tx.candidate || !tx.voterHash) {
      throw new Error("Invalid transaction");
    }
    this.pendingTransactions.push({ ...tx, ts: new Date().toISOString() });
  }

  minePendingTransactions() {
    if (this.pendingTransactions.length === 0) return null;
    const block = new Block(
      this.chain.length,
      new Date().toISOString(),
      this.pendingTransactions,
      this.getLatestBlock().hash
    );
    block.mine(this.difficulty);
    this.chain.push(block);
    this.pendingTransactions = [];
    return block;
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  tally(electionId) {
    const counts = new Map();
    for (const block of this.chain) {
      for (const tx of block.transactions || []) {
        if (tx.electionId === electionId) {
          counts.set(tx.candidate, (counts.get(tx.candidate) || 0) + 1);
        }
      }
    }
    return Array.from(counts.entries()).map(([c, v]) => ({
      candidate: c,
      votes: v,
    }));
  }
}

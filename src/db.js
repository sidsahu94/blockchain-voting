import sqlite3 from "sqlite3";
import { open } from "sqlite";

export async function getDb(dbFile) {
  const db = await open({ filename: dbFile, driver: sqlite3.Database });
  await db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS voters (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS elections (
      id TEXT PRIMARY KEY,
      name TEXT,
      candidates_json TEXT,
      start_ts TEXT,
      end_ts TEXT,
      created_by TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS votes_guard (
      election_id TEXT,
      voter_id TEXT,
      cast_at TEXT,
      PRIMARY KEY (election_id, voter_id)
    );
  `);
  return db;
}

const pool = require('./db');

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      id SERIAL PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP NOT NULL,
      hwid TEXT,
      redeemed_at TIMESTAMP,
      is_active BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS key_logs (
      id SERIAL PRIMARY KEY,
      key TEXT,
      hwid TEXT,
      ip TEXT,
      result TEXT,
      checked_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Migration complete');
  process.exit(0);
}

migrate().catch(console.error);

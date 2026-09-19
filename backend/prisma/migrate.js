// Applies the database schema (database/init/*.sql) idempotently against
// DATABASE_URL.
//
// The Postgres container runs database/init/*.sql automatically ONLY on a fresh
// data volume. If you already have a persisted ./.data/postgres that predates the
// init scripts, the tables won't exist — this recreates them. Every statement in
// the init SQL is guarded (CREATE ... IF NOT EXISTS / ADD COLUMN IF NOT EXISTS),
// so running this repeatedly is safe.
//
//   npm run migrate
//
// The backend container also runs this on startup so `docker compose up` just works.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prisma } from '../src/db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Where to find the init SQL: mounted into the container at /app/database-init,
// or in the repo at ../../database/init for local runs.
const CANDIDATE_DIRS = ['/app/database-init', path.resolve(__dirname, '../../database/init')];

function findSqlDir() {
  for (const d of CANDIDATE_DIRS) {
    if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
      const hasSql = fs.readdirSync(d).some((f) => f.endsWith('.sql'));
      if (hasSql) return d;
    }
  }
  return null;
}

// Split a SQL file into individual statements. The init files use plain
// statements (no functions / dollar-quoting), so splitting on top-level ';'
// after stripping line comments is sufficient.
function splitStatements(sql) {
  const noComments = sql
    .split('\n')
    .map((line) => line.replace(/--.*$/, ''))
    .join('\n');
  return noComments
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
}

async function main() {
  const dir = findSqlDir();
  if (!dir) {
    console.error('Could not locate database/init SQL files. Looked in:', CANDIDATE_DIRS);
    process.exit(1);
  }
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  console.log(`Applying schema from ${dir}: ${files.join(', ')}`);

  // The migrations are deliberately idempotent. PostgreSQL emits a NOTICE for
  // every existing table, column, and index on each backend restart; suppress
  // those expected notices while preserving warnings and errors.
  await prisma.$executeRawUnsafe("SET client_min_messages = 'warning'");

  for (const file of files) {
    const sql = fs.readFileSync(path.join(dir, file), 'utf8');
    const statements = splitStatements(sql);
    for (const stmt of statements) {
      await prisma.$executeRawUnsafe(stmt);
    }
    console.log(`  ✓ ${file} (${statements.length} statements)`);
  }
  console.log('Schema is up to date.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

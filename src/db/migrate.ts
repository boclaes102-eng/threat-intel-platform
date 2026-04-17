import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { readdirSync, existsSync } from 'fs';
import path from 'path';
import 'dotenv/config';

async function runMigrations() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is required');

  const cwd = process.cwd();
  const migrationsFolder = path.resolve(cwd, 'drizzle');
  console.log('CWD:', cwd);
  console.log('Migrations folder:', migrationsFolder);
  console.log('Exists:', existsSync(migrationsFolder));
  if (existsSync(migrationsFolder)) {
    console.log('drizzle/ contents:', readdirSync(migrationsFolder));
    const meta = path.join(migrationsFolder, 'meta');
    console.log('meta/ exists:', existsSync(meta));
    if (existsSync(meta)) console.log('meta/ contents:', readdirSync(meta));
  }

  const client = postgres(url, { max: 1 });
  const db = drizzle(client);

  console.log('Running migrations...');
  await migrate(db, { migrationsFolder });
  console.log('Migrations complete.');

  await client.end();
}

runMigrations().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});

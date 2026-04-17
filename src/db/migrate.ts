import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import path from 'path';
import 'dotenv/config';

async function runMigrations() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is required');

  // drizzle folder is copied into dist/ during build so it ships with the compiled output
  const migrationsFolder = path.join(__dirname, '../../drizzle');

  const client = postgres(url, { max: 1 });
  const db = drizzle(client);

  console.log('Running migrations...');
  await migrate(db, { migrationsFolder });
  console.log('Migrations complete.');

  await client.end({ timeout: 5 });
  process.exit(0);
}

runMigrations().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});

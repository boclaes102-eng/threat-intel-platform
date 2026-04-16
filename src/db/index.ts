import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { env } from '../lib/env';
import * as schema from './schema';

const queryClient = postgres(env.DATABASE_URL, {
  max: env.NODE_ENV === 'test' ? 5 : env.DB_POOL_MAX,
  idle_timeout: 30,
  connect_timeout: 10,
});

export const db = drizzle(queryClient, { schema });

export type DB = typeof db;

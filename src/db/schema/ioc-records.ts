import { pgTable, uuid, varchar, integer, timestamp, jsonb, index } from 'drizzle-orm/pg-core';
import { iocTypeEnum, iocVerdictEnum } from './enums';

export interface IocSource {
  name: string;
  found: boolean;
  verdict: string;
  score: number;
  details?: Record<string, unknown>;
}

export const iocRecords = pgTable('ioc_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  indicator: varchar('indicator', { length: 512 }).unique().notNull(),
  type: iocTypeEnum('type').notNull(),
  verdict: iocVerdictEnum('verdict').notNull(),
  score: integer('score').default(0),
  sources: jsonb('sources').$type<IocSource[]>().default([]),
  lastChecked: timestamp('last_checked').defaultNow().notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (t) => ({
  expiresAtIdx: index('ioc_expires_at_idx').on(t.expiresAt),
}));

export type IocRecord = typeof iocRecords.$inferSelect;
export type NewIocRecord = typeof iocRecords.$inferInsert;

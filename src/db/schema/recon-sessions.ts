import { pgTable, uuid, varchar, text, jsonb, timestamp, index } from 'drizzle-orm/pg-core';
import { users } from './users';
import { reconToolEnum } from './enums';

export const reconSessions = pgTable(
  'recon_sessions',
  {
    id:        uuid('id').primaryKey().defaultRandom(),
    userId:    uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    tool:      reconToolEnum('tool').notNull(),
    target:    varchar('target', { length: 512 }).notNull(),
    summary:   jsonb('summary').$type<Record<string, unknown>>().notNull().default({}),
    results:   jsonb('results').$type<Record<string, unknown>>().notNull().default({}),
    tags:      jsonb('tags').$type<string[]>().notNull().default([]),
    notes:     text('notes'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    userIdx:      index('rs_user_id_idx').on(t.userId),
    toolIdx:      index('rs_tool_idx').on(t.tool),
    createdAtIdx: index('rs_created_at_idx').on(t.createdAt),
  }),
);

export type ReconSession       = typeof reconSessions.$inferSelect;
export type NewReconSession    = typeof reconSessions.$inferInsert;

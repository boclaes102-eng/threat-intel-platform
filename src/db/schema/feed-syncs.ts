import { pgTable, uuid, varchar, text, integer, timestamp, jsonb } from 'drizzle-orm/pg-core';
import { feedStatusEnum } from './enums';

export const feedSyncs = pgTable('feed_syncs', {
  id: uuid('id').primaryKey().defaultRandom(),
  feedType: varchar('feed_type', { length: 50 }).notNull(),
  status: feedStatusEnum('status').default('running').notNull(),
  startedAt: timestamp('started_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at'),
  recordsProcessed: integer('records_processed').default(0),
  recordsAdded: integer('records_added').default(0),
  error: text('error'),
  metadata: jsonb('metadata'),
});

export type FeedSync = typeof feedSyncs.$inferSelect;
export type NewFeedSync = typeof feedSyncs.$inferInsert;

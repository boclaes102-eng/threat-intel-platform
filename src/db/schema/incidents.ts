import { pgTable, uuid, varchar, integer, timestamp, index } from 'drizzle-orm/pg-core';
import { users } from './users';
import { alertSeverityEnum, incidentStatusEnum } from './enums';

export const incidents = pgTable('incidents', {
  id:          uuid('id').primaryKey().defaultRandom(),
  userId:      uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
  title:       varchar('title', { length: 500 }).notNull(),
  severity:    alertSeverityEnum('severity').notNull(),
  status:      incidentStatusEnum('status').notNull().default('open'),
  ruleName:    varchar('rule_name', { length: 200 }).notNull(),
  eventCount:  integer('event_count').notNull().default(1),
  firstSeenAt: timestamp('first_seen_at').notNull(),
  lastSeenAt:  timestamp('last_seen_at').notNull(),
  resolvedAt:  timestamp('resolved_at'),
  createdAt:   timestamp('created_at').defaultNow().notNull(),
  updatedAt:   timestamp('updated_at').defaultNow().notNull(),
}, (t) => ({
  userIdIdx:  index('inc_user_id_idx').on(t.userId),
  statusIdx:  index('inc_status_idx').on(t.userId, t.status),
  createdIdx: index('inc_created_at_idx').on(t.createdAt),
}));

export type Incident    = typeof incidents.$inferSelect;
export type NewIncident = typeof incidents.$inferInsert;

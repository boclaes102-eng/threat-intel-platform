import { pgTable, uuid, varchar, text, inet, integer, timestamp, jsonb, index } from 'drizzle-orm/pg-core';
import { users } from './users';
import { eventCategoryEnum, alertSeverityEnum } from './enums';

export const logEvents = pgTable('log_events', {
  id:        uuid('id').primaryKey().defaultRandom(),
  userId:    uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  source:    varchar('source', { length: 100 }).notNull(),
  category:  eventCategoryEnum('category').notNull(),
  action:    varchar('action', { length: 200 }).notNull(),
  severity:  alertSeverityEnum('severity').notNull().default('info'),
  sourceIp:  inet('source_ip'),
  targetIp:  inet('target_ip'),
  targetPort: integer('target_port'),
  message:   text('message'),
  rawData:   jsonb('raw_data').$type<Record<string, unknown>>(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (t) => ({
  userIdIdx:    index('le_user_id_idx').on(t.userId),
  createdAtIdx: index('le_created_at_idx').on(t.createdAt),
  categoryIdx:  index('le_category_idx').on(t.userId, t.category),
  sourceIpIdx:  index('le_source_ip_idx').on(t.sourceIp),
}));

export type LogEvent    = typeof logEvents.$inferSelect;
export type NewLogEvent = typeof logEvents.$inferInsert;

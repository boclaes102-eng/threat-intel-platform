import { pgTable, uuid, varchar, timestamp, jsonb, index } from 'drizzle-orm/pg-core';
import { users } from './users';
import { assets } from './assets';
import { alertTypeEnum, alertSeverityEnum } from './enums';

export const alerts = pgTable('alerts', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
  type: alertTypeEnum('type').notNull(),
  severity: alertSeverityEnum('severity').notNull(),
  title: varchar('title', { length: 500 }).notNull(),
  details: jsonb('details').$type<Record<string, unknown>>().notNull(),
  readAt: timestamp('read_at'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (t) => ({
  userIdIdx: index('alerts_user_id_idx').on(t.userId),
  createdAtIdx: index('alerts_created_at_idx').on(t.createdAt),
  userSeverityIdx: index('alerts_user_severity_idx').on(t.userId, t.severity),
}));

export type Alert = typeof alerts.$inferSelect;
export type NewAlert = typeof alerts.$inferInsert;

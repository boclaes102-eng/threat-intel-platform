import { pgTable, uuid, varchar, timestamp, boolean, jsonb, unique, index } from 'drizzle-orm/pg-core';
import { users } from './users';
import { assetTypeEnum } from './enums';

export const assets = pgTable('assets', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  type: assetTypeEnum('type').notNull(),
  value: varchar('value', { length: 512 }).notNull(),
  label: varchar('label', { length: 255 }),
  tags: jsonb('tags').$type<string[]>().default([]),
  active: boolean('active').default(true).notNull(),
  lastScanned: timestamp('last_scanned'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (t) => ({
  userValueUnique: unique().on(t.userId, t.value),
  userIdIdx: index('assets_user_id_idx').on(t.userId),
  valueIdx: index('assets_value_idx').on(t.value),
}));

export type Asset = typeof assets.$inferSelect;
export type NewAsset = typeof assets.$inferInsert;

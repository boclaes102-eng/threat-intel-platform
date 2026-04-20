import { pgTable, uuid, varchar, text, integer, boolean, jsonb, timestamp } from 'drizzle-orm/pg-core';
import { alertSeverityEnum, eventCategoryEnum } from './enums';

export const correlationRules = pgTable('correlation_rules', {
  id:              uuid('id').primaryKey().defaultRandom(),
  name:            varchar('name', { length: 200 }).notNull().unique(),
  description:     text('description').notNull(),
  category:        eventCategoryEnum('category').notNull(),
  severity:        alertSeverityEnum('severity').notNull(),
  windowSeconds:   integer('window_seconds').notNull(),
  threshold:       integer('threshold').notNull(),
  groupBy:         varchar('group_by', { length: 100 }),
  conditions:      jsonb('conditions').$type<Record<string, unknown>>().notNull(),
  enabled:         boolean('enabled').notNull().default(true),
  createdAt:       timestamp('created_at').defaultNow().notNull(),
});

export type CorrelationRule    = typeof correlationRules.$inferSelect;
export type NewCorrelationRule = typeof correlationRules.$inferInsert;

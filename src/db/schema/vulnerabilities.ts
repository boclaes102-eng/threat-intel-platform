import { pgTable, uuid, varchar, text, timestamp, jsonb, numeric, unique, index } from 'drizzle-orm/pg-core';
import { assets } from './assets';
import { severityEnum, vulnStatusEnum } from './enums';

export const vulnerabilities = pgTable('vulnerabilities', {
  id: uuid('id').primaryKey().defaultRandom(),
  cveId: varchar('cve_id', { length: 30 }).unique().notNull(),
  title: text('title'),
  description: text('description').notNull(),
  severity: severityEnum('severity').notNull(),
  cvssScore: numeric('cvss_score', { precision: 4, scale: 2 }),
  cvssVector: varchar('cvss_vector', { length: 100 }),
  publishedAt: timestamp('published_at').notNull(),
  modifiedAt: timestamp('modified_at'),
  affectedProducts: jsonb('affected_products').$type<string[]>().default([]),
  references: jsonb('references').$type<string[]>().default([]),
  rawData: jsonb('raw_data'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const assetVulnerabilities = pgTable('asset_vulnerabilities', {
  id: uuid('id').primaryKey().defaultRandom(),
  assetId: uuid('asset_id').notNull().references(() => assets.id, { onDelete: 'cascade' }),
  vulnerabilityId: uuid('vulnerability_id').notNull().references(() => vulnerabilities.id, { onDelete: 'cascade' }),
  status: vulnStatusEnum('status').default('open').notNull(),
  discoveredAt: timestamp('discovered_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (t) => ({
  assetVulnUnique: unique().on(t.assetId, t.vulnerabilityId),
  assetIdIdx: index('av_asset_id_idx').on(t.assetId),
}));

export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type NewVulnerability = typeof vulnerabilities.$inferInsert;
export type AssetVulnerability = typeof assetVulnerabilities.$inferSelect;

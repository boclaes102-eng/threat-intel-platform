import 'dotenv/config';
import { db } from '../src/db';
import {
  alerts,
  assetVulnerabilities,
  assets,
  vulnerabilities,
  iocRecords,
  feedSyncs,
  users,
} from '../src/db/schema';

// Wipe all tables between tests to ensure isolation.
// Order matters — FK constraints require deleting child rows first.
export async function cleanDatabase() {
  await db.delete(alerts);
  await db.delete(assetVulnerabilities);
  await db.delete(assets);
  await db.delete(vulnerabilities);
  await db.delete(iocRecords);
  await db.delete(feedSyncs);
  await db.delete(users);
}

beforeEach(async () => {
  await cleanDatabase();
});

import 'dotenv/config';
import { db } from '../src/db';
import {
  alerts,
  assetVulnerabilities,
  assets,
  vulnerabilities,
  iocRecords,
  feedSyncs,
} from '../src/db/schema';

// Wipe data tables between tests. Users are NOT deleted — each test file
// registers its own user once in beforeAll and relies on it persisting.
export async function cleanDatabase() {
  await db.delete(alerts);
  await db.delete(assetVulnerabilities);
  await db.delete(assets);
  await db.delete(vulnerabilities);
  await db.delete(iocRecords);
  await db.delete(feedSyncs);
}

beforeEach(async () => {
  await cleanDatabase();
});

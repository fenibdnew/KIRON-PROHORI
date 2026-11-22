/**
 * KIRON PROHORI — CISA KEV Tracker Module (/client/modules/kev/index.ts)
 * Official CISA KEV JSON synchronization, snapshot diffing, and Unknown != No ransomware semantics.
 */

export {
  computeKevSnapshotDiff,
  filterAndSortKevRecords,
} from '../../../src/intelligence/engine';
export { validateAndParseCisaKevCatalog } from '../../../src/connectors/parsers';

/**
 * KIRON PROHORI — Unified Test Suite Runner (/tests/run-all.ts)
 * Executes all Phase 2–6 automated verification checks and zero-key startup validation.
 */

import { runPhase6ComprehensiveSuite, EXTERNAL_API_DEPENDENCIES_MATRIX } from '../src/qa/phase6.test';
import { getStartupConnectorConfigSummary } from '../server/controllers';
import { ZERO_COST_STARTUP_POLICY } from '../shared/constants';

const startupSummary = getStartupConnectorConfigSummary();
const qaSuite = runPhase6ComprehensiveSuite();

console.log('===================================================================');
console.log('KIRON PROHORI — Unified Repository Verification Suite (/tests/run-all.ts)');
console.log('===================================================================');
console.log(`Zero-Cost Budget Policy ($0): ${ZERO_COST_STARTUP_POLICY.budgetUsd === 0 ? 'VERIFIED' : 'FAIL'}`);
console.log(`CISA KEV Startup Mode:        ${startupSummary.cisaKevMode}`);
console.log(`NIST NVD 2.0 Startup Mode:    ${startupSummary.nvdMode}`);
console.log(`URLhaus Optional Status:      ${startupSummary.urlhausStatus}`);
console.log(`External Dependencies Audited: ${EXTERNAL_API_DEPENDENCIES_MATRIX.length} ($0 tiers)`);
console.log(`Phase 6 QA / Security / Cost: ${qaSuite.passedChecks}/${qaSuite.totalChecks} checks passed`);

if (!qaSuite.allPassed) {
  process.exit(1);
}

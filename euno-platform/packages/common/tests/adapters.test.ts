/**
 * Tests for adapter exports — including the SIGNING_ALGORITHMS allow-list
 * that prevents type/runtime drift between the SigningAlgorithm type and the
 * issuer's runtime allow-list.
 */

import { SIGNING_ALGORITHMS, SigningAlgorithm } from '../src/adapters';

describe('SIGNING_ALGORITHMS', () => {
  it('includes ES256K (the algorithm previously missing from the type union)', () => {
    expect(SIGNING_ALGORITHMS).toContain('ES256K' as SigningAlgorithm);
  });

  it('includes the full RS/ES/EdDSA family', () => {
    for (const alg of ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA']) {
      expect(SIGNING_ALGORITHMS).toContain(alg as SigningAlgorithm);
    }
  });

  it('contains no duplicate entries', () => {
    expect(new Set(SIGNING_ALGORITHMS).size).toBe(SIGNING_ALGORITHMS.length);
  });
});

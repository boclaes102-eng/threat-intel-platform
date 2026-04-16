import { describe, it, expect } from 'vitest';
import { extractCvssFromItem, extractAffectedProducts, type NvdCveItem } from '../../../src/services/nvd';

const mockItem: NvdCveItem = {
  cve: {
    id: 'CVE-2024-1234',
    published: '2024-01-15T00:00:00.000',
    lastModified: '2024-01-16T00:00:00.000',
    descriptions: [{ lang: 'en', value: 'A test vulnerability' }],
    metrics: {
      cvssMetricV31: [
        {
          cvssData: {
            baseScore: 9.8,
            baseSeverity: 'CRITICAL',
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          },
        },
      ],
    },
    references: [{ url: 'https://example.com/advisory' }],
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              { criteria: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', vulnerable: true },
              { criteria: 'cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*', vulnerable: false },
            ],
          },
        ],
      },
    ],
  },
};

describe('extractCvssFromItem', () => {
  it('extracts CVSS v3.1 data correctly', () => {
    const result = extractCvssFromItem(mockItem);
    expect(result).not.toBeNull();
    expect(result!.score).toBe(9.8);
    expect(result!.severity).toBe('critical');
    expect(result!.vector).toContain('CVSS:3.1');
  });

  it('returns null when no metrics present', () => {
    const noMetrics: NvdCveItem = { ...mockItem, cve: { ...mockItem.cve, metrics: undefined } };
    expect(extractCvssFromItem(noMetrics)).toBeNull();
  });

  it('falls back to v3.0 when v3.1 is absent', () => {
    const v30Item: NvdCveItem = {
      ...mockItem,
      cve: {
        ...mockItem.cve,
        metrics: {
          cvssMetricV30: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.0/...' } }],
        },
      },
    };
    const result = extractCvssFromItem(v30Item);
    expect(result!.score).toBe(7.5);
  });
});

describe('extractAffectedProducts', () => {
  it('extracts only vulnerable CPE entries', () => {
    const products = extractAffectedProducts(mockItem);
    expect(products).toHaveLength(1);
    expect(products[0]).toContain('cpe:2.3:a:vendor:product:1.0');
  });

  it('returns empty array when no configurations', () => {
    const noConfig: NvdCveItem = { ...mockItem, cve: { ...mockItem.cve, configurations: [] } };
    expect(extractAffectedProducts(noConfig)).toHaveLength(0);
  });

  it('deduplicates CPE entries', () => {
    const dup: NvdCveItem = {
      ...mockItem,
      cve: {
        ...mockItem.cve,
        configurations: [
          { nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:v:p:1.0:*', vulnerable: true }] }] },
          { nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:v:p:1.0:*', vulnerable: true }] }] },
        ],
      },
    };
    expect(extractAffectedProducts(dup)).toHaveLength(1);
  });
});

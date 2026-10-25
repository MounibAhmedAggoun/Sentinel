import { describe, expect, it } from 'vitest';
import { domainAncestors, registrableDomain } from './domain.js';

describe('registrableDomain', () => {
  it('returns the domain itself when it has no subdomain', () => {
    expect(registrableDomain('example.com')).toBe('example.com');
  });

  it('strips one subdomain level', () => {
    expect(registrableDomain('www.example.com')).toBe('example.com');
  });

  it('strips multiple subdomain levels', () => {
    expect(registrableDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('handles multi-part public suffixes like .co.uk', () => {
    expect(registrableDomain('mail.example.co.uk')).toBe('example.co.uk');
  });

  it('returns null for a bare IP', () => {
    expect(registrableDomain('93.184.216.34')).toBeNull();
  });
});

describe('domainAncestors', () => {
  it('returns just the domain for a bare registrable domain', () => {
    expect(domainAncestors('example.com')).toEqual(['example.com']);
  });

  it('walks up from a subdomain to the registrable domain', () => {
    expect(domainAncestors('www.example.com')).toEqual(['www.example.com', 'example.com']);
  });

  it('walks up through every intermediate label', () => {
    expect(domainAncestors('a.b.c.example.com')).toEqual([
      'a.b.c.example.com',
      'b.c.example.com',
      'c.example.com',
      'example.com',
    ]);
  });

  it('handles multi-part public suffixes correctly', () => {
    expect(domainAncestors('deep.mail.example.co.uk')).toEqual([
      'deep.mail.example.co.uk',
      'mail.example.co.uk',
      'example.co.uk',
    ]);
  });

  it('falls back to just the hostname for something tldts cannot parse', () => {
    expect(domainAncestors('93.184.216.34')).toEqual(['93.184.216.34']);
  });
});

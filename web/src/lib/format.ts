import type { Decision, Origin, Scope } from './types';

export function duration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 172800) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

/** "5m ago" / "in 3h" */
export function relative(t: string | null | undefined, now = Date.now()): string {
  if (!t) return '–';
  const d = (Date.parse(t) - now) / 1000;
  return d >= 0 ? `in ${duration(d)}` : `${duration(-d)} ago`;
}

/** Remaining ban time. */
export function remaining(t: string | null, now = Date.now()): string {
  return t === null ? 'permanent' : `${duration((Date.parse(t) - now) / 1000)} left`;
}

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
export function dateTime(t: string | null | undefined): string {
  return t ? dtf.format(new Date(t)) : '–';
}

export function scope(s: Scope): string {
  switch (s.type) {
    case 'global':
      return 'global';
    case 'group':
      return `group ${s.value}`;
    case 'agents':
      return `agent ${s.value.join(', ')}`;
  }
}

export function origin(o: Origin): string {
  return `${o.type}:${o.value}`;
}

export function kind(d: Decision): string {
  return d.kind.kind;
}

/** Single addresses are shown without "/32" or "/128". */
export function target(t: string): string {
  return t.includes(':') ? t.replace(/\/128$/, '') : t.replace(/\/32$/, '');
}

export function number(n: number): string {
  return n.toLocaleString();
}

/** "AS64500 · DE" (short) for lists; empty without data */
export function geoShort(g: import('./types').GeoInfo | null | undefined): string {
  if (!g) return '';
  return [g.asn != null ? `AS${g.asn}` : '', g.country ?? ''].filter(Boolean).join(' · ');
}

/** "AS64500 Example Hosting · Germany (DE)" */
export function geoLong(g: import('./types').GeoInfo | null | undefined): string {
  if (!g) return '';
  const as = g.asn != null ? `AS${g.asn}${g.as_org ? ' ' + g.as_org : ''}` : (g.as_org ?? '');
  const c = g.country ? (g.country_name ? `${g.country_name} (${g.country})` : g.country) : '';
  return [as, c].filter(Boolean).join(' · ');
}

/** Whether a ban-list search term (lower case) matches this address's
 * ASN/country: "as:64500" / "as64500", "country:de", or text in the AS
 * name or country name. */
export function geoMatches(g: import('./types').GeoInfo | null | undefined, q: string): boolean {
  if (!g) return false;
  const m = /^as:?\s*(\d+)$/.exec(q);
  if (m) return g.asn === Number(m[1]);
  if (q.startsWith('country:')) return (g.country ?? '').toLowerCase() === q.slice(8).trim();
  return (
    (g.as_org ?? '').toLowerCase().includes(q) || (g.country_name ?? '').toLowerCase().includes(q)
  );
}

import type { Decision, Origin, Scope } from './types';

export function duration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 172800) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

/** 1536 → "1.5 KiB" */
export function bytes(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i === 0 ? n : n.toFixed(1)} ${units[i]}`;
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


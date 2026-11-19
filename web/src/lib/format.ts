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

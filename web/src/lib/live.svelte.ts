// Server-sent events from /api/v1/events. Pages register a callback that
// reloads their data; it runs (debounced) for every new decision and after
// every (re)connect, when events may have been missed.
import { session } from './session.svelte';
import type { Decision } from './types';

type Listener = (d: Decision | null) => void;

const listeners = new Set<Listener>();
let source: EventSource | null = null;
let connected = $state(false);

function emit(d: Decision | null) {
  for (const l of listeners) l(d);
}

export function liveConnected(): boolean {
  return connected;
}

export function startLive(): void {
  if (source) return;
  source = new EventSource('/api/v1/events');
  source.addEventListener('hello', () => {
    connected = true;
    emit(null);
  });
  source.addEventListener('decision', (e) => emit(JSON.parse((e as MessageEvent).data)));
  source.addEventListener('resync', () => emit(null));
  source.addEventListener('logout', () => {
    stopLive();
    session.me = null;
    session.expired = true;
  });
  source.onerror = () => {
    connected = false;
  };
}

export function stopLive(): void {
  source?.close();
  source = null;
  connected = false;
}

/** Calls `reload` on changes, at most every `ms`; returns the unsubscribe. */
export function onChange(reload: (d: Decision | null) => void, ms = 400): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let last: Decision | null = null;
  const l: Listener = (d) => {
    last = d;
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      reload(last);
    }, ms);
  };
  listeners.add(l);
  return () => {
    listeners.delete(l);
    if (timer) clearTimeout(timer);
  };
}

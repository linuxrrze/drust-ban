import { session } from './session.svelte';
import type { Me } from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && session.me?.csrf_token) headers['x-csrf-token'] = session.me.csrf_token;
  let r: Response;
  try {
    r = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'controller not reachable');
  }
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    if (r.status === 401 && session.me && path !== '/session') {
      session.me = null;
      session.expired = true;
    }
    throw new ApiError(r.status, data?.error ?? `${r.status} ${r.statusText}`);
  }
  return data as T;
}

export const get = <T>(path: string) => api<T>('GET', path);
export const post = <T>(path: string, body: unknown = {}) => api<T>('POST', path, body);

export async function checkSession(): Promise<void> {
  try {
    session.me = await get<Me>('/whoami');
  } catch {
    session.me = null;
  } finally {
    session.checked = true;
  }
}

export async function login(username: string, password: string): Promise<void> {
  session.me = await api<Me>('POST', '/session', { username, password });
  session.expired = false;
}

export async function logout(): Promise<void> {
  try {
    await api('DELETE', '/session');
  } finally {
    session.me = null;
  }
}

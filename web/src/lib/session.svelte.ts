// Who is logged in. The session cookie is HttpOnly; the CSRF token lives
// only in memory and is fetched again (whoami) after a reload.
import type { Me, Role } from './types';

const order: Role[] = ['viewer', 'operator', 'admin'];

export const session = $state<{ me: Me | null; checked: boolean; expired: boolean }>({
  me: null,
  checked: false,
  expired: false,
});

export function can(role: Role): boolean {
  return session.me !== null && order.indexOf(session.me.role) >= order.indexOf(role);
}

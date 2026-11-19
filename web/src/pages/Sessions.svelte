<script lang="ts">
  import { ApiError, api, get } from '../lib/api';
  import { dateTime, relative } from '../lib/format';
  import { session } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { SessionInfo } from '../lib/types';
  import Dialog from '../components/Dialog.svelte';

  let sessions = $state<SessionInfo[]>([]);
  let loaded = $state(false);
  let error = $state('');
  let filter = $state('');
  let now = $state(Date.now());
  // what the confirmation dialog is about to end
  let pending = $state<{ kind: 'one'; s: SessionInfo } | { kind: 'user'; user: string } | { kind: 'all' } | null>(null);
  let confirmOpen = $state(false);
  let busy = $state(false);

  async function load() {
    try {
      sessions = (await get<{ sessions: SessionInfo[] }>('/sessions')).sessions;
      error = '';
      now = Date.now();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loaded = true;
    }
  }

  $effect(() => {
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  });

  const shown = $derived(
    sessions.filter((s) => !filter.trim() || s.user.toLowerCase().includes(filter.trim().toLowerCase())),
  );
  const users = $derived(new Set(sessions.map((s) => s.user)).size);

  /** "Firefox 132 on Linux"-style summary; the full string is in the tooltip. */
  function browser(ua: string | null): string {
    if (!ua) return '–';
    const name =
      /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl\//.test(ua) ? 'curl' : null;
    const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : null;
    if (!name) return ua.slice(0, 40);
    return os ? `${name} on ${os}` : name;
  }

  function ask(p: NonNullable<typeof pending>) {
    pending = p;
    confirmOpen = true;
  }

  const endsOwn = $derived(
    pending !== null &&
      (pending.kind === 'all' ||
        (pending.kind === 'one' && pending.s.current) ||
        (pending.kind === 'user' && sessions.some((s) => s.current && s.user === (pending as { user: string }).user))),
  );

  async function confirm() {
    if (!pending) return;
    busy = true;
    try {
      let r: { ended: number };
      if (pending.kind === 'one') r = await api('DELETE', `/sessions/${encodeURIComponent(pending.s.id)}`);
      else if (pending.kind === 'user') r = await api('DELETE', `/sessions?user=${encodeURIComponent(pending.user)}`);
      else r = await api('DELETE', '/sessions?all=true');
      confirmOpen = false;
      if (endsOwn) {
        session.me = null; // our own session is gone: back to the login page
        return;
      }
      notify(r.ended === 1 ? 'Session ended' : `${r.ended} sessions ended`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    } finally {
      busy = false;
    }
  }

  const title = $derived(
    pending?.kind === 'one'
      ? `End ${pending.s.user}'s session?`
      : pending?.kind === 'user'
        ? `End all sessions of ${pending.user}?`
        : 'End all sessions?',
  );
</script>

<div class="page-head">
  <h1>Sessions</h1>
  <span class="faint">{sessions.length} signed in · {users} {users === 1 ? 'user' : 'users'}</span>
  <span class="spacer"></span>
  <input type="search" placeholder="Filter by user" bind:value={filter} aria-label="Filter by user" />
  {#if sessions.length}
    <button class="danger" onclick={() => ask({ kind: 'all' })}>End all…</button>
  {/if}
</div>

{#if error}<div class="error-box">{error}</div>{/if}

<div class="card">
  {#if loaded && shown.length === 0}
    <div class="empty">{sessions.length ? 'No session matches the filter.' : 'Nobody is signed in to the web UI.'}</div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>User</th><th>Role</th><th>Sign-in</th><th>Signed in</th><th>Last active</th>
            <th>Ends</th><th>From</th><th>Browser</th><th></th>
          </tr>
        </thead>
        <tbody>
          {#each shown as s (s.id)}
            <tr class:selected={s.current}>
              <td>
                {s.user}
                {#if s.current}<span class="pill plain">this session</span>{/if}
              </td>
              <td>{s.role ?? '–'}</td>
              <td>{s.method === 'oidc' ? 'single sign-on' : 'password'}</td>
              <td title={dateTime(s.created_at)}>{relative(s.created_at, now)}</td>
              <td title={dateTime(s.last_used_at)}>{relative(s.last_used_at, now)}</td>
              <td title={dateTime(s.expires_at)}>{relative(s.expires_at, now)}</td>
              <td class="mono small">{s.remote_addr ?? '–'}</td>
              <td title={s.user_agent ?? ''}>{browser(s.user_agent)}</td>
              <td class="actions">
                <button class="link" onclick={() => ask({ kind: 'one', s })}>End</button>
                {#if sessions.filter((x) => x.user === s.user).length > 1}
                  · <button class="link" onclick={() => ask({ kind: 'user', user: s.user })}>all of {s.user}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<p class="faint small">
  Ending a session signs that browser out within seconds. It does not lock anybody out: to do that,
  delete the local user (<code>df2b-controller user delete</code>) or disable them at the identity
  provider. API tokens are not sessions; they are managed with <code>df2b-controller api-token</code>.
</p>

<Dialog bind:open={confirmOpen} title={title} onsubmit={confirm}>
  <p class="muted confirm-text">
    {#if pending?.kind === 'all'}
      Everybody is signed out of the web UI, including you. Use this after a suspected compromise.
    {:else if pending?.kind === 'one'}
      The browser at {pending.s.remote_addr ?? 'an unknown address'} ({browser(pending.s.user_agent)}) is signed out.
    {:else if pending?.kind === 'user'}
      Every browser where {pending.user} is signed in is signed out.
    {/if}
    {#if endsOwn && pending?.kind !== 'all'}<strong> This includes your own session.</strong>{/if}
  </p>
  <div class="actions">
    <button type="button" onclick={() => (confirmOpen = false)}>Cancel</button>
    <button type="submit" class="danger solid" disabled={busy}>End</button>
  </div>
</Dialog>

<style>
  .actions { white-space: nowrap; }
  td .pill { margin-left: 6px; }
  p { margin: 12px 0 0; }
  p.confirm-text { margin: 0; }
</style>

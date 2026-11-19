<script lang="ts">
  import { ApiError, api, get, post } from '../lib/api';
  import { dateTime, relative } from '../lib/format';
  import { generatePassword, MIN_PASSWORD } from '../lib/password';
  import { href } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { AuthMethods, Role, UserInfo } from '../lib/types';
  import Dialog from '../components/Dialog.svelte';

  const roles: { id: Role; text: string }[] = [
    { id: 'viewer', text: 'viewer – read only' },
    { id: 'operator', text: 'operator – also ban and unban' },
    { id: 'admin', text: 'admin – everything' },
  ];

  let users = $state<UserInfo[]>([]);
  let passwordLogin = $state(true);
  let methods = $state<AuthMethods | null>(null);
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());

  // create / reset dialogs
  let createOpen = $state(false);
  let resetOpen = $state(false);
  let deleteOpen = $state(false);
  let target = $state<UserInfo | null>(null);
  let name = $state('');
  let role = $state<Role>('viewer');
  let password = $state('');
  let temporary = $state(true);
  let formError = $state('');
  let busy = $state(false);
  let copied = $state(false);

  async function load() {
    try {
      const r = await get<{ users: UserInfo[]; password_login: boolean }>('/users');
      users = r.users;
      passwordLogin = r.password_login;
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
    get<AuthMethods>('/auth-methods').then((m) => (methods = m)).catch(() => {});
  });

  function openCreate() {
    name = '';
    role = 'viewer';
    password = generatePassword();
    temporary = true;
    formError = '';
    copied = false;
    createOpen = true;
  }

  function openReset(u: UserInfo) {
    target = u;
    password = generatePassword();
    temporary = true;
    formError = '';
    copied = false;
    resetOpen = true;
  }

  async function copy() {
    await navigator.clipboard.writeText(password);
    copied = true;
  }

  async function run(f: () => Promise<void>) {
    busy = true;
    formError = '';
    try {
      await f();
      load();
    } catch (e) {
      formError = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  const create = () =>
    run(async () => {
      await post('/users', { name: name.trim(), role, password, temporary });
      createOpen = false;
      notify(`User ${name.trim()} created — hand over the password securely`);
    });

  const reset = () =>
    run(async () => {
      if (!target) return;
      const r = await post<{ sessions_ended: number }>(`/users/${encodeURIComponent(target.name)}/password`, {
        password,
        temporary,
      });
      resetOpen = false;
      notify(`Password of ${target.name} reset${r.sessions_ended ? `; ${r.sessions_ended} session(s) signed out` : ''}`);
    });

  const remove = () =>
    run(async () => {
      if (!target) return;
      await api('DELETE', `/users/${encodeURIComponent(target.name)}`);
      deleteOpen = false;
      notify(`User ${target.name} deleted`);
    });

  async function changeRole(u: UserInfo, r: Role) {
    if (r === u.role) return;
    try {
      await api('PATCH', `/users/${encodeURIComponent(u.name)}`, { role: r });
      notify(`${u.name} is now ${r}`);
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    }
    load();
  }

  const self = (u: UserInfo) => u.name === session.me?.name;
</script>

<div class="page-head">
  <h1>Users</h1>
  <span class="faint">local accounts</span>
  <span class="spacer"></span>
  <button class="primary" onclick={openCreate}>Add user…</button>
</div>

{#if methods?.oidc}
  <p class="info">
    Single sign-on ({methods.oidc.name}) is enabled: those users and their roles are managed at
    the identity provider and do not appear here.
    {#if !passwordLogin}<strong>Password sign-in is disabled</strong>, so the accounts below can only
      be used once it is enabled again.{/if}
  </p>
{/if}

{#if error}<div class="error-box">{error}</div>{/if}

<div class="card">
  {#if loaded && users.length === 0}
    <div class="empty">No local users.</div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>User</th><th>Role</th><th>Password</th><th>Created</th><th class="num">Sessions</th><th></th></tr>
        </thead>
        <tbody>
          {#each users as u (u.name)}
            <tr>
              <td>{u.name}{#if self(u)} <span class="pill plain">you</span>{/if}</td>
              <td>
                {#if self(u)}
                  {u.role}
                {:else}
                  <select value={u.role} aria-label="Role of {u.name}" onchange={(e) => changeRole(u, (e.currentTarget as HTMLSelectElement).value as Role)}>
                    {#each roles as r (r.id)}<option value={r.id}>{r.id}</option>{/each}
                  </select>
                {/if}
              </td>
              <td>
                {#if u.must_change_password}
                  <span class="pill warn">temporary</span>
                {:else}
                  <span class="muted" title={dateTime(u.password_changed_at)}>changed {relative(u.password_changed_at, now)}</span>
                {/if}
              </td>
              <td class="muted" title={dateTime(u.created_at)}>{relative(u.created_at, now)}</td>
              <td class="num">
                {#if u.sessions}<a href={href('sessions')}>{u.sessions}</a>{:else}<span class="faint">0</span>{/if}
              </td>
              <td class="actions">
                {#if self(u)}
                  <a href={href('account')}>Change your password</a>
                {:else}
                  <button class="link" onclick={() => openReset(u)}>Reset password</button>
                  · <button class="link danger-link" onclick={() => { target = u; formError = ''; deleteOpen = true; }}>Delete</button>
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
  Changes take effect immediately; a password reset or deletion signs the user out. You cannot
  lower your own role or delete yourself — another admin can, or <code>df2b-controller user</code>
  on the controller host.
</p>

{#snippet passwordField()}
  <label class="field">
    Password
    <div class="row">
      <input class="mono grow" bind:value={password} required minlength={MIN_PASSWORD} autocomplete="off" spellcheck="false" />
      <button type="button" onclick={() => { password = generatePassword(); copied = false; }}>Generate</button>
      <button type="button" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
    </div>
    <span class="hint">Hand it over through a separate, secure channel. At least {MIN_PASSWORD} characters.</span>
  </label>
  <label class="check">
    <input type="checkbox" bind:checked={temporary} />
    Must be changed at the next sign-in (recommended)
  </label>
{/snippet}

<Dialog bind:open={createOpen} title="Add user" onsubmit={create}>
  <label class="field">
    User name
    <input bind:value={name} required maxlength="64" pattern="[A-Za-z0-9._@\-]+" autocomplete="off" />
    <span class="hint">Letters, digits, - _ . @. Shown in the audit log.</span>
  </label>
  <label class="field">
    Role
    <select bind:value={role}>
      {#each roles as r (r.id)}<option value={r.id}>{r.text}</option>{/each}
    </select>
  </label>
  {@render passwordField()}
  {#if formError}<div class="error-box">{formError}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (createOpen = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Add user</button>
  </div>
</Dialog>

<Dialog bind:open={resetOpen} title="Reset password of {target?.name}" onsubmit={reset}>
  {@render passwordField()}
  <p class="muted confirm-text">{target?.name} is signed out everywhere.</p>
  {#if formError}<div class="error-box">{formError}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (resetOpen = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Set password</button>
  </div>
</Dialog>

<Dialog bind:open={deleteOpen} title="Delete {target?.name}?" onsubmit={remove}>
  <p class="muted confirm-text">
    The account is removed and its sessions end. Bans and audit entries made by {target?.name} stay.
  </p>
  {#if formError}<div class="error-box">{formError}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (deleteOpen = false)}>Cancel</button>
    <button type="submit" class="danger solid" disabled={busy}>Delete</button>
  </div>
</Dialog>

<style>
  .info { background: var(--surface-2); border-radius: 8px; padding: 10px 14px; margin: 0 0 16px; color: var(--text-2); }
  .actions { white-space: nowrap; }
  .danger-link { color: var(--bad); }
  .grow { flex: 1; }
  .check { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  p { margin: 12px 0 0; }
  p.confirm-text { margin: 0; }
  td select { padding: 2px 6px; }
</style>

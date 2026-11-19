<script lang="ts">
  import { ApiError, api, get, post } from '../lib/api';
  import { dateTime, relative } from '../lib/format';
  import { notify } from '../lib/toast.svelte';
  import type { Role, TokenInfo } from '../lib/types';
  import Dialog from '../components/Dialog.svelte';

  let tokens = $state<TokenInfo[]>([]);
  let fingerprint = $state<string | null>(null);
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());

  let createOpen = $state(false);
  let revokeOpen = $state(false);
  let target = $state<TokenInfo | null>(null);
  let name = $state('');
  let role = $state<Role>('viewer');
  let ttl = $state('90d');
  let formError = $state('');
  let busy = $state(false);
  // shown once, right after creating
  let created = $state<{ token: string; name: string; role: Role; expires_at: string | null } | null>(null);
  let copied = $state('');

  async function load() {
    try {
      const r = await get<{ tokens: TokenInfo[]; ca_fingerprint: string | null }>('/api-tokens');
      tokens = r.tokens;
      fingerprint = r.ca_fingerprint;
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
  });

  function openCreate() {
    name = '';
    role = 'viewer';
    ttl = '90d';
    formError = '';
    created = null;
    copied = '';
    createOpen = true;
  }

  async function submit() {
    if (created) {
      createOpen = false;
      return;
    }
    busy = true;
    formError = '';
    try {
      created = await post('/api-tokens', { name: name.trim(), role, ttl });
      load();
    } catch (e) {
      formError = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  // the token disappears from memory when the dialog closes
  $effect(() => {
    if (!createOpen) created = null;
  });

  const config = $derived(
    created
      ? [
          `controller = "${location.origin}"`,
          `token = "${created.token}"`,
          ...(fingerprint
            ? [`ca_fingerprint = "${fingerprint}"   # pins the controller's internal CA`]
            : []),
        ].join('\n')
      : '',
  );

  async function copy(what: 'token' | 'config') {
    if (!created) return;
    await navigator.clipboard.writeText(what === 'token' ? created.token : config + '\n');
    copied = what;
  }

  async function revoke() {
    if (!target) return;
    busy = true;
    try {
      await api('DELETE', `/api-tokens/${encodeURIComponent(target.name)}`);
      revokeOpen = false;
      notify(`Token ${target.name} revoked`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    } finally {
      busy = false;
    }
  }

  function expiry(t: TokenInfo): { text: string; cls: string } {
    if (t.expired) return { text: 'expired', cls: 'bad' };
    if (!t.expires_at) return { text: 'never expires', cls: 'plain' };
    const left = Date.parse(t.expires_at) - now;
    return { text: `expires ${relative(t.expires_at, now)}`, cls: left < 14 * 86400e3 ? 'warn' : 'plain' };
  }
</script>

<div class="page-head">
  <h1>API tokens</h1>
  <span class="faint">for df2bctl, scripts and monitoring</span>
  <span class="spacer"></span>
  <button class="primary" onclick={openCreate}>Create token…</button>
</div>

{#if error}<div class="error-box">{error}</div>{/if}

<div class="card">
  {#if loaded && tokens.length === 0}
    <div class="empty">No API tokens yet.</div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Role</th><th>Expiry</th><th>Last used</th><th>Created</th><th></th></tr>
        </thead>
        <tbody>
          {#each tokens as t (t.name)}
            {@const ex = expiry(t)}
            <tr>
              <td class="mono">{t.name}</td>
              <td>{t.role}</td>
              <td><span class="pill {ex.cls}" title={dateTime(t.expires_at)}>{ex.text}</span></td>
              <td class="muted" title={dateTime(t.last_used_at)}>{t.last_used_at ? relative(t.last_used_at, now) : 'not since restart'}</td>
              <td class="muted" title={dateTime(t.created_at)}>{relative(t.created_at, now)} by {t.created_by ?? 'controller host'}</td>
              <td><button class="link danger-link" onclick={() => { target = t; revokeOpen = true; }}>Revoke</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<p class="faint small">
  Only a hash of each token is stored; a lost token cannot be shown again, create a new one.
  Revoking takes effect immediately. Tokens cannot create other tokens.
</p>

<Dialog bind:open={createOpen} title={created ? `Token ${created.name}` : 'Create API token'} onsubmit={submit}>
  {#if !created}
    <label class="field">
      Name
      <input bind:value={name} required maxlength="64" pattern="[A-Za-z0-9._@\-]+" placeholder="e.g. monitoring or alice-laptop" autocomplete="off" />
      <span class="hint">Shown in the audit log for everything done with this token.</span>
    </label>
    <label class="field">
      Role
      <select bind:value={role}>
        <option value="viewer">viewer – read only (monitoring)</option>
        <option value="operator">operator – also ban and unban</option>
        <option value="admin">admin – everything</option>
      </select>
    </label>
    <label class="field">
      Expires after
      <select bind:value={ttl}>
        <option value="30d">30 days</option>
        <option value="90d">90 days</option>
        <option value="365d">1 year</option>
        <option value="never">never</option>
      </select>
      {#if ttl === 'never'}<span class="hint warn-text">Tokens that never expire are easy to forget; prefer an expiry.</span>{/if}
    </label>
    {#if formError}<div class="error-box">{formError}</div>{/if}
    <div class="actions">
      <button type="button" onclick={() => (createOpen = false)}>Cancel</button>
      <button type="submit" class="primary" disabled={busy}>Create</button>
    </div>
  {:else}
    <p class="notice confirm-text">Copy the token now — it is shown only once.</p>
    <code class="secret">{created.token}</code>
    <div class="field">
      df2bctl configuration (<span class="mono">~/.config/df2b/df2bctl.toml</span>, mode 0600)
      <pre class="secret">{config}</pre>
    </div>
    <div class="actions">
      <button type="button" onclick={() => copy('token')}>{copied === 'token' ? 'Copied' : 'Copy token'}</button>
      <button type="button" onclick={() => copy('config')}>{copied === 'config' ? 'Copied' : 'Copy configuration'}</button>
      <button type="submit" class="primary">Done</button>
    </div>
  {/if}
</Dialog>

<Dialog bind:open={revokeOpen} title="Revoke {target?.name}?" onsubmit={revoke}>
  <p class="muted confirm-text">
    Every program using this token is refused from now on{target?.current ? ', including the one you are using' : ''}.
  </p>
  <div class="actions">
    <button type="button" onclick={() => (revokeOpen = false)}>Cancel</button>
    <button type="submit" class="danger solid" disabled={busy}>Revoke</button>
  </div>
</Dialog>

<style>
  .danger-link { color: var(--bad); }
  p { margin: 12px 0 0; }
  p.confirm-text { margin: 0; }
  .notice { background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 8px 12px; }
  .secret {
    display: block; padding: 10px 12px; border-radius: 8px; background: var(--surface-2);
    word-break: break-all; white-space: pre-wrap; user-select: all; margin: 0;
    font-family: var(--mono); font-size: 12.5px; font-weight: 400;
  }
  .warn-text { color: var(--warn); }
</style>

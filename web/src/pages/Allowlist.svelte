<script lang="ts">
  import { ApiError, api, get } from '../lib/api';
  import { dateTime, relative, target as fmtTarget } from '../lib/format';
  import { onChange } from '../lib/live.svelte';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { AllowEntry } from '../lib/types';
  import AllowDialog from '../components/AllowDialog.svelte';
  import Dialog from '../components/Dialog.svelte';

  let entries = $state<AllowEntry[]>([]);
  let coverage = $state<{ connected: number; current: number } | null>(null);
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());
  let addOpen = $state(false);
  let removeOpen = $state(false);
  let target = $state<AllowEntry | null>(null);
  let busy = $state(false);

  async function load() {
    try {
      const r = await get<{ entries: AllowEntry[]; agents: { connected: number; current: number } }>('/allowlist');
      entries = r.entries;
      coverage = r.agents;
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
    const off = onChange(load, 1000);
    // agents confirm a new list with their next heartbeat (10 s)
    const t = setInterval(load, 10_000);
    return () => {
      off();
      clearInterval(t);
    };
  });

  async function remove() {
    if (!target) return;
    busy = true;
    try {
      await api('DELETE', `/allowlist?net=${encodeURIComponent(target.net)}`);
      removeOpen = false;
      notify(`${target.net} removed from the allowlist`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    } finally {
      busy = false;
    }
  }
</script>

<div class="page-head">
  <h1>Allowlist</h1>
  <span class="faint">networks the controller never bans</span>
  <span class="spacer"></span>
  {#if can('admin')}<button class="primary" onclick={() => (addOpen = true)}>Add…</button>{/if}
</div>

{#if error}<div class="error-box">{error}</div>{/if}

{#if coverage && coverage.connected > 0}
  <p class="coverage">
    {#if coverage.current === coverage.connected}
      <span class="pill good">all {coverage.connected} connected agents use this list</span>
    {:else}
      <span class="pill warn">{coverage.current} of {coverage.connected} connected agents use this list</span>
      <span class="faint small">Agents confirm changes within about 10 seconds; older agent versions do not receive it.</span>
    {/if}
  </p>
{/if}

<div class="card">
  {#if loaded && entries.length === 0}
    <div class="empty">
      The allowlist is empty. Add your own networks (offices, monitoring, partners) so they can never
      be locked out.
    </div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Network</th><th>Comment</th><th>Added</th><th>Expires</th><th class="num">Overlapping bans</th>{#if can('admin')}<th></th>{/if}</tr>
        </thead>
        <tbody>
          {#each entries as e (e.net)}
            <tr>
              <td class="mono"><a href={href('ip', e.net)}>{fmtTarget(e.net)}</a></td>
              <td>{e.comment || '–'}</td>
              <td class="muted">
                {#if e.source === 'command line'}
                  <span class="pill plain" title="--allow on the controller's command line">command line</span>
                {:else}
                  <span title={dateTime(e.created_at)}>{relative(e.created_at, now)} by {e.created_by}</span>
                {/if}
              </td>
              <td>
                {#if e.expires_at}
                  <span class="pill warn" title={dateTime(e.expires_at)}>{relative(e.expires_at, now)}</span>
                {:else}<span class="faint">never</span>{/if}
              </td>
              <td class="num">
                {#if e.active_bans}
                  <span class="pill warn" title="Active bans overlapping this network (made before it was added, or not lifted)">{e.active_bans}</span>
                {:else}<span class="faint">0</span>{/if}
              </td>
              {#if can('admin')}
                <td>
                  {#if e.source === 'api'}
                    <button class="link danger-link" onclick={() => { target = e; removeOpen = true; }}>Remove</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<p class="faint small">
  Connected agents receive this list at once: they stop banning these networks, lift their local
  bans on them, and keep the list across restarts even while the controller is unreachable. The
  controller also refuses manual bans and agent reports that overlap it. Each agent's own
  allowlist from its configuration applies as well. Entries from <code>--allow</code> can only be
  changed on the controller's command line.
</p>

<AllowDialog bind:open={addOpen} ondone={load} />

<Dialog bind:open={removeOpen} title="Remove {target?.net}?" onsubmit={remove}>
  <p class="muted confirm-text">
    The network can be banned again from now on. Nothing is banned right away.
  </p>
  <div class="actions">
    <button type="button" onclick={() => (removeOpen = false)}>Cancel</button>
    <button type="submit" class="danger solid" disabled={busy}>Remove</button>
  </div>
</Dialog>

<style>
  .danger-link { color: var(--bad); }
  .coverage { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 0 0 12px; }
  p { margin: 12px 0 0; }
  p.confirm-text { margin: 0; }
</style>

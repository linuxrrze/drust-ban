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
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());
  let addOpen = $state(false);
  let removeOpen = $state(false);
  let target = $state<AllowEntry | null>(null);
  let busy = $state(false);

  async function load() {
    try {
      entries = (await get<{ entries: AllowEntry[] }>('/allowlist')).entries;
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
    return onChange(load, 1000);
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
          <tr><th>Network</th><th>Comment</th><th>Added</th><th class="num">Overlapping bans</th>{#if can('admin')}<th></th>{/if}</tr>
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
  The controller refuses manual bans and ignores agents' ban reports that overlap these networks.
  Agents also have their own allowlist in their configuration, which applies to local bans before
  anything reaches the controller; add critical networks there too. Entries from
  <code>--allow</code> can only be changed on the controller's command line.
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
  p { margin: 12px 0 0; }
  p.confirm-text { margin: 0; }
</style>

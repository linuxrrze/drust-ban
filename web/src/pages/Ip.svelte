<script lang="ts">
  import { ApiError, get } from '../lib/api';
  import { dateTime, origin, remaining, scope, target } from '../lib/format';
  import { onChange } from '../lib/live.svelte';
  import { go, href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import type { Decision, History } from '../lib/types';
  import BanDialog from '../components/BanDialog.svelte';
  import UnbanDialog from '../components/UnbanDialog.svelte';
  import AllowDialog from '../components/AllowDialog.svelte';

  let { addr = '' }: { addr?: string } = $props();

  let input = $state('');
  let data = $state<History | null>(null);
  let error = $state('');
  let banOpen = $state(false);
  let unbanOpen = $state(false);
  let allowOpen = $state(false);

  async function load() {
    if (!addr) {
      data = null;
      return;
    }
    try {
      data = await get<History>(`/history?target=${encodeURIComponent(addr)}`);
      error = '';
    } catch (e) {
      data = null;
      error = e instanceof ApiError ? e.message : String(e);
    }
  }

  $effect(() => {
    input = addr;
    load();
    return onChange(load);
  });

  function search(e: SubmitEvent) {
    e.preventDefault();
    if (input.trim()) go('ip', input.trim());
  }

  const byId = $derived(new Map((data?.history ?? []).map((d) => [d.id, d])));
  function revoked(d: Decision): Decision | undefined {
    return 'revokes' in d.kind ? byId.get(d.kind.revokes) : undefined;
  }
</script>

<div class="page-head">
  <h1>Address lookup</h1>
  <span class="spacer"></span>
  <form class="row" onsubmit={search}>
    <input type="search" class="mono" placeholder="203.0.113.7 or 2001:db8::/64" bind:value={input} aria-label="Address or prefix" />
    <button type="submit">Look up</button>
  </form>
</div>

{#if error}<div class="error-box">{error}</div>{/if}

{#if !addr}
  <div class="card empty">Enter an address or prefix to see its bans and decision history.</div>
{:else if data}
  <div class="card summary">
    <div>
      <div class="mono big">{target(data.target)}</div>
      <div class="row">
        {#if data.active.length}
          <span class="pill bad">banned</span>
          <span class="muted">by {data.active.length} active {data.active.length === 1 ? 'ban' : 'bans'}</span>
        {:else}
          <span class="pill good">not banned</span>
        {/if}
        {#if data.allowlisted}<a class="pill plain" href={href('allowlist')}>on the controller allowlist</a>{/if}
      </div>
    </div>
    <span class="spacer"></span>
    {#if can('operator')}
      {#if data.active.length}
        <button class="danger" onclick={() => (unbanOpen = true)}>Unban…</button>
      {/if}
      {#if !data.allowlisted}
        <button class="primary" onclick={() => (banOpen = true)}>Ban…</button>
      {/if}
    {/if}
    {#if can('admin') && !data.allowlisted}
      <button onclick={() => (allowOpen = true)}>Allowlist…</button>
    {/if}
  </div>

  {#if data.active.length}
    <div class="card">
      <h2>Active bans</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Target</th><th>Jail</th><th>Scope</th><th>Origin</th><th>Reason</th><th>Expires</th></tr></thead>
          <tbody>
            {#each data.active as d (d.id)}
              <tr>
                <td class="mono">{target(d.target)}</td>
                <td>{d.jail ?? 'manual'}</td>
                <td>{scope(d.scope)}</td>
                <td class="muted">{origin(d.origin)}</td>
                <td class="muted">{d.reason}</td>
                <td>{remaining(d.expires_at)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}

  <div class="card">
    <h2>History</h2>
    {#if data.history.length === 0}
      <div class="faint small">No decisions about {target(data.target)} or overlapping prefixes.</div>
    {:else}
      <ol class="timeline">
        {#each data.history as d (d.id)}
          {@const r = revoked(d)}
          <li class={d.kind.kind}>
            <div class="when faint small">{dateTime(d.created_at)} · #{d.seq}</div>
            <div>
              <strong>{d.kind.kind === 'ban' ? 'Banned' : 'Unbanned'}</strong>
              <a class="mono" href={href('ip', d.target)}>{target(d.target)}</a>
              {#if d.kind.kind === 'ban'}
                for {d.expires_at ? dateTime(d.expires_at).replace(/^/, 'until ') : 'ever'}
              {:else if r}
                (lifts ban #{r.seq})
              {/if}
              · {scope(d.scope)}
            </div>
            <div class="muted small">
              {origin(d.origin)}{d.jail ? ` · jail ${d.jail}` : ''}{d.reason ? ` · ${d.reason}` : ''}
            </div>
          </li>
        {/each}
      </ol>
      {#if data.history.length >= 200}<div class="faint small">Showing the newest 200 decisions.</div>{/if}
    {/if}
    <p class="faint small note">
      Log lines and per-host observations are not collected centrally yet; the history shows
      decisions only.
    </p>
  </div>

  <BanDialog bind:open={banOpen} initialTarget={addr} ondone={load} />
  <UnbanDialog bind:open={unbanOpen} targets={[addr]} ondone={load} />
  <AllowDialog bind:open={allowOpen} initialNet={addr} ondone={load} />
{/if}

<style>
  .card { margin-bottom: 16px; }
  .summary { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .big { font-size: 20px; font-weight: 600; margin-bottom: 6px; }
  .spacer { flex: 1; }
  .timeline { list-style: none; margin: 0; padding: 0 0 0 18px; border-left: 2px solid var(--border); display: grid; gap: 14px; }
  .timeline li { position: relative; }
  .timeline li::before {
    content: ''; position: absolute; left: -24px; top: 4px; width: 10px; height: 10px;
    border-radius: 50%; background: var(--surface); border: 2px solid var(--text-3);
  }
  .timeline li.ban::before { border-color: var(--bad); }
  .timeline li.unban::before { border-color: var(--good); }
  .note { margin: 16px 0 0; }
</style>

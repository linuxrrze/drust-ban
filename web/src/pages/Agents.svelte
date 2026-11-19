<script lang="ts">
  import { ApiError, get, post } from '../lib/api';
  import { dateTime, relative } from '../lib/format';
  import { go, href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { Agent, Status } from '../lib/types';
  import Dialog from '../components/Dialog.svelte';
  import EnrollDialog from '../components/EnrollDialog.svelte';

  let { selected = null }: { selected?: string | null } = $props();

  let agents = $state<Agent[]>([]);
  let allowVersion = $state('');
  let loaded = $state(false);
  let error = $state('');
  let filter = $state('');
  let now = $state(Date.now());
  let enrollOpen = $state(false);
  let revokeOpen = $state(false);

  async function load() {
    try {
      const [a, s] = await Promise.all([get<{ agents: Agent[] }>('/agents'), get<Status>('/status')]);
      agents = a.agents;
      allowVersion = s.allowlist_version;
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
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  });

  const shown = $derived(
    agents.filter((a) => {
      const f = filter.trim().toLowerCase();
      return !f || a.id.toLowerCase().includes(f) || a.group.toLowerCase().includes(f) || a.hostname.toLowerCase().includes(f);
    }),
  );
  const current = $derived(agents.find((a) => a.id === selected) ?? null);

  type State = { text: string; cls: string };
  function agentState(a: Agent): State {
    if (a.revoked) return { text: 'revoked', cls: 'plain' };
    if (!a.connected) return { text: 'offline', cls: 'bad' };
    if (!a.status.firewall_healthy) return { text: 'firewall error', cls: 'bad' };
    if (Date.parse(a.cert_not_after) - now < 3 * 86400e3) return { text: 'cert expiring', cls: 'warn' };
    return { text: 'online', cls: 'good' };
  }

  async function revoke() {
    if (!current) return;
    try {
      await post(`/agents/${encodeURIComponent(current.id)}/revoke`);
      notify(`Revoked ${current.id}`);
      revokeOpen = false;
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : String(e), 'error');
    }
  }

  function skew(ms: number): string {
    const s = Math.abs(ms) / 1000;
    return s < 1 ? `${ms} ms` : `${s.toFixed(1)} s ${ms > 0 ? 'behind' : 'ahead'}`;
  }
</script>

<div class="page-head">
  <h1>Agents</h1>
  <span class="faint">{agents.filter((a) => a.connected).length} of {agents.filter((a) => !a.revoked).length} online</span>
  <span class="spacer"></span>
  <input type="search" placeholder="Filter by name or group" bind:value={filter} aria-label="Filter agents" />
  {#if can('admin')}
    <button class="primary" onclick={() => (enrollOpen = true)}>Enroll agent</button>
  {/if}
</div>

{#if error}<div class="error-box">{error}</div>{/if}

<div class="layout" class:with-detail={current !== null}>
  <div class="card">
    {#if loaded && agents.length === 0}
      <div class="empty">
        No agents enrolled yet.
        {#if can('admin')}<button class="link" onclick={() => (enrollOpen = true)}>Create an enrollment token</button>{/if}
      </div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Agent</th><th>Group</th><th>State</th><th>Last seen</th>
              <th class="num">Bans</th><th>Version</th><th>Certificate</th>
            </tr>
          </thead>
          <tbody>
            {#each shown as a (a.id)}
              {@const st = agentState(a)}
              <tr class:selected={a.id === selected} class="clickable" onclick={() => go('agents', a.id)}>
                <td><a href={href('agents', a.id)}>{a.id}</a></td>
                <td>{a.group}</td>
                <td><span class="pill {st.cls}">{st.text}</span></td>
                <td class="muted">{relative(a.status.last_seen, now)}</td>
                <td class="num">{a.status.active_bans.toLocaleString()}</td>
                <td class="muted">{a.status.agent_version || '–'}</td>
                <td class="muted">expires {relative(a.cert_not_after, now)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  {#if current}
    {@const st = agentState(current)}
    <aside class="card detail">
      <div class="row">
        <h2 class="title">{current.id}</h2>
        <span class="spacer"></span>
        <a href={href('agents')} aria-label="Close details">✕</a>
      </div>
      <span class="pill {st.cls}">{st.text}</span>
      <dl>
        <dt>Host name</dt><dd>{current.hostname}</dd>
        <dt>Group</dt><dd>{current.group}</dd>
        <dt>Enrolled</dt><dd>{dateTime(current.enrolled_at)}</dd>
        <dt>Last heartbeat</dt><dd>{current.status.last_seen ? dateTime(current.status.last_seen) : 'never (since controller start)'}</dd>
        <dt>Version</dt><dd>{current.status.agent_version || '–'}</dd>
        <dt>Active bans</dt><dd>{current.status.active_bans.toLocaleString()}</dd>
        <dt>Firewall</dt>
        <dd>
          {current.status.firewall_backend || '–'}
          {#if current.status.last_seen}
            <span class="pill {current.status.firewall_healthy ? 'good' : 'bad'}">{current.status.firewall_healthy ? 'healthy' : 'error'}</span>
          {/if}
        </dd>
        <dt>Clock skew</dt><dd>{skew(current.status.clock_skew_ms)}</dd>
        <dt>Applied decisions</dt><dd>up to #{current.status.last_applied_seq}</dd>
        <dt>Allowlist</dt>
        <dd>
          {#if !current.status.last_seen}–
          {:else if current.status.allowlist_version === allowVersion}<span class="pill good">current</span>
          {:else if !current.status.allowlist_version}<span class="pill plain" title="This agent version does not report it">unknown</span>
          {:else}<span class="pill warn">outdated</span>{/if}
        </dd>
        <dt>Certificate</dt><dd>valid until {dateTime(current.cert_not_after)}<br /><span class="faint small">renewed automatically</span></dd>
        <dt>Serial</dt><dd class="mono small">{current.serials[0] ?? '–'}</dd>
      </dl>
      {#if can('admin') && !current.revoked}
        <button class="danger" onclick={() => (revokeOpen = true)}>Revoke agent…</button>
      {/if}
      {#if current.revoked}
        <p class="faint small">Revoked agents cannot connect. To bring the host back, enroll it again with a new token.</p>
      {/if}
    </aside>
  {/if}
</div>

<EnrollDialog bind:open={enrollOpen} />

<Dialog bind:open={revokeOpen} title="Revoke {current?.id}?" onsubmit={revoke}>
  <p class="muted">
    The agent's connections are closed within seconds and it can no longer connect. Bans it already
    applied stay on the host until they expire. This cannot be undone; the host has to be enrolled
    again.
  </p>
  <div class="actions">
    <button type="button" onclick={() => (revokeOpen = false)}>Cancel</button>
    <button type="submit" class="danger solid">Revoke</button>
  </div>
</Dialog>

<style>
  .layout { display: grid; gap: 16px; }
  .layout.with-detail { grid-template-columns: minmax(0, 1fr) 340px; align-items: start; }
  @media (max-width: 1000px) { .layout.with-detail { grid-template-columns: 1fr; } }
  .clickable { cursor: pointer; }
  .detail { display: grid; gap: 12px; position: sticky; top: 16px; }
  .detail .title { margin: 0; color: var(--text); font-size: 15px; word-break: break-all; }
  .detail .pill { justify-self: start; }
  .spacer { flex: 1; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 14px; margin: 0; }
  dt { color: var(--text-2); }
  dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
  .detail button { justify-self: start; }
  p { margin: 0; }
</style>

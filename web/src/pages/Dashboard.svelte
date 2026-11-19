<script lang="ts">
  import { get } from '../lib/api';
  import { origin, relative, target } from '../lib/format';
  import { onChange } from '../lib/live.svelte';
  import { href } from '../lib/router.svelte';
  import type { Agent, Decision, Stats, Status } from '../lib/types';
  import HourlyChart from '../components/HourlyChart.svelte';
  import TopList from '../components/TopList.svelte';

  let status = $state<Status | null>(null);
  let stats = $state<Stats | null>(null);
  let agents = $state<Agent[]>([]);
  let recent = $state<Decision[]>([]);
  let error = $state('');
  let now = $state(Date.now());

  async function load() {
    try {
      const [s, st, a, d] = await Promise.all([
        get<Status>('/status'),
        get<Stats>('/stats'),
        get<{ agents: Agent[] }>('/agents'),
        get<{ decisions: Decision[] }>('/decisions'),
      ]);
      status = s;
      stats = st;
      agents = a.agents;
      recent = d.decisions.slice(-8).reverse();
      error = '';
      now = Date.now();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    load();
    const off = onChange(load, 1000);
    const t = setInterval(load, 30_000);
    return () => {
      off();
      clearInterval(t);
    };
  });

  const problems = $derived(
    agents.filter((a) => !a.revoked && (!a.connected || !a.status.firewall_healthy || certSoon(a))),
  );

  function certSoon(a: Agent): boolean {
    return Date.parse(a.cert_not_after) - now < 3 * 86400e3;
  }
</script>

<div class="page-head"><h1>Overview</h1></div>

{#if error}<div class="error-box">{error}</div>{/if}

{#if status && stats}
  <div class="tiles">
    <a class="card tile" href={href('agents')}>
      <span class="label">Agents online</span>
      <span class="value">{status.agents.connected}<span class="of"> / {status.agents.total - status.agents.revoked}</span></span>
      {#if problems.length}
        <span class="pill warn">{problems.length} need attention</span>
      {:else}
        <span class="pill good">all healthy</span>
      {/if}
    </a>
    <a class="card tile" href={href('bans')}>
      <span class="label">Active bans</span>
      <span class="value">{stats.active.total.toLocaleString()}</span>
      <span class="faint small">{stats.active.permanent} permanent</span>
    </a>
    <div class="card tile">
      <span class="label">IPv4 / IPv6</span>
      <span class="value">{stats.active.ipv4.toLocaleString()}<span class="of"> / {stats.active.ipv6.toLocaleString()}</span></span>
      <span class="faint small">active bans by family</span>
    </div>
    <div class="card tile">
      <span class="label">Last 24 hours</span>
      <span class="value">{stats.bans_per_hour.slice(-24).reduce((s, h) => s + h.count, 0).toLocaleString()}</span>
      <span class="faint small">new bans</span>
    </div>
  </div>

  <div class="card chart-card">
    <h2>New bans per hour · last 48 hours</h2>
    <HourlyChart data={stats.bans_per_hour} />
  </div>

  <div class="three">
    <TopList title="Top jails" items={stats.top_jails} />
    <TopList title="Top networks (/16, /32)" items={stats.top_prefixes} link={(k) => href('ip', k)} />
    <TopList title="Banned by" items={stats.top_origins} />
  </div>

  <div class="two">
    <div class="card">
      <h2>Latest bans</h2>
      {#if recent.length === 0}
        <div class="faint small">no active bans</div>
      {:else}
        <div class="table-wrap">
          <table>
            <tbody>
              {#each recent as d (d.id)}
                <tr>
                  <td class="mono"><a href={href('ip', d.target)}>{target(d.target)}</a></td>
                  <td>{d.jail ?? 'manual'}</td>
                  <td class="muted">{origin(d.origin)}</td>
                  <td class="num faint">{relative(d.created_at, now)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
    <div class="card">
      <h2>Agents needing attention</h2>
      {#if problems.length === 0}
        <div class="faint small">All agents are connected, their firewalls are healthy and no certificate expires within 3 days.</div>
      {:else}
        <div class="table-wrap">
          <table>
            <tbody>
              {#each problems as a (a.id)}
                <tr>
                  <td><a href={href('agents', a.id)}>{a.id}</a></td>
                  <td>
                    {#if !a.connected}<span class="pill bad">offline · seen {relative(a.status.last_seen, now)}</span>
                    {:else if !a.status.firewall_healthy}<span class="pill bad">firewall error</span>
                    {:else}<span class="pill warn">certificate expires {relative(a.cert_not_after, now)}</span>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </div>

  <p class="faint small foot">
    Controller {status.version} · local bans propagate: {status.propagate} · decision log #{status.last_seq}
    {#if status.allowlist.length}· never banned: <span class="mono">{status.allowlist.join(', ')}</span>{/if}
  </p>
{:else if !error}
  <div class="empty">Loading…</div>
{/if}

<style>
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(180px, 100%), 1fr)); gap: 16px; margin-bottom: 16px; }
  .tile { display: grid; gap: 4px; color: inherit; text-decoration: none; }
  a.tile:hover { text-decoration: none; border-color: var(--accent); }
  .label { color: var(--text-2); font-weight: 550; font-size: 13px; }
  .value { font-size: 28px; font-weight: 650; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
  .of { font-size: 18px; color: var(--text-3); font-weight: 500; }
  .tile .pill { justify-self: start; }
  .chart-card { margin-bottom: 16px; }
  .three { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(240px, 100%), 1fr)); gap: 16px; margin-bottom: 16px; }
  .two { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(340px, 100%), 1fr)); gap: 16px; }
  .foot { margin-top: 16px; }
</style>

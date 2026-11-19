<script lang="ts">
  import { get } from '../lib/api';
  import { dateTime } from '../lib/format';
  import type { AuditEntry } from '../lib/types';

  let entries = $state<AuditEntry[]>([]);
  let error = $state('');
  let more = $state(true);
  let loading = $state(false);
  const PAGE = 100;

  async function load(reset = false) {
    loading = true;
    try {
      const before = !reset && entries.length ? `&before=${entries[entries.length - 1].seq}` : '';
      const r = await get<{ entries: AuditEntry[] }>(`/audit?limit=${PAGE}${before}`);
      entries = reset ? r.entries : [...entries, ...r.entries];
      more = r.entries.length === PAGE;
      error = '';
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    load(true);
  });

  const labels: Record<string, string> = {
    ban: 'ban',
    unban: 'unban',
    'agent.enroll': 'agent enrolled',
    'agent.revoke': 'agent revoked',
    'enroll_token.create': 'enrollment token created',
    'session.login': 'logged in',
    'session.end': 'session ended',
    'user.create': 'user created',
    'policy.propagate': 'ban propagation changed',
    'jail.policy': 'jail settings changed',
    'jail.policy_remove': 'jail settings removed',
    'agent.group': 'agent moved',
    'allowlist.add': 'allowlisted',
    'allowlist.remove': 'removed from allowlist',
    'token.create': 'API token created',
    'token.revoke': 'API token revoked',
    'user.update': 'role changed',
    'user.password_reset': 'password reset',
    'user.password_change': 'own password changed',
    'user.delete': 'user deleted',
    'session.end_user': "user's sessions ended",
    'session.end_all': 'all sessions ended',
    'session.backchannel_logout': 'logged out by provider',
  };

  function details(e: AuditEntry): string {
    return Object.entries(e.details)
      .filter(([, v]) => v !== null && v !== undefined)
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join('  ');
  }
</script>

<div class="page-head">
  <h1>Audit log</h1>
  <span class="spacer"></span>
  <button onclick={() => load(true)} disabled={loading}>Refresh</button>
</div>

{#if error}<div class="error-box">{error}</div>{/if}

<div class="card">
  {#if entries.length === 0 && !loading}
    <div class="empty">Nothing recorded yet.</div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th class="num">#</th><th>Time</th><th>Who</th><th>Action</th><th>From</th><th>Details</th></tr></thead>
        <tbody>
          {#each entries as e (e.seq)}
            <tr>
              <td class="num faint">{e.seq}</td>
              <td class="nowrap">{dateTime(e.time)}</td>
              <td>{e.actor}</td>
              <td><span class="pill plain">{labels[e.action] ?? e.action}</span></td>
              <td class="mono small muted">{e.remote_addr ?? '–'}</td>
              <td class="mono small details">{details(e)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if more}
      <div class="more"><button onclick={() => load()} disabled={loading}>Load older entries</button></div>
    {/if}
  {/if}
</div>

<p class="faint small">
  Changes made with <code>df2b-controller</code> on the controller host (API tokens, users, revocations)
  are not recorded here yet.
</p>

<style>
  .nowrap { white-space: nowrap; }
  .details { overflow-wrap: anywhere; min-width: 240px; }
  .more { padding-top: 12px; }
  p { margin-top: 12px; }
</style>

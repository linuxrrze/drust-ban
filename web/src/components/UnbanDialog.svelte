<script lang="ts">
  import { ApiError, post } from '../lib/api';
  import { dateTime, target as fmtTarget } from '../lib/format';
  import { can } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    targets,
    ondone,
  }: { open: boolean; targets: string[]; ondone?: () => void } = $props();

  let reason = $state('');
  let allowFor = $state('');
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      error = '';
      reason = '';
      allowFor = '';
    }
  });

  async function submit() {
    busy = true;
    error = '';
    let done = 0;
    let until: string | null = null;
    const failed: string[] = [];
    for (const t of targets) {
      try {
        const r = await post<{ allowed_until: string | null }>('/unban', {
          target: t,
          reason: reason.trim() || null,
          allow_for: allowFor || null,
        });
        until = r.allowed_until ?? until;
        done++;
      } catch (e) {
        // 404: already lifted (e.g. by an earlier unban of a covering prefix)
        if (!(e instanceof ApiError && e.status === 404)) failed.push(`${t}: ${e instanceof Error ? e.message : e}`);
      }
    }
    busy = false;
    if (failed.length) {
      error = failed.join('\n');
    } else {
      const what = done === 1 ? `Unbanned ${fmtTarget(targets[0])}` : `Unbanned ${done} entries`;
      notify(until ? `${what}; not banned again until ${dateTime(until)}` : what);
      open = false;
    }
    ondone?.();
  }
</script>

<Dialog bind:open title={targets.length === 1 ? `Unban ${fmtTarget(targets[0])}` : `Unban ${targets.length} entries`} onsubmit={submit}>
  <p class="muted">
    Lifts every active ban overlapping {targets.length === 1 ? 'this target' : 'these targets'}, in
    the scope each ban was made, including local bans on the agents. Offense history is kept, so
    repeat offenders are still escalated.
  </p>
  {#if targets.length > 1}
    <ul class="list mono">
      {#each targets as t (t)}<li>{fmtTarget(t)}</li>{/each}
    </ul>
  {/if}
  <label class="field">
    Reason
    <input bind:value={reason} placeholder="manual unban" />
  </label>
  <label class="field">
    Then don't ban it again for
    <select bind:value={allowFor}>
      <option value="">— (may be banned again right away)</option>
      <option value="1h">1 hour</option>
      <option value="24h">24 hours</option>
      <option value="7d">7 days</option>
      {#if can('admin')}<option value="30d">30 days</option>{/if}
    </select>
    <span class="hint">
      For false positives: a temporary allowlist entry, so the next failed login does not ban it
      again. Single addresses and networks up to /24 (IPv4) or /48 (IPv6).
    </span>
  </label>
  {#if error}<div class="error-box pre">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="danger solid" disabled={busy}>{busy ? 'Unbanning…' : 'Unban'}</button>
  </div>
</Dialog>

<style>
  p { margin: 0; }
  .list { margin: 0; padding-left: 20px; max-height: 160px; overflow: auto; }
  .pre { white-space: pre-line; }
</style>

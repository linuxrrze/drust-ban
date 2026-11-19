<script lang="ts">
  import { ApiError, api } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import type { JailDefinition } from '../lib/types';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    def,
    groups,
    filters,
    ondone,
  }: {
    open: boolean;
    def: JailDefinition | null;
    groups: string[];
    filters: string[];
    ondone?: () => void;
  } = $props();

  type Src = { type: 'file' | 'journald'; lines: string; start_at_end: boolean; start: string };

  let name = $state('');
  let scope = $state('');
  let newGroup = $state('');
  let filter = $state('');
  let sources = $state<Src[]>([]);
  let enabled = $state(true);
  let maxretry = $state('5');
  let findtime = $state('10m');
  let bantime = $state('1h');
  let factor = $state('1');
  let maxBantime = $state('');
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      error = '';
      name = def?.name ?? '';
      scope = def?.group ?? '';
      newGroup = '';
      filter = def?.filter ?? '';
      sources = (def?.sources ?? [{ type: 'file', paths: [], start_at_end: true }]).map((s) =>
        s.type === 'file'
          ? { type: 'file', lines: s.paths.join('\n'), start_at_end: s.start_at_end, start: '' }
          : { type: 'journald', lines: s.matches.join('\n'), start_at_end: false, start: s.start ?? '' },
      );
      enabled = def?.enabled ?? true;
      maxretry = String(def?.maxretry ?? 5);
      findtime = def?.findtime ?? '10m';
      bantime = def?.bantime ?? '1h';
      factor = String(def?.bantime_factor ?? 1);
      maxBantime = def?.max_bantime ?? '';
    }
  });

  const group = $derived(scope === '+' ? newGroup.trim() : scope);
  const lines = (t: string) => t.split('\n').map((l) => l.trim()).filter(Boolean);

  async function save() {
    busy = true;
    error = '';
    try {
      const body = {
        group: group || null,
        filter: filter.trim(),
        sources: sources.map((s) =>
          s.type === 'file'
            ? { type: 'file', paths: lines(s.lines), start_at_end: s.start_at_end }
            : { type: 'journald', matches: lines(s.lines), start: s.start.trim() || null },
        ),
        enabled,
        maxretry: Number(maxretry),
        findtime: findtime.trim(),
        bantime: bantime.trim(),
        bantime_factor: Number(factor),
        max_bantime: maxBantime.trim() || null,
      };
      const r = await api<{ filter_is_central: boolean }>(
        'PUT',
        `/jail-definitions/${encodeURIComponent(name.trim())}`,
        body,
      );
      notify(
        `Jail ${name.trim()} defined for ${group ? `group ${group}` : 'all agents'}` +
          (r.filter_is_central ? '' : ` (agents need the filter file ${filter.trim()}.toml)`),
      );
      open = false;
      ondone?.();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title={def ? `Jail ${def.name}` : 'Define a jail'} onsubmit={save}>
  <div class="two">
    <label class="field">
      Name
      <input bind:value={name} required pattern="[A-Za-z0-9._\-]+" maxlength="64" disabled={!!def} />
    </label>
    <label class="field">
      For
      <select bind:value={scope} disabled={!!def}>
        <option value="">all agents</option>
        {#each groups as g (g)}<option value={g}>group {g}</option>{/each}
        <option value="+">another group…</option>
      </select>
    </label>
  </div>
  {#if scope === '+'}
    <label class="field">Group <input bind:value={newGroup} required pattern="[A-Za-z0-9._\-]+" /></label>
  {/if}
  <label class="field">
    Filter
    <input bind:value={filter} list="central-filters" required pattern="[A-Za-z0-9._\-]+" placeholder="central filter, or one the agents have" />
    <datalist id="central-filters">{#each filters as f (f)}<option value={f}></option>{/each}</datalist>
  </label>

  <fieldset>
    <legend>Log sources</legend>
    {#each sources as s, i (i)}
      <div class="source">
        <div class="row">
          <select bind:value={s.type} aria-label="Source type">
            <option value="file">files</option>
            <option value="journald">systemd journal</option>
          </select>
          <span class="spacer"></span>
          {#if sources.length > 1}<button type="button" class="link" onclick={() => sources.splice(i, 1)}>remove</button>{/if}
        </div>
        <textarea class="mono" rows="2" bind:value={s.lines} required
          placeholder={s.type === 'file' ? '/var/log/app/auth.log (one path per line)' : '_SYSTEMD_UNIT=app.service (one match per line, + for OR)'}></textarea>
        {#if s.type === 'file'}
          <label class="check"><input type="checkbox" bind:checked={s.start_at_end} /> only new lines (skip what the file already contains)</label>
        {:else}
          <label class="check">start <input bind:value={s.start} placeholder="tail, head or e.g. 10m" /></label>
        {/if}
      </div>
    {/each}
    <button type="button" class="link" onclick={() => sources.push({ type: 'file', lines: '', start_at_end: true, start: '' })}>+ add a source</button>
    <p class="faint small">Agents read central file sources only below their <code>central_paths</code> (default /var/log).</p>
  </fieldset>

  <div class="limits">
    <label class="field">Failures <input bind:value={maxretry} required inputmode="numeric" /></label>
    <label class="field">within <input bind:value={findtime} required /></label>
    <label class="field">First ban <input bind:value={bantime} required /></label>
    <label class="field">Escalation × <input bind:value={factor} required inputmode="decimal" /></label>
    <label class="field">Longest ban <input bind:value={maxBantime} placeholder="none" /></label>
  </div>
  <label class="check"><input type="checkbox" bind:checked={enabled} /> enabled</label>
  {#if error}<div class="error-box">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Save</button>
  </div>
</Dialog>

<style>
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  fieldset { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; margin: 0; display: grid; gap: 10px; }
  legend { font-weight: 550; font-size: 13px; padding: 0 4px; }
  .source { display: grid; gap: 6px; padding-bottom: 8px; border-bottom: 1px dashed var(--border); }
  textarea { width: 100%; resize: vertical; font-size: 12.5px; }
  .check { display: flex; gap: 8px; align-items: center; font-size: 13px; }
  .limits { display: grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr)); gap: 10px; }
  .spacer { flex: 1; }
  p { margin: 0; }
</style>

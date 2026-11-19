<script lang="ts">
  import { ApiError, api, post } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import type { CentralFilter } from '../lib/types';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    filter,
    ondone,
  }: { open: boolean; filter: CentralFilter | null; ondone?: () => void } = $props();

  const template = `# Lines must contain one of these to be looked at (fast prefilter).
literals = ["login failed"]
# Each pattern must contain <HOST> exactly once.
failregex = [
  'login failed for \\S+ from <HOST>',
]
ignoreregex = []
`;

  let name = $state('');
  let toml = $state('');
  let sample = $state('');
  let result = $state<{ lines: number; matched: number; matches: { line: number; ip: string }[] } | null>(null);
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      name = filter?.name ?? '';
      toml = filter?.toml ?? template;
      sample = '';
      result = null;
      error = '';
    }
  });

  async function test() {
    error = '';
    result = null;
    try {
      result = await post('/filters/test', { toml, lines: sample.split('\n').filter((l) => l.trim()) });
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    }
  }

  async function save() {
    busy = true;
    error = '';
    try {
      await api('PUT', `/filters/${encodeURIComponent(name.trim())}`, { toml });
      notify(`Filter ${name.trim()} saved`);
      open = false;
      ondone?.();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title={filter ? `Filter ${filter.name}` : 'New filter'} onsubmit={save}>
  {#if !filter}
    <label class="field">
      Name
      <input bind:value={name} required pattern="[A-Za-z0-9._\-]+" maxlength="64" placeholder="e.g. app-auth" />
    </label>
  {/if}
  <label class="field">
    Definition <span class="hint">same format as the agents' filter files</span>
    <textarea class="mono code" bind:value={toml} rows="9" spellcheck="false" required></textarea>
  </label>
  <label class="field">
    Try it <span class="hint">paste log lines, one per line</span>
    <textarea class="mono code" bind:value={sample} rows="4" spellcheck="false"></textarea>
  </label>
  <div class="row">
    <button type="button" onclick={test} disabled={!sample.trim()}>Test</button>
    {#if result}
      <span class="muted">{result.matched} of {result.lines} lines match</span>
    {/if}
  </div>
  {#if result && result.matches.length}
    <ul class="matches mono small">
      {#each result.matches.slice(0, 20) as m (m.line)}<li>line {m.line}: {m.ip}</li>{/each}
    </ul>
  {/if}
  {#if error}<div class="error-box pre">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Save</button>
  </div>
</Dialog>

<style>
  .code { width: 100%; resize: vertical; font-size: 12.5px; }
  .matches { margin: 0; padding-left: 18px; max-height: 120px; overflow: auto; }
  .pre { white-space: pre-wrap; }
</style>

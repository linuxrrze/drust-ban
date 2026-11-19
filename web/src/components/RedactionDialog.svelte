<script lang="ts">
  import { ApiError, api } from '../lib/api';
  import { notify } from '../lib/toast.svelte';
  import type { RedactPreset, RedactRule } from '../lib/types';
  import Dialog from './Dialog.svelte';

  let {
    open = $bindable(false),
    rule,
    presets,
    defaultReplace,
    ondone,
  }: {
    open: boolean;
    rule: RedactRule | null;
    presets: RedactPreset[];
    defaultReplace: string;
    ondone?: () => void;
  } = $props();

  const exampleLines = [
    'sshd[4711]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2',
    '203.0.113.7 - - "GET /login?user=ann@example.org&token=abc123 HTTP/1.1" 401 512',
  ].join('\n');

  let name = $state('');
  let pattern = $state('');
  let replace = $state('');
  let enabled = $state(true);
  let lines = $state(exampleLines);
  let preview = $state<{ line: string; stable: boolean }[]>([]);
  let previewError = $state('');
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    if (open) {
      error = '';
      name = rule?.name ?? '';
      pattern = rule?.pattern ?? '';
      replace = rule?.replace ?? defaultReplace;
      enabled = rule?.enabled ?? true;
    }
  });

  function usePreset(p: RedactPreset) {
    if (!rule) name = p.name;
    pattern = p.pattern;
    replace = p.replace;
  }

  // live preview: the current rules with this one in its place
  $effect(() => {
    if (!open) return;
    const body = {
      pattern: pattern.trim() ? pattern : undefined,
      replace,
      name: rule?.name ?? (name.trim() || undefined),
      lines: lines.split('\n').filter((l) => l.trim()).slice(0, 20),
    };
    const t = setTimeout(async () => {
      try {
        preview = (await api<{ results: { line: string; stable: boolean }[] }>('POST', '/redaction/test', body)).results;
        previewError = '';
      } catch (e) {
        preview = [];
        previewError = e instanceof ApiError ? e.message : String(e);
      }
    }, 250);
    return () => clearTimeout(t);
  });

  const unstable = $derived(preview.some((p) => !p.stable));

  async function save() {
    busy = true;
    error = '';
    try {
      const r = await api<{ lines_redacted: number }>('PUT', `/redaction/${encodeURIComponent(name.trim())}`, {
        pattern,
        replace,
        enabled,
      });
      const n = r.lines_redacted;
      notify(`Rule ${name.trim()} saved${n ? ` · ${n} kept ${n === 1 ? 'line' : 'lines'} redacted` : ''}`);
      open = false;
      ondone?.();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open title={rule ? `Redaction rule ${rule.name}` : 'New redaction rule'} onsubmit={save}>
  {#if !rule}
    <div class="presets">
      <span class="muted small">Start from</span>
      {#each presets as p (p.name)}
        <button type="button" class="chip" title={p.description} onclick={() => usePreset(p)}>{p.name}</button>
      {/each}
    </div>
    <label class="field">
      Name <input bind:value={name} required pattern="[A-Za-z0-9._\-]+" maxlength="64" placeholder="e.g. ssh-user" />
    </label>
  {/if}
  <label class="field">
    Pattern <span class="hint">regular expression (Rust syntax; <code>(?i)</code> ignores case)</span>
    <input class="mono" bind:value={pattern} required maxlength="500" spellcheck="false" autocomplete="off" />
  </label>
  <div class="grid">
    <label class="field">
      Replace with <span class="hint"><code>$1</code>, <code>{'${name}'}</code>: groups; <code>$$</code>: a $</span>
      <input class="mono" bind:value={replace} spellcheck="false" autocomplete="off" />
    </label>
    <label class="check"><input type="checkbox" bind:checked={enabled} /> Enabled</label>
  </div>
  <label class="field">
    Try it on <span class="hint">one line each; all rules apply, this one in its place</span>
    <textarea class="mono code" bind:value={lines} rows="3" spellcheck="false"></textarea>
  </label>
  {#if previewError}
    <div class="error-box">{previewError}</div>
  {:else if preview.length}
    <ul class="preview" aria-label="Preview">
      {#each preview as p, i (i)}<li><code>{p.line}</code></li>{/each}
    </ul>
    {#if unstable}
      <p class="warn-text small">
        Applying the rules again changes these lines further. Kept lines are redacted again whenever the
        rules change, so make the replacement something the pattern does not match.
      </p>
    {/if}
  {/if}
  <p class="faint small">
    Agents apply the enabled rules before sending a line; the controller applies them again as lines
    arrive and rewrites the lines it already keeps (the original text is gone). Agents with
    <code>central_redaction = false</code> do not accept them: for those, use <code>[[redact]]</code> in
    their <code>agent.toml</code>, or <code>send_samples = false</code>.
  </p>
  {#if error}<div class="error-box">{error}</div>{/if}
  <div class="actions">
    <button type="button" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>Save</button>
  </div>
</Dialog>

<style>
  .presets { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
  .chip { padding: 2px 10px; border-radius: 999px; font-size: 12.5px; }
  .grid { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: end; }
  .check { display: flex; gap: 6px; align-items: center; padding-bottom: 8px; }
  .preview { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
  .preview code {
    display: block; padding: 6px 8px; border-radius: 6px; background: var(--surface-2);
    white-space: pre-wrap; overflow-wrap: anywhere;
  }
  .warn-text { color: var(--warn); margin: 0; }
  p { margin: 0; }
</style>

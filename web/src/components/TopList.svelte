<script lang="ts">
  import type { Count } from '../lib/types';

  let {
    title,
    items,
    link,
  }: { title: string; items: Count[]; link?: (key: string) => string } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.count)));
</script>

<div class="card">
  <h2>{title}</h2>
  {#if items.length === 0}
    <div class="faint small">nothing banned</div>
  {:else}
    <ul>
      {#each items as it (it.key)}
        <li>
          <span class="key mono">
            {#if link}<a href={link(it.key)}>{it.key}</a>{:else}{it.key}{/if}
          </span>
          <span class="num">{it.count.toLocaleString()}</span>
          <svg class="meter" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true">
            <rect class="track" width="100" height="4" rx="2" />
            <rect class="fill" width={Math.max(2, (it.count / max) * 100)} height="4" rx="2" />
          </svg>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
  li { display: grid; grid-template-columns: 1fr auto; gap: 3px 8px; }
  .key { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .num { font-variant-numeric: tabular-nums; color: var(--text-2); }
  .meter { grid-column: 1 / -1; width: 100%; height: 4px; display: block; }
  .track { fill: var(--surface-2); }
  .fill { fill: var(--series-1); }
</style>

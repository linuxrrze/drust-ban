<script lang="ts">
  // New bans per hour: one series, columns from a shared baseline. Only SVG
  // attributes are used (no inline styles: the CSP forbids them).
  let { data }: { data: { hour: string; count: number }[] } = $props();

  let width = $state(600);
  const height = 180;
  const pad = { top: 12, right: 8, bottom: 22, left: 36 };

  let hover = $state<number | null>(null);

  const max = $derived(Math.max(1, ...data.map((d) => d.count)));
  // 0 + up to three gridlines at round values
  const ticks = $derived.by(() => {
    const raw = max / 3;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = Math.max(1, [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? mag * 10);
    const out = [];
    for (let v = 0; v <= max + step * 0.001; v += step) out.push(v);
    if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
    return out;
  });
  const top = $derived(ticks[ticks.length - 1]);
  const plotW = $derived(Math.max(10, width - pad.left - pad.right));
  const plotH = height - pad.top - pad.bottom;
  const slot = $derived(plotW / Math.max(1, data.length));
  // ≤ 24px bars; at least a 2px surface gap between neighbours
  const barW = $derived(Math.max(1, Math.min(24, slot - 2)));
  const y = (v: number) => pad.top + plotH - (v / top) * plotH;

  /** Column with a 4px rounded data end, square at the baseline. */
  function bar(i: number, v: number): string {
    const x = pad.left + i * slot + (slot - barW) / 2;
    const h = (v / top) * plotH;
    const b = pad.top + plotH;
    const r = Math.min(4, barW / 2, h);
    return `M${x},${b} V${b - h + r} Q${x},${b - h} ${x + r},${b - h} H${x + barW - r} Q${x + barW},${b - h} ${x + barW},${b - h + r} V${b} Z`;
  }

  const hourFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
  const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  const label = (h: string) => hourFmt.format(new Date(h));

  const total = $derived(data.reduce((s, d) => s + d.count, 0));
  const tip = $derived.by(() => {
    if (hover === null || !data[hover]) return null;
    const d = data[hover];
    const start = new Date(d.hour);
    const text = `${dayFmt.format(start)}–${hourFmt.format(new Date(start.getTime() + 3600e3))}`;
    const value = `${d.count.toLocaleString()} new ban${d.count === 1 ? '' : 's'}`;
    const w = Math.max(text.length, value.length) * 6.6 + 20;
    const cx = pad.left + hover * slot + slot / 2;
    const x = Math.min(Math.max(cx - w / 2, 0), width - w);
    return { text, value, w, x, cx };
  });
</script>

<div class="chart" bind:clientWidth={width}>
  <svg {width} {height} role="img" aria-label="New bans per hour, last 48 hours, {total} in total">
    {#each ticks as t (t)}
      <line class="grid" x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} />
      <text class="axis" x={pad.left - 6} y={y(t) + 4} text-anchor="end">{t.toLocaleString()}</text>
    {/each}
    {#each data as d, i (d.hour)}
      {#if d.count > 0}
        <path class="bar" class:dim={hover !== null && hover !== i} d={bar(i, d.count)} />
      {/if}
      {#if i % 6 === 0}
        <text class="axis" x={pad.left + i * slot + slot / 2} y={height - 6} text-anchor="middle">{label(d.hour)}</text>
      {/if}
    {/each}
    <line class="base" x1={pad.left} x2={width - pad.right} y1={pad.top + plotH} y2={pad.top + plotH} />
    <!-- hit targets: the whole column, wider than the bar -->
    {#each data as d, i (d.hour)}
      <rect
        role="presentation"
        class="hit"
        x={pad.left + i * slot}
        y={pad.top}
        width={slot}
        height={plotH}
        onpointerenter={() => (hover = i)}
        onpointerleave={() => (hover = null)}
      />
    {/each}
    {#if tip}
      <line class="cross" x1={tip.cx} x2={tip.cx} y1={pad.top} y2={pad.top + plotH} />
      <g transform="translate({tip.x},{0})" class="tip">
        <rect width={tip.w} height="40" rx="6" />
        <text x="10" y="16" class="tip-label">{tip.text}</text>
        <text x="10" y="32" class="tip-value">{tip.value}</text>
      </g>
    {/if}
  </svg>
  <table class="sr-only">
    <caption>New bans per hour</caption>
    <thead><tr><th>Hour starting</th><th>New bans</th></tr></thead>
    <tbody>
      {#each data as d (d.hour)}<tr><td>{dayFmt.format(new Date(d.hour))}</td><td>{d.count}</td></tr>{/each}
    </tbody>
  </table>
</div>

<style>
  .chart { position: relative; width: 100%; }
  svg { display: block; overflow: visible; }
  .grid { stroke: var(--grid); stroke-width: 1; }
  .base { stroke: var(--text-3); stroke-width: 1; }
  .axis { fill: var(--text-3); font-size: 11px; font-variant-numeric: tabular-nums; }
  .bar { fill: var(--series-1); }
  .bar.dim { opacity: 0.45; }
  .hit { fill: transparent; }
  .cross { stroke: var(--text-3); stroke-width: 1; stroke-dasharray: 2 3; pointer-events: none; }
  .tip { pointer-events: none; }
  .tip rect { fill: var(--surface); stroke: var(--border); }
  .tip-label { fill: var(--text-2); font-size: 11px; }
  .tip-value { fill: var(--text); font-size: 12px; font-weight: 600; }
</style>

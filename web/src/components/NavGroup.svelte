<script lang="ts">
  // A group of nav links behind a button (disclosure pattern: ordinary
  // links in a panel, not an ARIA menu). On narrow screens the group is
  // shown inline under its label instead (see the media query).
  import { href } from '../lib/router.svelte';

  let {
    label,
    items,
    page,
    onnavigate,
  }: {
    label: string;
    items: { id: string; label: string }[];
    page: string;
    onnavigate?: () => void;
  } = $props();

  let open = $state(false);
  let root: HTMLElement;
  let button: HTMLButtonElement;
  const panelId = $derived(`navgroup-${label.toLowerCase().replace(/\W+/g, '-')}`);
  const active = $derived(items.some((i) => i.id === page));
  const current = $derived(items.find((i) => i.id === page));

  function close(refocus = false) {
    open = false;
    if (refocus) button.focus();
  }

  $effect(() => {
    if (!open) return;
    const onPointer = (e: PointerEvent) => {
      if (!root.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close(true);
      }
    };
    // leaving the group with Tab closes it as well
    const onFocus = (e: FocusEvent) => {
      if (e.target instanceof Node && !root.contains(e.target)) close();
    };
    window.addEventListener('pointerdown', onPointer);
    window.addEventListener('keydown', onKey);
    window.addEventListener('focusin', onFocus);
    return () => {
      window.removeEventListener('pointerdown', onPointer);
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('focusin', onFocus);
    };
  });
</script>

<div class="group" bind:this={root}>
  <button
    bind:this={button}
    class="toggle"
    class:active
    aria-expanded={open}
    aria-controls={panelId}
    onclick={() => (open = !open)}
  >
    {label}{#if current}<span class="current">: {current.label}</span>{/if}
    <svg class="chev" class:up={open} viewBox="0 0 12 12" width="12" height="12" aria-hidden="true">
      <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  </button>
  <span class="heading" aria-hidden="true">{label}</span>
  <div id={panelId} class="panel" class:open>
    {#each items as i (i.id)}
      <a
        href={href(i.id)}
        class:active={page === i.id}
        aria-current={page === i.id ? 'page' : undefined}
        onclick={() => {
          close();
          onnavigate?.();
        }}>{i.label}</a
      >
    {/each}
  </div>
</div>

<style>
  .group { position: relative; }
  .toggle {
    display: inline-flex; align-items: center; gap: 4px;
    border: none; background: none; color: var(--text-2);
    padding: 6px 10px; border-radius: 8px; font-weight: 550;
  }
  .toggle:hover { background: var(--surface-2); }
  .toggle.active { color: var(--text); background: var(--surface-2); }
  .current { font-weight: 450; }
  .chev { transition: transform 0.12s; }
  .chev.up { transform: rotate(180deg); }
  .heading { display: none; }
  .panel {
    display: none; position: absolute; top: calc(100% + 6px); left: 0; z-index: 20;
    min-width: 180px; padding: 6px; flex-direction: column; gap: 2px;
    background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
    box-shadow: 0 8px 28px rgb(0 0 0 / 0.14);
  }
  .panel.open { display: flex; }
  .panel a { color: var(--text-2); padding: 7px 10px; border-radius: 6px; font-weight: 550; }
  .panel a:hover { background: var(--surface-2); text-decoration: none; }
  .panel a.active { color: var(--text); background: var(--surface-2); }

  /* phones: the nav is a column; show the group inline under its label */
  @media (max-width: 760px) {
    .toggle { display: none; }
    .heading {
      display: block; padding: 10px 10px 2px; font-size: 12px; font-weight: 600;
      color: var(--text-3); text-transform: uppercase; letter-spacing: 0.04em;
    }
    .panel, .panel.open {
      display: flex; position: static; box-shadow: none; border: none;
      padding: 0; min-width: 0; background: none;
    }
    .panel a { padding: 6px 10px; }
  }
  @media (prefers-reduced-motion: reduce) {
    .chev { transition: none; }
  }
</style>

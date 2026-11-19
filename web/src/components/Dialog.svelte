<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    open = $bindable(false),
    title,
    children,
    onsubmit,
  }: {
    open: boolean;
    title: string;
    children: Snippet;
    onsubmit?: () => void | Promise<void>;
  } = $props();

  let el: HTMLDialogElement;

  $effect(() => {
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  });

  function submit(e: SubmitEvent) {
    e.preventDefault();
    onsubmit?.();
  }
</script>

<dialog bind:this={el} onclose={() => (open = false)} aria-label={title}>
  {#if open}
    <form onsubmit={submit}>
      <h1>{title}</h1>
      {@render children()}
    </form>
  {/if}
</dialog>

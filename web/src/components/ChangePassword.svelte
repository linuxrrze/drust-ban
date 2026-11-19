<script lang="ts">
  import { ApiError, api } from '../lib/api';
  import { MIN_PASSWORD } from '../lib/password';
  import { session } from '../lib/session.svelte';
  import { notify } from '../lib/toast.svelte';
  import type { Me } from '../lib/types';

  let { forced = false }: { forced?: boolean } = $props();

  let current = $state('');
  let next = $state('');
  let repeat = $state('');
  let error = $state('');
  let busy = $state(false);

  const problem = $derived(
    next.length > 0 && [...next].length < MIN_PASSWORD
      ? `At least ${MIN_PASSWORD} characters.`
      : repeat.length > 0 && repeat !== next
        ? 'The passwords differ.'
        : '',
  );

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (problem || next !== repeat) return;
    busy = true;
    error = '';
    try {
      // the controller replaces the session (new cookie and CSRF token)
      session.me = await api<Me>('POST', '/session/password', {
        current_password: current,
        new_password: next,
      });
      current = next = repeat = '';
      notify('Password changed; your other sessions have been signed out');
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<form class="pw" onsubmit={submit}>
  {#if forced}
    <p class="notice">
      An administrator set a temporary password for you. Choose your own to continue.
    </p>
  {/if}
  <label class="field">
    {forced ? 'Temporary password' : 'Current password'}
    <input type="password" bind:value={current} autocomplete="current-password" required />
  </label>
  <label class="field">
    New password
    <input type="password" bind:value={next} autocomplete="new-password" required minlength={MIN_PASSWORD} />
    <span class="hint">At least {MIN_PASSWORD} characters; a passphrase of several words is easy to remember.</span>
  </label>
  <label class="field">
    Repeat new password
    <input type="password" bind:value={repeat} autocomplete="new-password" required />
  </label>
  {#if problem}<div class="faint small" role="status">{problem}</div>{/if}
  {#if error}<div class="error-box" role="alert">{error}</div>{/if}
  <div>
    <button class="primary" type="submit" disabled={busy || !!problem}>{busy ? 'Saving…' : 'Change password'}</button>
  </div>
</form>

<style>
  .pw { display: grid; gap: 14px; max-width: 380px; }
  .notice { background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 8px 12px; margin: 0; }
</style>

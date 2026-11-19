<script lang="ts">
  import { ApiError, login } from '../lib/api';
  import { session } from '../lib/session.svelte';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await login(username.trim(), password);
      password = '';
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<main class="login">
  <form class="card" onsubmit={submit}>
    <div class="brand">
      <img src="/favicon.svg" alt="" width="36" height="36" />
      <div>
        <h1>dist-f2b</h1>
        <div class="muted small">controller</div>
      </div>
    </div>
    {#if session.expired}
      <div class="notice">Your session has ended. Please log in again.</div>
    {/if}
    <label class="field">
      User name
      <!-- svelte-ignore a11y_autofocus -->
      <input bind:value={username} autocomplete="username" required autofocus />
    </label>
    <label class="field">
      Password
      <input type="password" bind:value={password} autocomplete="current-password" required />
    </label>
    {#if error}<div class="error-box" role="alert">{error}</div>{/if}
    <button class="primary" type="submit" disabled={busy}>{busy ? 'Logging in…' : 'Log in'}</button>
    <p class="faint small">
      Users are created on the controller host:<br />
      <code>df2b-controller user add &lt;name&gt; --role admin</code>
    </p>
  </form>
</main>

<style>
  .login { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
  form { width: min(360px, 100%); display: grid; gap: 14px; padding: 24px; }
  .brand { display: flex; gap: 12px; align-items: center; margin-bottom: 4px; }
  .notice { background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 8px 12px; }
  p { margin: 0; }
</style>

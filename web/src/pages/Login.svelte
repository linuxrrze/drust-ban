<script lang="ts">
  import { ApiError, get, login } from '../lib/api';
  import { route } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import type { AuthMethods } from '../lib/types';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);
  let methods = $state<AuthMethods | null>(null);

  // set by the controller after a failed single sign-on: #/login-error/<code>
  const messages: Record<string, string> = {
    expired: 'The sign-in took too long or was started in another browser window. Please try again.',
    cancelled: 'Sign-in was cancelled at the identity provider.',
    denied: 'Your account has no access to dist-f2b. Ask an administrator to add you to one of the configured groups.',
    conflict: 'Your user name from the identity provider clashes with a local user or API token. Ask an administrator.',
    unavailable: 'The identity provider cannot be reached right now. Please try again later.',
    failed: 'Sign-in failed. Please try again; if it keeps failing, an administrator can find the reason in the controller log.',
  };
  const ssoError = $derived(
    route.parts[0] === 'login-error' ? (messages[route.parts[1]] ?? messages.failed) : '',
  );

  $effect(() => {
    get<AuthMethods>('/auth-methods')
      .then((m) => (methods = m))
      .catch(() => (methods = { password: true, oidc: null }));
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await login(username.trim(), password);
      password = '';
      if (route.parts[0] === 'login-error') location.hash = '#/';
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<main class="login">
  <div class="card box">
    <div class="brand">
      <img src="/favicon.svg" alt="" width="36" height="36" />
      <div>
        <h1>dist-f2b</h1>
        <div class="muted small">controller</div>
      </div>
    </div>
    {#if session.expired}
      <div class="notice">Your session has ended. Please sign in again.</div>
    {/if}
    {#if ssoError}<div class="error-box" role="alert">{ssoError}</div>{/if}

    {#if methods?.oidc}
      <!-- a full page navigation: the controller redirects to the provider -->
      <a class="button primary sso" href="/api/v1/oidc/login">Sign in with {methods.oidc.name}</a>
    {/if}

    {#if methods?.password}
      {#if methods.oidc}<div class="or"><span>or with a local account</span></div>{/if}
      <form onsubmit={submit}>
        <label class="field">
          User name
          <!-- svelte-ignore a11y_autofocus -->
          <input bind:value={username} autocomplete="username" required autofocus={!methods.oidc} />
        </label>
        <label class="field">
          Password
          <input type="password" bind:value={password} autocomplete="current-password" required />
        </label>
        {#if error}<div class="error-box" role="alert">{error}</div>{/if}
        <button class:primary={!methods.oidc} type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
      {#if !methods.oidc}
        <p class="faint small">
          Users are created on the controller host:<br />
          <code>df2b-controller user add &lt;name&gt; --role admin</code>
        </p>
      {/if}
    {/if}
  </div>
</main>

<style>
  .login { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
  .box { width: min(360px, 100%); display: grid; gap: 14px; padding: 24px; }
  form { display: grid; gap: 14px; }
  .brand { display: flex; gap: 12px; align-items: center; margin-bottom: 4px; }
  .notice { background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 8px 12px; }
  .sso { text-align: center; padding: 9px 12px; }
  .sso:hover { text-decoration: none; }
  .or { display: flex; align-items: center; gap: 10px; color: var(--text-3); font-size: 12.5px; }
  .or::before, .or::after { content: ''; flex: 1; border-top: 1px solid var(--border); }
  p { margin: 0; }
</style>

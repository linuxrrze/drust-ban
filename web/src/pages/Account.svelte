<script lang="ts">
  import { session } from '../lib/session.svelte';
  import ChangePassword from '../components/ChangePassword.svelte';
</script>

<div class="page-head"><h1>Your account</h1></div>

<div class="card">
  <dl>
    <dt>User</dt><dd>{session.me?.name}</dd>
    <dt>Role</dt><dd>{session.me?.role}</dd>
    <dt>Signed in with</dt>
    <dd>{session.me?.method === 'oidc' ? 'single sign-on' : session.me?.method === 'token' ? 'API token' : 'password'}</dd>
  </dl>
</div>

<div class="card">
  <h2>Password</h2>
  {#if session.me?.method === 'password'}
    <ChangePassword />
  {:else if session.me?.method === 'oidc'}
    <p class="muted">Your password is managed by your identity provider.</p>
  {:else}
    <p class="muted">API tokens have no password.</p>
  {/if}
</div>

<style>
  .card { margin-bottom: 16px; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; margin: 0; }
  dt { color: var(--text-2); }
  dd { margin: 0; }
  p { margin: 0; }
</style>

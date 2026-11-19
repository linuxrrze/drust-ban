<script lang="ts">
  import { checkSession, logout } from './lib/api';
  import { liveConnected, startLive, stopLive } from './lib/live.svelte';
  import { href, route } from './lib/router.svelte';
  import { can, session } from './lib/session.svelte';
  import Toasts from './components/Toasts.svelte';
  import Agents from './pages/Agents.svelte';
  import Audit from './pages/Audit.svelte';
  import Bans from './pages/Bans.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Ip from './pages/Ip.svelte';
  import Login from './pages/Login.svelte';
  import Sessions from './pages/Sessions.svelte';
  import Users from './pages/Users.svelte';
  import Tokens from './pages/Tokens.svelte';
  import Account from './pages/Account.svelte';
  import ChangePassword from './components/ChangePassword.svelte';

  checkSession();

  $effect(() => {
    // a temporary password allows nothing but changing it
    if (session.me && !session.me.must_change_password) startLive();
    else stopLive();
  });

  // signed in (again): leave the login error page
  $effect(() => {
    if (session.me && route.parts[0] === 'login-error') location.hash = '#/';
  });

  const page = $derived(route.parts[0] ?? '');
  const nav = $derived([
    { id: '', label: 'Overview', show: true },
    { id: 'bans', label: 'Bans', show: true },
    { id: 'agents', label: 'Agents', show: true },
    { id: 'ip', label: 'Address lookup', show: true },
    { id: 'users', label: 'Users', show: can('admin') },
    { id: 'tokens', label: 'API tokens', show: can('admin') },
    { id: 'sessions', label: 'Sessions', show: can('admin') },
    { id: 'audit', label: 'Audit log', show: can('admin') },
  ]);
  let menuOpen = $state(false);
  const adminPages = ['users', 'tokens', 'sessions', 'audit'];
</script>

{#if !session.checked}
  <div class="empty">Loading…</div>
{:else if !session.me}
  <Login />
{:else if session.me.must_change_password}
  <main class="forced">
    <div class="card">
      <h1>Choose a new password</h1>
      <p class="muted">Signed in as {session.me.name}.</p>
      <ChangePassword forced />
      <button class="link out" onclick={logout}>Sign out</button>
    </div>
  </main>
{:else}
  <div class="shell">
    <header>
      <a class="brand" href={href()}>
        <img src="/favicon.svg" alt="" width="24" height="24" />
        <span>dist-f2b</span>
      </a>
      <button class="menu-btn" aria-expanded={menuOpen} aria-controls="nav" onclick={() => (menuOpen = !menuOpen)}>Menu</button>
      <nav id="nav" class:open={menuOpen}>
        {#each nav.filter((n) => n.show) as n (n.id)}
          <a href={href(...(n.id ? [n.id] : []))} class:active={page === n.id} aria-current={page === n.id ? 'page' : undefined} onclick={() => (menuOpen = false)}>{n.label}</a>
        {/each}
      </nav>
      <span class="spacer"></span>
      <span class="live" title={liveConnected() ? 'Receiving live updates' : 'Live updates disconnected, reconnecting'}>
        <span class="dot" class:on={liveConnected()}></span>
        <span class="live-text">{liveConnected() ? 'live' : 'offline'}</span>
      </span>
      <a class="user" href={href('account')} title="Your account">{session.me.name} <span class="faint">· {session.me.role}</span></a>
      {#if session.me.auth === 'session'}
        <button onclick={logout}>Log out</button>
      {/if}
    </header>
    <main>
      {#if page === ''}
        <Dashboard />
      {:else if page === 'bans'}
        <Bans />
      {:else if page === 'agents'}
        <Agents selected={route.parts[1] ?? null} />
      {:else if page === 'ip'}
        {#key route.parts[1]}<Ip addr={route.parts.slice(1).join('/')} />{/key}
      {:else if page === 'account'}
        <Account />
      {:else if adminPages.includes(page) && !can('admin')}
        <div class="card empty">This page needs the admin role. <a href={href()}>Go to the overview</a></div>
      {:else if page === 'users'}
        <Users />
      {:else if page === 'tokens'}
        <Tokens />
      {:else if page === 'sessions'}
        <Sessions />
      {:else if page === 'audit'}
        <Audit />
      {:else}
        <div class="card empty">Page not found. <a href={href()}>Go to the overview</a></div>
      {/if}
    </main>
  </div>
{/if}
<Toasts />

<style>
  .shell { min-height: 100vh; }
  header {
    display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
    padding: 10px 24px; background: var(--surface); border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 10;
  }
  .brand { display: flex; align-items: center; gap: 8px; color: var(--text); font-weight: 700; font-size: 15px; }
  .brand:hover { text-decoration: none; }
  nav { display: flex; gap: 2px; }
  nav a { color: var(--text-2); padding: 6px 10px; border-radius: 8px; font-weight: 550; }
  nav a:hover { background: var(--surface-2); text-decoration: none; }
  nav a.active { color: var(--text); background: var(--surface-2); }
  .spacer { flex: 1; }
  .live { display: inline-flex; align-items: center; gap: 6px; color: var(--text-2); font-size: 12.5px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-3); }
  .dot.on { background: var(--good); }
  .user { font-weight: 550; color: var(--text); }
  .forced { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
  .forced .card { width: min(420px, 100%); display: grid; gap: 12px; padding: 24px; }
  .forced p { margin: 0; }
  .out { justify-self: start; }
  main { padding: 24px; max-width: 1400px; margin: 0 auto; }
  .menu-btn { display: none; }
  @media (max-width: 760px) {
    header { padding: 10px 16px; gap: 10px; }
    main { padding: 16px; }
    .menu-btn { display: block; order: 2; }
    .spacer { display: none; }
    .live { margin-left: auto; }
    .live-text, .user .faint { display: none; }
    nav { order: 10; width: 100%; flex-direction: column; display: none; }
    nav.open { display: flex; }
  }
</style>

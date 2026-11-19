// Hash routing (#/bans, #/ip/203.0.113.7): the controller then only has to
// serve real files, and the CSP stays simple.

function parse(): string[] {
  const h = location.hash.replace(/^#\/?/, '');
  return h === '' ? [] : h.split('/').map(decodeURIComponent);
}

export const route = $state<{ parts: string[] }>({ parts: parse() });

window.addEventListener('hashchange', () => {
  route.parts = parse();
});

export function href(...parts: string[]): string {
  return '#/' + parts.map(encodeURIComponent).join('/');
}

export function go(...parts: string[]): void {
  location.hash = href(...parts);
}

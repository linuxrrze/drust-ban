#!/usr/bin/env node
// Writes the license texts of all third-party code compiled into the
// df2b-agent, df2b-controller and df2bctl binaries (Rust crates and the
// Svelte runtime embedded with the web UI) to stdout, for
// /usr/share/doc/<package>/THIRD-PARTY-LICENSES. The licenses of the
// dependencies (MIT, Apache-2.0, BSD, ISC, ...) require these texts to be
// distributed with the binaries.
//
//   node packaging/third-party-licenses.mjs > target/THIRD-PARTY-LICENSES
//
// It fails if a dependency's license is not on the ALLOWED list below
// (all permissive, compatible with the project's MIT license), or if no
// license text can be found for it: a new dependency with a copyleft or
// unknown license then stops the package build instead of slipping in.
//
// Only normal dependencies of the packaged crates for the host platform
// count; build scripts, proc macros, dev-dependencies and tools (protoc,
// vite, the Svelte compiler) do not end up in the binaries.

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGES = ['df2b-agent', 'df2b-controller', 'df2bctl'];
// the parts of the web UI's node_modules that end up in web/dist (the
// Svelte runtime and what it imports)
const WEB_RUNTIME = ['svelte', 'clsx', 'esm-env'];

const ALLOWED = new Set([
  'MIT',
  'MIT-0',
  'Apache-2.0',
  'Apache-2.0 WITH LLVM-exception',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  'Zlib',
  'BSL-1.0',
  'Unlicense',
  'Unicode-3.0',
  'Unicode-DFS-2016',
  'CDLA-Permissive-2.0',
  '0BSD',
]);

const MIT_TEXT = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

const errors = [];

// --- SPDX expressions ("/" is the old spelling of OR) ---

function tokens(expr) {
  return expr
    .replace(/\//g, ' OR ')
    .replace(/([()])/g, ' $1 ')
    .trim()
    .split(/\s+/);
}

// the expression as a list of alternatives, each a list of licenses that
// all apply
function alternatives(expr) {
  const t = tokens(expr);
  let i = 0;
  const or = () => {
    let alts = and();
    while (t[i] === 'OR') {
      i++;
      alts = alts.concat(and());
    }
    return alts;
  };
  const and = () => {
    let alts = atom();
    while (t[i] === 'AND') {
      i++;
      const right = atom();
      alts = alts.flatMap((a) => right.map((b) => a.concat(b)));
    }
    return alts;
  };
  const atom = () => {
    if (t[i] === '(') {
      i++;
      const alts = or();
      if (t[i++] !== ')') throw new Error(`unbalanced parentheses in "${expr}"`);
      return alts;
    }
    let id = t[i++];
    if (id === undefined || ['AND', 'OR', ')'].includes(id)) {
      throw new Error(`cannot parse license "${expr}"`);
    }
    if (t[i] === 'WITH') {
      id = `${id} WITH ${t[i + 1]}`;
      i += 2;
    }
    return [[id]];
  };
  const alts = or();
  if (i !== t.length) throw new Error(`cannot parse license "${expr}"`);
  return alts;
}

function allowed(expr) {
  return alternatives(expr).some((alt) => alt.every((id) => ALLOWED.has(id)));
}

// --- license files ---

const LICENSE_FILE = /^(licen[cs]e|copying|copyright|notice|unlicense)/i;

function licenseFiles(dir) {
  return readdirSync(dir)
    .filter((f) => LICENSE_FILE.test(f) && statSync(join(dir, f)).isFile())
    .sort()
    .map((f) => ({ name: f, text: readFileSync(join(dir, f), 'utf8').trimEnd() + '\n' }));
}

// a crate without license files: the MIT text with its authors, if MIT is
// one of the alternatives
function fallback(name, license, authors) {
  if (!alternatives(license).some((alt) => alt.length === 1 && alt[0] === 'MIT')) {
    return null;
  }
  const who = authors.length ? authors.join(', ') : `the ${name} authors`;
  return [{ name: 'MIT (the crate ships no license file)', text: `Copyright (c) ${who}\n\n${MIT_TEXT}` }];
}

// --- Rust crates ---

function host() {
  const out = execFileSync('rustc', ['-vV'], { encoding: 'utf8' });
  return out.match(/^host: (\S+)$/m)[1];
}

function crates() {
  const meta = JSON.parse(
    execFileSync(
      'cargo',
      ['metadata', '--format-version', '1', '--locked', '--filter-platform', host()],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 256 << 20 },
    ),
  );
  const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const workspace = new Set(meta.workspace_members);
  const roots = meta.packages.filter((p) => workspace.has(p.id) && PACKAGES.includes(p.name));
  if (roots.length !== PACKAGES.length) throw new Error('packaged crates not found in the workspace');

  const seen = new Set();
  const stack = roots.map((p) => p.id);
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    const pkg = pkgs.get(id);
    // runs in the compiler only
    if (pkg.targets.some((t) => t.kind.includes('proc-macro'))) continue;
    for (const dep of nodes.get(id).deps) {
      if (dep.dep_kinds.some((k) => k.kind === null)) stack.push(dep.pkg);
    }
  }

  const out = [];
  for (const id of seen) {
    const p = pkgs.get(id);
    if (workspace.has(id) || p.targets.some((t) => t.kind.includes('proc-macro'))) continue;
    out.push({
      name: p.name,
      version: p.version,
      license: p.license,
      dir: dirname(p.manifest_path),
      licenseFile: p.license_file,
      authors: p.authors ?? [],
    });
  }
  return out;
}

// --- web UI runtime ---

function webPackages() {
  const out = [];
  for (const name of WEB_RUNTIME) {
    const dir = join(ROOT, 'web', 'node_modules', name);
    if (!existsSync(join(dir, 'package.json'))) {
      errors.push(`web/node_modules/${name} is missing: run 'npm --prefix web ci' first`);
      continue;
    }
    const p = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    const authors = p.author ? [typeof p.author === 'string' ? p.author : p.author.name] : [];
    out.push({ name: `${name} (npm)`, version: p.version, license: p.license, dir, authors });
  }
  return out;
}

// --- output ---

const deps = [...crates(), ...webPackages()].sort(
  (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
);

// identical license files are printed once, with all their users
const groups = new Map();
for (const d of deps) {
  if (!d.license) {
    errors.push(`${d.name} ${d.version}: no license declared`);
    continue;
  }
  try {
    if (!allowed(d.license)) {
      errors.push(`${d.name} ${d.version}: license "${d.license}" is not on the allowed list`);
      continue;
    }
  } catch (e) {
    errors.push(`${d.name} ${d.version}: ${e.message}`);
    continue;
  }
  let files = licenseFiles(d.dir);
  if (d.licenseFile && !files.length) {
    const f = join(d.dir, d.licenseFile);
    files = [{ name: d.licenseFile, text: readFileSync(f, 'utf8').trimEnd() + '\n' }];
  }
  if (!files.length) files = fallback(d.name, d.license, d.authors);
  if (!files) {
    errors.push(`${d.name} ${d.version}: no license file and no MIT alternative`);
    continue;
  }
  for (const f of files) {
    // the same text often comes as LICENSE-APACHE, LICENSE.txt, ...
    const key = f.text.replace(/\s+/g, ' ').trim();
    const g = groups.get(key) ?? { users: [], text: f.text };
    g.users.push(`${d.name} ${d.version}: ${f.name}`);
    groups.set(key, g);
  }
}

if (errors.length) {
  for (const e of errors) console.error(`third-party-licenses: ${e}`);
  process.exit(1);
}

const rule = '='.repeat(78);
let doc = `Third-party software in dist-f2b

The df2b-agent, df2b-controller and df2bctl binaries contain the following
third-party software (Rust crates; df2b-controller also embeds the Svelte
runtime in its web UI). dist-f2b itself is licensed under the MIT license
(see the copyright file next to this one).

`;
doc += deps.map((d) => `  ${d.name} ${d.version}: ${d.license}`).join('\n') + '\n';
for (const g of groups.values()) {
  doc += `\n${rule}\n${g.users.join('\n')}\n${rule}\n\n${g.text}`;
}
process.stdout.write(doc);

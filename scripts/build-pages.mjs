// Builds the static site pages in web/ from site-src/.
//
//   node scripts/build-pages.mjs
//
// Each page in site-src/pages/ starts with a front-matter comment:
//   <!--
//   title: Page title
//   description: One sentence for search results.
//   section: home | info | demos
//   scripts: app.js experiments.js
//   -->
// The page body is wrapped in site-src/layout.html. TeX between $…$ (inline) or
// $$…$$ (display) is rendered to MathML at build time, so the site needs no math
// library or extra fonts at runtime. {{include:name}} inserts site-src/fragments/name.html.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';
import katex from 'katex';

const ROOT = new URL('..', import.meta.url).pathname;
const SRC = join(ROOT, 'site-src');
const OUT = join(ROOT, 'web');
const layout = readFileSync(join(SRC, 'layout.html'), 'utf8');

// MathML Core renders only mathvariant="normal"; map the other variants to Unicode
// mathematical alphanumerics so blackboard, sans-serif, script and bold letters survive.
const ALPHA = {
  'double-struck': [0x1d538, 0x1d552, 0x1d7d8, { C: 'ℂ', H: 'ℍ', N: 'ℕ', P: 'ℙ', Q: 'ℚ', R: 'ℝ', Z: 'ℤ' }],
  'sans-serif': [0x1d5a0, 0x1d5ba, 0x1d7e2, {}],
  script: [0x1d49c, 0x1d4b6, null, { B: 'ℬ', E: 'ℰ', F: 'ℱ', H: 'ℋ', I: 'ℐ', L: 'ℒ', M: 'ℳ', R: 'ℛ', e: 'ℯ', g: 'ℊ', o: 'ℴ' }],
  bold: [0x1d400, 0x1d41a, 0x1d7ce, {}],
};
function mapVariant(text, variant) {
  const [upper, lower, digit, holes] = ALPHA[variant];
  return [...text].map((ch) => {
    if (holes[ch]) return holes[ch];
    if (ch >= 'A' && ch <= 'Z') return String.fromCodePoint(upper + ch.charCodeAt(0) - 65);
    if (ch >= 'a' && ch <= 'z') return String.fromCodePoint(lower + ch.charCodeAt(0) - 97);
    if (digit && ch >= '0' && ch <= '9') return String.fromCodePoint(digit + ch.charCodeAt(0) - 48);
    return ch;
  }).join('');
}
function fixVariants(mathml) {
  return mathml
    .replace(/<annotation[\s\S]*?<\/annotation>/g, '')
    .replace(/<(mi|mn|mtext) mathvariant="([\w-]+)">([^<]*)<\/\1>/g, (all, tag, variant, text) =>
      (ALPHA[variant] ? `<${tag}${tag === 'mi' ? ' mathvariant="normal"' : ''}>${mapVariant(text, variant)}</${tag}>` : all));
}

function renderMath(html) {
  const tex = (source, displayMode) => fixVariants(katex.renderToString(source, {
    displayMode, output: 'mathml', throwOnError: true, strict: 'error',
  }));
  return html
    .replace(/\$\$([\s\S]+?)\$\$/g, (_, t) => `<div class="math-display">${tex(t.trim(), true)}</div>`)
    .replace(/(^|[^\\])\$([^$\n]+?)\$/g, (_, pre, t) => `${pre}${tex(t, false)}`)
    .replace(/\\\$/g, '$');
}

function includeFragments(html) {
  return html.replace(/\{\{include:([\w-]+)\}\}/g, (_, name) =>
    readFileSync(join(SRC, 'fragments', `${name}.html`), 'utf8'));
}

for (const file of readdirSync(join(SRC, 'pages')).filter((f) => f.endsWith('.html'))) {
  const raw = readFileSync(join(SRC, 'pages', file), 'utf8');
  const match = raw.match(/^<!--([\s\S]*?)-->\s*/);
  if (!match) throw new Error(`${file}: missing front-matter comment`);
  const meta = Object.fromEntries(match[1].trim().split('\n').map((line) => {
    const i = line.indexOf(':');
    return [line.slice(0, i).trim(), line.slice(i + 1).trim()];
  }));
  const body = renderMath(includeFragments(raw.slice(match[0].length)));
  const scripts = (meta.scripts || '').split(/\s+/).filter(Boolean)
    .map((src) => `  <script type="module" src="${src.startsWith('/') ? src : `/${src}`}"></script>`).join('\n');
  const page = layout
    .replaceAll('{{title}}', meta.title)
    .replaceAll('{{description}}', meta.description)
    .replace(`data-section="${meta.section}"`, `data-section="${meta.section}" aria-current="true"`)
    .replace(`data-page="${file}"`, `data-page="${file}" aria-current="page"`)
    .replace('{{content}}', () => body.trim())
    .replace('{{scripts}}', () => scripts);
  writeFileSync(join(OUT, file), page);
  console.log(`built web/${basename(file)}`);
}

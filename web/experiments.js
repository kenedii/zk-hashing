// Experiment log charts: small dependency-free SVG line charts with a hover readout.
// Data comes from the CSV files in ./data/, which are the raw monitoring logs.

const NS = 'http://www.w3.org/2000/svg';

async function csv(path) {
  const text = await (await fetch(path)).text();
  const [head, ...rows] = text.trim().split('\n');
  const keys = head.split(',');
  return rows.map((r) => Object.fromEntries(r.split(',').map((v, i) => [keys[i], Number(v)])));
}

function el(name, attrs = {}, parent) {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (parent) parent.append(node);
  return node;
}

function niceMax(v) {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

/**
 * series: [{ name, values: [{x, y}], cls }]; refs: [{ y, label }]
 */
function lineChart(host, { series, refs = [], gaps = [], xLabel, yUnit, xFmt, yFmt, yMax, yDiv = 4, xStep }) {
  const W = 720, H = 260, m = { t: 16, r: 16, b: 40, l: 52 };
  const xs = series.flatMap((s) => s.values.map((p) => p.x));
  const x0 = 0, x1 = Math.max(...xs);
  const top = yMax ?? niceMax(Math.max(...series.flatMap((s) => s.values.map((p) => p.y)), ...refs.map((r) => r.y)) * 1.05);
  const sx = (x) => m.l + ((x - x0) / (x1 - x0)) * (W - m.l - m.r);
  const sy = (y) => H - m.b - (y / top) * (H - m.t - m.b);

  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'xchart', role: 'img' });
  // Grid and y ticks
  for (const g of gaps) {
    el('rect', { x: sx(g.from), y: m.t, width: sx(g.to) - sx(g.from), height: H - m.t - m.b, class: 'gap' }, svg);
    el('text', { x: (sx(g.from) + sx(g.to)) / 2, y: m.t + 14, class: 'gap-label', 'text-anchor': 'middle' }, svg).textContent = g.label;
  }
  for (let i = 0; i <= yDiv; i += 1) {
    const v = (top / yDiv) * i;
    el('line', { x1: m.l, x2: W - m.r, y1: sy(v), y2: sy(v), class: i ? 'grid' : 'baseline' }, svg);
    el('text', { x: m.l - 8, y: sy(v) + 4, class: 'tick', 'text-anchor': 'end' }, svg).textContent = yFmt(v);
  }
  // x ticks
  for (let v = Math.ceil(x0 / xStep) * xStep; v <= x1 + 1e-9; v += xStep) {
    el('line', { x1: sx(v), x2: sx(v), y1: H - m.b, y2: H - m.b + 5, class: 'baseline' }, svg);
    el('text', { x: sx(v), y: H - m.b + 18, class: 'tick', 'text-anchor': 'middle' }, svg).textContent = xFmt(v);
  }
  el('text', { x: (m.l + W - m.r) / 2, y: H - 4, class: 'tick axis-title', 'text-anchor': 'middle' }, svg).textContent = xLabel;
  // Reference lines
  for (const r of refs) {
    el('line', { x1: m.l, x2: W - m.r, y1: sy(r.y), y2: sy(r.y), class: 'ref' }, svg);
    el('text', { x: W - m.r - 4, y: sy(r.y) - 6, class: 'ref-label', 'text-anchor': 'end' }, svg).textContent = r.label;
  }
  // Series
  for (const s of series) {
    const inGap = (a, b) => gaps.some((g) => a <= g.from && b >= g.to);
    const d = s.values.map((p, i) => `${i && !inGap(s.values[i - 1].x, p.x) ? 'L' : 'M'}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join('');
    el('path', { d, class: `series ${s.cls}` }, svg);
  }
  // Hover layer
  const cross = el('line', { y1: m.t, y2: H - m.b, class: 'cross', visibility: 'hidden' }, svg);
  const dots = series.map((s) => el('circle', { r: 4, class: `dot ${s.cls}`, visibility: 'hidden' }, svg));
  const hit = el('rect', { x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b, fill: 'transparent' }, svg);
  const tip = document.createElement('div');
  tip.className = 'xtip';
  tip.hidden = true;

  function show(clientX) {
    const box = svg.getBoundingClientRect();
    const px = ((clientX - box.left) / box.width) * W;
    const xv = x0 + ((px - m.l) / (W - m.l - m.r)) * (x1 - x0);
    const lines = [];
    let at = null;
    series.forEach((s, i) => {
      let best = s.values[0];
      for (const p of s.values) if (Math.abs(p.x - xv) < Math.abs(best.x - xv)) best = p;
      at = best.x;
      dots[i].setAttribute('cx', sx(best.x));
      dots[i].setAttribute('cy', sy(best.y));
      dots[i].setAttribute('visibility', 'visible');
      lines.push(`<span class="key ${s.cls}"></span>${s.name}: <b>${yFmt(best.y, true)}</b>`);
    });
    cross.setAttribute('x1', sx(at));
    cross.setAttribute('x2', sx(at));
    cross.setAttribute('visibility', 'visible');
    tip.innerHTML = `<div class="tip-x">${xFmt(at, true)}</div>${lines.join('<br>')}`;
    tip.hidden = false;
    const left = (sx(at) / W) * box.width;
    tip.style.left = `${Math.min(left + 12, box.width - 220)}px`;
  }
  function hide() {
    tip.hidden = true;
    cross.setAttribute('visibility', 'hidden');
    dots.forEach((d) => d.setAttribute('visibility', 'hidden'));
  }
  hit.addEventListener('pointermove', (e) => show(e.clientX));
  hit.addEventListener('pointerleave', hide);

  // Legend (always for >= 2 series)
  if (series.length > 1) {
    const legend = document.createElement('p');
    legend.className = 'xlegend';
    legend.innerHTML = series.map((s) => `<span><span class="key ${s.cls}"></span>${s.name}</span>`).join('');
    host.append(legend);
  }
  const wrap = document.createElement('div');
  wrap.className = 'xchart-wrap';
  wrap.append(svg, tip);
  host.append(wrap);
  svg.setAttribute('aria-label', `${series.map((s) => s.name).join(' and ')} by ${xLabel.toLowerCase()} (${yUnit})`);
}

const hours = (s, long) => (long ? `${(s / 3600).toFixed(2)} h elapsed` : `${(s / 3600).toFixed(0)} h`);
const minutes = (s, long) => (long ? `${(s / 60).toFixed(1)} min elapsed` : `${(s / 60).toFixed(0)} min`);
const gib = (v, long) => (long ? `${v.toFixed(1)} GiB` : `${v.toFixed(0)}`);

async function boot() {
  try {
    const browser = await csv('data/browser-wasm32-mimc.csv');
    lineChart(document.getElementById('chart-browser'), {
      series: [{ name: 'Renderer memory', cls: 's1', values: browser.map((r) => ({ x: r.elapsed_s, y: r.renderer_rss_gib })) }],
      refs: [{ y: 4, label: 'wasm32 address-space limit, 4 GiB' }],
      xLabel: 'Time since the proof started', yUnit: 'GiB', xFmt: minutes, xStep: 180,
      yFmt: (v, long) => (long ? `${v.toFixed(2)} GiB` : `${v.toFixed(0)}`), yMax: 5, yDiv: 5,
    });

    const run = await csv('data/argon2id-pagefile-run.csv');
    // The monitor itself could not sample while the system was paging heavily.
    const gaps = [];
    for (let i = 1; i < run.length; i += 1) {
      if (run[i].elapsed_s - run[i - 1].elapsed_s > 600) gaps.push({ from: run[i - 1].elapsed_s, to: run[i].elapsed_s, label: 'No samples' });
    }
    lineChart(document.getElementById('chart-argon-mem'), {
      series: [
        { name: 'Committed memory', cls: 's1', values: run.map((r) => ({ x: r.elapsed_s, y: r.private_gib })) },
        { name: 'Resident in RAM', cls: 's2', values: run.map((r) => ({ x: r.elapsed_s, y: r.working_set_gib })) },
      ],
      refs: [{ y: 125.6, label: 'Physical RAM, 125.6 GiB' }], gaps,
      xLabel: 'Time since the proof started', yUnit: 'GiB', xFmt: hours, xStep: 3600, yFmt: gib, yMax: 250, yDiv: 5,
    });

    const util = [];
    for (let i = 1; i < run.length; i += 1) {
      const dt = run[i].elapsed_s - run[i - 1].elapsed_s;
      if (dt > 0 && dt <= 600) util.push({ x: run[i].elapsed_s, y: Math.min(100, (100 * (run[i].cpu_s - run[i - 1].cpu_s)) / dt) });
    }
    lineChart(document.getElementById('chart-argon-cpu'), {
      series: [{ name: 'Prover CPU use', cls: 's1', values: util }],
      refs: [], gaps,
      xLabel: 'Time since the proof started', yUnit: '% of one core', xFmt: hours, xStep: 3600,
      yFmt: (v, long) => (long ? `${v.toFixed(1)}% of one core` : `${v.toFixed(0)}%`), yMax: 100,
    });
  } catch (error) {
    for (const id of ['chart-browser', 'chart-argon-mem', 'chart-argon-cpu']) {
      const host = document.getElementById(id);
      if (host) host.textContent = `Chart data could not be loaded (${error.message}).`;
    }
  }
}

boot();

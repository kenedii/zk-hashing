// Interactive cave example (Quisquater et al.): an honest prover always exits on the
// called side; a guessing prover succeeds only when the call matches the side entered.
const $ = (id) => document.getElementById(id);
const left = $('path-left');
const right = $('path-right');
const dot = $('prover-dot');
const door = $('door');
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

let passed = 0;
let caughtAt = 0;
let round = 0;
let busy = false;

const SUP = '⁰¹²³⁴⁵⁶⁷⁸⁹';
const pow2 = (n) => `2⁻${String(n).split('').map((d) => SUP[d]).join('')}`;

const side = () => (crypto.getRandomValues(new Uint8Array(1))[0] & 1 ? 'right' : 'left');
const pathFor = (s) => (s === 'left' ? left : right);
const honest = () => $('prover-honest').checked;

function place(path, t) {
  const p = path.getPointAtLength(path.getTotalLength() * t);
  dot.setAttribute('cx', p.x.toFixed(1));
  dot.setAttribute('cy', p.y.toFixed(1));
}

function animate(path, from, to, ms) {
  if (reduceMotion || ms === 0) { place(path, to); return Promise.resolve(); }
  return new Promise((resolve) => {
    const start = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - start) / ms);
      const e = k < 0.5 ? 2 * k * k : 1 - ((-2 * k + 2) ** 2) / 2;
      place(path, from + (to - from) * e);
      if (k < 1) requestAnimationFrame(step); else resolve();
    };
    requestAnimationFrame(step);
  });
}

function highlight(entered, called, viaDoor) {
  left.classList.toggle('entered', entered === 'left');
  right.classList.toggle('entered', entered === 'right');
  left.classList.toggle('called', called === 'left');
  right.classList.toggle('called', called === 'right');
  door.classList.toggle('open', viaDoor);
}

function render() {
  $('toy-passed').textContent = `${passed} of ${round}`;
  const chance = 2 ** -passed;
  $('toy-chance').textContent = passed === 0 ? '1'
    : chance >= 1e-3 ? `1 in ${2 ** passed}` : `1 in ${(2 ** passed).toLocaleString()} (${pow2(passed)})`;
  const verdict = $('toy-verdict');
  verdict.className = 'toy-verdict';
  if (round === 0) verdict.textContent = 'No rounds yet.';
  else if (caughtAt) {
    verdict.classList.add('rejected');
    verdict.textContent = `Rejected. The prover came out of the wrong passage in round ${caughtAt}, so the verifier knows the claim is false.`;
  } else {
    verdict.classList.add(passed >= 20 ? 'accepted' : 'pending');
    verdict.textContent = passed >= 20
      ? `Convinced. A prover without the code would pass ${passed} rounds with probability ${pow2(passed)}.`
      : `So far so good. A guessing prover would still pass this far with probability ${$('toy-chance').textContent}.`;
  }
}

function log(text, ok) {
  const li = document.createElement('li');
  li.className = ok ? 'ok' : 'fail';
  li.textContent = text;
  $('toy-log').prepend(li);
}

async function oneRound(animated) {
  if (caughtAt) return false;
  round += 1;
  const entered = side();
  const called = side();
  const knows = honest();
  const ok = knows || entered === called;
  const viaDoor = knows && entered !== called;
  const exitSide = ok ? called : entered;
  const caption = $('toy-caption');
  if (animated) {
    highlight(entered, null, false);
    caption.textContent = `Round ${round}: the prover walks into one passage, out of the verifier's sight.`;
    await animate(pathFor(entered), 0, 0.92, 700);
    highlight(entered, called, false);
    caption.textContent = `The verifier calls: "Come out on the ${called}."`;
    await new Promise((r) => setTimeout(r, reduceMotion ? 0 : 450));
    if (viaDoor) {
      highlight(entered, called, true);
      await animate(pathFor(called), 0.92, 0.92, 0);
    }
    await animate(pathFor(exitSide), 0.92, 0, 700);
  } else {
    highlight(entered, called, viaDoor);
    place(pathFor(exitSide), 0);
  }
  caption.textContent = ok
    ? `The prover came out on the ${called}${viaDoor ? ', using the door' : ''}. Round passed.`
    : `The prover could not reach the ${called} side without the code and came out on the ${entered}. Caught.`;
  if (ok) passed += 1; else caughtAt = round;
  log(`Round ${round}: entered ${entered}, verifier called ${called}${viaDoor ? ', door used' : ''}: ${ok ? 'passed' : 'caught'}`, ok);
  render();
  return ok;
}

async function run(n) {
  if (busy) return;
  busy = true;
  for (const b of document.querySelectorAll('.toy-buttons button')) b.disabled = true;
  try {
    for (let i = 0; i < n; i += 1) if (!(await oneRound(n === 1))) break;
  } finally {
    busy = false;
    for (const b of document.querySelectorAll('.toy-buttons button')) b.disabled = false;
  }
}

function reset() {
  passed = 0; caughtAt = 0; round = 0;
  $('toy-log').replaceChildren();
  highlight(null, null, false);
  dot.setAttribute('cx', 160); dot.setAttribute('cy', 270);
  $('toy-caption').textContent = 'Choose a prover and run a round.';
  render();
}

$('toy-one').addEventListener('click', () => run(1));
$('toy-ten').addEventListener('click', () => run(10));
$('toy-reset').addEventListener('click', reset);
for (const r of document.querySelectorAll('input[name="prover"]')) r.addEventListener('change', reset);
render();

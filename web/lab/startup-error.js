// Shows a readable message if the Wasm verifier fails to start.
window.addEventListener('error', (event) => {
  const status = document.getElementById('wasm-status');
  const hash = document.getElementById('program-hash');
  const output = document.getElementById('log');
  if (status && status.textContent !== 'Wasm ready') status.textContent = 'load failed';
  if (hash && hash.textContent.includes('loading')) hash.textContent = 'WebAssembly failed to initialize';
  if (output) output.textContent = `Page startup error: ${event.message}`;
});

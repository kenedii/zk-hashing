// Cube lattice adapted from the tensors.vip frontend.
/* ---------- infinite wireframe-cube lattice (fly with scroll, drag to look, click to pulse) ---------- */
(() => {
  if (!window.THREE) return;
  const canvas = document.getElementById('cubes');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let renderer;
  try { renderer = new THREE.WebGLRenderer({canvas, antialias: true, alpha: false}); } catch (e) { return; }
  renderer.setClearColor(0x020504, 1);
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(70, 1, .1, 200);

  const S = 9;                    // spacing between cube centres
  const C = 1.9;                  // cube half-size
  const NX = 4, NY = 3, NZ = 8;  // block half-extent in cells (wraps around the camera => infinite)
  const hash = (i, j, k) => { const h = Math.sin(i * 127.1 + j * 311.7 + k * 74.7) * 43758.5453; return h - Math.floor(h); };
  const PAL = [[0.0, 1.0, 0.45], [0.10, 0.65, 1.0], [1.0, 0.16, 0.30]];

  // cube wireframes: each vertex carries its cube centre + local corner offset so the shader can spin each cube
  const cPos = [], cCtr = [], cCol = [], cSeed = [];
  const corners = [[-1,-1,-1],[1,-1,-1],[1,1,-1],[-1,1,-1],[-1,-1,1],[1,-1,1],[1,1,1],[-1,1,1]];
  const edges = [[0,1],[1,2],[2,3],[3,0],[4,5],[5,6],[6,7],[7,4],[0,4],[1,5],[2,6],[3,7]];
  // connectors between neighbouring cube centres
  const lPos = [], lCol = [];
  const nodes = [];
  for (let i = -NX; i <= NX; i++) for (let j = -NY; j <= NY; j++) for (let k = -NZ; k <= NZ; k++) {
    const x = i * S, y = j * S, z = k * S, h = hash(i, j, k);
    const pc = PAL[h < .45 ? 1 : h < .78 ? 0 : 2];
    const sc = 1.0;
    for (const [e0, e1] of edges) for (const v of [corners[e0], corners[e1]]) {
      cPos.push(v[0] * C * sc, v[1] * C * sc, v[2] * C * sc); cCtr.push(x, y, z); cCol.push(...pc); cSeed.push(h);
    }
    nodes.push(x, y, z);
    const dim = .75;
    if (i < NX) { lPos.push(x, y, z, x + S, y, z); lCol.push(.1*dim, .65*dim, 1*dim, .1*dim, .65*dim, 1*dim); }
    if (j < NY) { lPos.push(x, y, z, x, y + S, z); lCol.push(0, dim, .45*dim, 0, dim, .45*dim); }
    if (k < NZ) { lPos.push(x, y, z, x, y, z + S); lCol.push(dim, .16*dim, .3*dim, dim, .16*dim, .3*dim); }
  }

  const uniforms = {
    uTime: {value: 0},
    uPulseO: {value: new THREE.Vector3(0, 0, -1e5)}, uPulseT: {value: -100},
    uFar: {value: NZ * S * .85}, uPx: {value: 1},
  };
  const common = `
    uniform float uTime, uPulseT, uFar; uniform vec3 uPulseO;
    varying vec3 vW; varying float vD;
    float ringAt(){ float age = uTime - uPulseT; float r = age * 42.0;
      return exp(-pow((distance(vW, uPulseO) - r) / 4.0, 2.0)) * exp(-age * .5); }
    float fogAt(){ return (1.0 - smoothstep(uFar * .2, uFar, vD)) * smoothstep(1.0, 6.0, vD); }`;
  const mat = (vs, fs) => new THREE.ShaderMaterial({uniforms, vertexShader: vs, fragmentShader: common + fs,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending});
  const cubeMat = mat(`
    uniform float uTime, uPulseT; uniform vec3 uPulseO; attribute vec3 aCtr; attribute vec3 color; attribute float aSeed;
    varying vec3 vC; varying vec3 vW; varying float vD; varying float vSeed;
    mat3 rot(vec3 a, float t){ a = normalize(a); float s = sin(t), c = cos(t), o = 1.0 - c;
      return mat3(o*a.x*a.x+c, o*a.x*a.y+a.z*s, o*a.z*a.x-a.y*s,
                  o*a.x*a.y-a.z*s, o*a.y*a.y+c, o*a.y*a.z+a.x*s,
                  o*a.z*a.x+a.y*s, o*a.y*a.z-a.x*s, o*a.z*a.z+c); }
    void main(){
      // every cube turns in sync, so the lattice stays orderly; a pulse passing through kicks them
      float kick = exp(-pow((distance(aCtr + modelMatrix[3].xyz, uPulseO) - (uTime - uPulseT) * 42.0) / 6.0, 2.0)) * exp(-(uTime - uPulseT) * .5);
      float breathe = 1.0 + .08 * sin(uTime * 1.3 + (aCtr.x + aCtr.y + aCtr.z) * .08) + kick * .6;
      vec3 p = rot(vec3(.35, 1.0, .2), uTime * .35 + kick * 1.5) * position * breathe + aCtr;
      vec4 w = modelMatrix * vec4(p, 1.0); vW = w.xyz; vD = distance(w.xyz, cameraPosition); vC = color; vSeed = aSeed;
      gl_Position = projectionMatrix * viewMatrix * w; }`, `
    varying vec3 vC; varying float vSeed;
    void main(){ float tw = .55 + .45 * sin(uTime * (1.0 + vSeed * 2.0) + vSeed * 40.0);
      vec3 c = mix(vC, vec3(.85, .97, 1.0), .25) * (.55 + .45 * tw) + vec3(.9, 1.0, 1.0) * ringAt() * 2.2;
      gl_FragColor = vec4(c * fogAt(), 1.0); }`);
  const linkMat = mat(`
    attribute vec3 color; varying vec3 vC; varying vec3 vW; varying float vD;
    void main(){ vec4 w = modelMatrix * vec4(position,1.0); vW = w.xyz; vD = distance(w.xyz, cameraPosition); vC = color;
      gl_Position = projectionMatrix * viewMatrix * w; }`, `
    varying vec3 vC;
    void main(){ float flow = .35 + .65 * pow(.5 + .5 * sin(vW.x * .35 + vW.y * .35 + vW.z * .35 - uTime * 3.0), 6.0);
      gl_FragColor = vec4((vC * flow * .55 + vC * ringAt() * 2.5) * fogAt(), 1.0); }`);
  const pointMat = mat(`
    uniform float uPx; varying vec3 vW; varying float vD;
    void main(){ vec4 w = modelMatrix * vec4(position,1.0); vW = w.xyz; vD = distance(w.xyz, cameraPosition);
      vec4 mv = viewMatrix * w; gl_PointSize = uPx * 60.0 / -mv.z; gl_Position = projectionMatrix * mv; }`, `
    void main(){ float d = length(gl_PointCoord - .5); float a = smoothstep(.5, 0.0, d); a *= a;
      gl_FragColor = vec4(vec3(.7, .95, 1.0) * a * (.5 + ringAt() * 2.0) * fogAt(), 1.0); }`);

  const cg = new THREE.BufferGeometry();
  cg.setAttribute('position', new THREE.Float32BufferAttribute(cPos, 3));
  cg.setAttribute('aCtr', new THREE.Float32BufferAttribute(cCtr, 3));
  cg.setAttribute('color', new THREE.Float32BufferAttribute(cCol, 3));
  cg.setAttribute('aSeed', new THREE.Float32BufferAttribute(cSeed, 1));
  const lg = new THREE.BufferGeometry();
  lg.setAttribute('position', new THREE.Float32BufferAttribute(lPos, 3));
  lg.setAttribute('color', new THREE.Float32BufferAttribute(lCol, 3));
  const ng = new THREE.BufferGeometry();
  ng.setAttribute('position', new THREE.Float32BufferAttribute(nodes, 3));
  const lattice = new THREE.Group();
  lattice.add(new THREE.LineSegments(lg, linkMat), new THREE.LineSegments(cg, cubeMat), new THREE.Points(ng, pointMat));
  scene.add(lattice);
  lattice.children.forEach((c) => c.frustumCulled = false);

  // ---- data packets that race along the edges and turn at nodes
  const PN = 80, packets = [], pp = new Float32Array(PN * 3), pc = new Float32Array(PN * 3);
  const PCOL = [[0, 1, .4], [.1, .65, 1], [1, .16, .3]];
  const DIRS = [[1,0,0],[-1,0,0],[0,1,0],[0,-1,0],[0,0,1],[0,0,-1]];
  function spawn(p) {
    const c = camera.position;
    p.x = Math.round((c.x + (Math.random() - .5) * NX * S * 1.4) / S) * S;
    p.y = Math.round((c.y + (Math.random() - .5) * NY * S * 1.4) / S) * S;
    p.z = Math.round((c.z + (Math.random() - .5) * NZ * S * 1.4) / S) * S;
    p.d = DIRS[Math.random() * 6 | 0]; p.t = 0; p.v = 6 + Math.random() * 14; p.c = Math.random() * 3 | 0;
  }
  for (let i = 0; i < PN; i++) { const p = {}; spawn(p); p.t = Math.random() * S; packets.push(p); }
  const pg = new THREE.BufferGeometry();
  pg.setAttribute('position', new THREE.BufferAttribute(pp, 3));
  pg.setAttribute('color', new THREE.BufferAttribute(pc, 3));
  const packetMat = new THREE.ShaderMaterial({
    uniforms, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    vertexShader: `uniform float uPx; attribute vec3 color; varying vec3 vC; varying float vD;
      void main(){ vC = color; vec4 mv = modelViewMatrix * vec4(position,1.0); vD = -mv.z;
        gl_PointSize = uPx * 90.0 / -mv.z; gl_Position = projectionMatrix * mv; }`,
    fragmentShader: `uniform float uFar; varying vec3 vC; varying float vD;
      void main(){ float d = length(gl_PointCoord - .5); float a = smoothstep(.5, 0.0, d); a *= a;
        float fog = 1.0 - smoothstep(uFar * .3, uFar, vD);
        gl_FragColor = vec4((vC + vec3(.35) * smoothstep(.2, 0.0, d)) * a * fog * 1.4, 1.0); }`,
  });
  const packetPts = new THREE.Points(pg, packetMat); packetPts.frustumCulled = false;
  scene.add(packetPts);

  // ---- controls
  let yaw = .62, pitch = -.38, tYaw = .62, tPitch = -.38, mx = 0, my = 0;
  let vel = 0, strafe = 0, lift = 0;
  const DRIFT = reduce ? 0 : 1.1;
  let dragging = false, lx = 0, ly = 0, moved = 0, touchFly = false;
  const hint = document.getElementById('hint');
  let used = false;
  const markUsed = () => { if (!used && hint) { used = true; hint.classList.add('used'); } };
  if (hint) setTimeout(() => hint.classList.add('on'), 1800);

  addEventListener('wheel', (e) => {
    if (document.body.classList.contains('modal-open')) return;
    vel += -e.deltaY * .06;
    strafe += e.deltaX * .04;
    vel = Math.max(-90, Math.min(90, vel));
    markUsed();
  }, {passive: true});
  addEventListener('pointermove', (e) => {
    mx = e.clientX / innerWidth * 2 - 1; my = e.clientY / innerHeight * 2 - 1;
    if (!dragging) return;
    const dx = e.clientX - lx, dy = e.clientY - ly; lx = e.clientX; ly = e.clientY; moved += Math.abs(dx) + Math.abs(dy);
    if (touchFly) { vel += dy * .35; tYaw -= dx * .004; }
    else { tYaw -= dx * .005; tPitch = Math.max(-1.3, Math.min(1.3, tPitch - dy * .005)); }
    markUsed();
  });
  canvas.addEventListener('pointerdown', (e) => {
    dragging = true; moved = 0; lx = e.clientX; ly = e.clientY; touchFly = e.pointerType === 'touch';
    canvas.classList.add('drag'); canvas.setPointerCapture(e.pointerId);
  });
  const up = (e) => {
    if (!dragging) return; dragging = false; canvas.classList.remove('drag');
    if (moved < 6) pulseAt(e.clientX, e.clientY);
  };
  canvas.addEventListener('pointerup', up); canvas.addEventListener('pointercancel', () => { dragging = false; canvas.classList.remove('drag'); });
  const keys = {};
  // Keep keyboard input dedicated to the demo forms and document navigation.
  addEventListener('keyup', (e) => { keys[e.key.toLowerCase()] = false; });

  const ray = new THREE.Raycaster(), v2 = new THREE.Vector2();
  function pulseAt(x, y) {
    v2.set(x / innerWidth * 2 - 1, -(y / innerHeight * 2 - 1));
    ray.setFromCamera(v2, camera);
    uniforms.uPulseO.value.copy(ray.ray.origin).addScaledVector(ray.ray.direction, 18);
    uniforms.uPulseT.value = uniforms.uTime.value;
    markUsed();
  }
  window.__latticePulse = () => { uniforms.uPulseO.value.copy(camera.position); uniforms.uPulseT.value = uniforms.uTime.value; };

  function resize() {
    const w = innerWidth, h = innerHeight, dpr = Math.min(devicePixelRatio || 1, 2);
    renderer.setPixelRatio(dpr); renderer.setSize(w, h, false);
    camera.aspect = w / h; camera.fov = w < 640 ? 85 : 70; camera.updateProjectionMatrix();
    uniforms.uPx.value = dpr * h / 720;
  }
  addEventListener('resize', () => { resize(); if (reduce) renderer.render(scene, camera); }); resize();

  // start inside a cube, slightly offset so edges don't sit on the eye
  camera.rotation.order = 'YXZ';
  camera.position.set(S * .5, S * .5, S * .5);
  const fwd = new THREE.Vector3(), right = new THREE.Vector3(), upv = new THREE.Vector3();
  let last = performance.now();
  function frame(now) {
    if (!reduce) requestAnimationFrame(frame);
    if (document.hidden) { last = now; return; }
    const dt = Math.min(.05, (now - last) / 1000); last = now;
    if (!reduce) uniforms.uTime.value += dt;

    if (keys['w'] || keys['arrowup']) vel += 60 * dt;
    if (keys['s'] || keys['arrowdown']) vel -= 60 * dt;
    if (keys['a'] || keys['arrowleft']) strafe -= 40 * dt;
    if (keys['d'] || keys['arrowright']) strafe += 40 * dt;
    if (keys['q']) lift -= 40 * dt;
    if (keys['e']) lift += 40 * dt;

    // look: drag target + gentle mouse parallax
    yaw += (tYaw - mx * .35 - yaw) * Math.min(1, dt * 4);
    pitch += (tPitch - my * .22 - pitch) * Math.min(1, dt * 4);
    camera.rotation.y = yaw; camera.rotation.x = pitch;
    camera.rotation.z = Math.sin(uniforms.uTime.value * .2) * .04 - strafe * .004;

    camera.getWorldDirection(fwd);
    right.crossVectors(fwd, camera.up).normalize();
    upv.crossVectors(right, fwd).normalize();
    camera.position.addScaledVector(fwd, (vel + DRIFT) * dt);
    camera.position.addScaledVector(right, strafe * dt);
    camera.position.addScaledVector(upv, lift * dt);
    const damp = Math.pow(.18, dt);
    vel *= damp; strafe *= damp; lift *= damp;

    // infinite: snap the lattice block to the cell the camera is in
    lattice.position.set(Math.round(camera.position.x / S) * S, Math.round(camera.position.y / S) * S, Math.round(camera.position.z / S) * S);

    // packets
    const c = camera.position;
    for (let i = 0; i < PN; i++) {
      const p = packets[i];
      p.t += p.v * dt;
      if (p.t >= S) {
        p.x += p.d[0] * S; p.y += p.d[1] * S; p.z += p.d[2] * S; p.t -= S;
        if (Math.random() < .45) p.d = DIRS[Math.random() * 6 | 0];
        if (Math.abs(p.x - c.x) > NX * S || Math.abs(p.y - c.y) > NY * S || Math.abs(p.z - c.z) > NZ * S) spawn(p);
      }
      pp[i * 3] = p.x + p.d[0] * p.t; pp[i * 3 + 1] = p.y + p.d[1] * p.t; pp[i * 3 + 2] = p.z + p.d[2] * p.t;
      const k = PCOL[p.c]; pc[i * 3] = k[0]; pc[i * 3 + 1] = k[1]; pc[i * 3 + 2] = k[2];
    }
    pg.attributes.position.needsUpdate = true; pg.attributes.color.needsUpdate = true;

    renderer.render(scene, camera);
  }
  requestAnimationFrame(frame);
})();

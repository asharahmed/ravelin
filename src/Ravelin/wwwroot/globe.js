/* Ravelin — an interactive spinning Earth rendered on <canvas>, no library.
   Continents are picked out in ink dots; red "hotspots" mark findings worldwide
   with travelling threat-arcs that spawn and fade. Drag to spin (with momentum);
   it auto-rotates otherwise. Colours track the live CSS tokens (light/dark). */
(function () {
    const reduce = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const instances = new Map();
    let nextId = 1;
    const D2R = Math.PI / 180;

    // Coarse equirectangular land map: 48 cols (lon) × 24 rows (lat, N→S).
    // Each row lists the inclusive column ranges that are land.
    const MAP_W = 48, MAP_H = 24;
    const LAND_ROWS = [
        [],                                          //  0  90..82N  Arctic
        [[8, 11], [16, 19], [30, 34]],               //  1  islands
        [[5, 12], [15, 20], [28, 40]],               //  2  N Canada, Greenland, Siberia
        [[3, 13], [16, 19], [24, 44]],               //  3
        [[2, 15], [22, 46]],                         //  4  Alaska/Canada, N Eurasia
        [[5, 16], [22, 46]],                         //  5
        [[7, 15], [23, 45]],                         //  6  US, Europe→Asia
        [[8, 15], [24, 43]],                         //  7
        [[8, 13], [23, 42]],                         //  8  S US/Mexico, N Africa→Asia
        [[9, 13], [22, 31], [33, 41]],               //  9
        [[11, 13], [21, 30], [33, 34], [37, 41]],    // 10  C America, Sahel, India, SE Asia
        [[14, 17], [21, 31], [37, 42]],              // 11  N S.America, Africa, Indonesia
        [[14, 19], [22, 31], [38, 43]],              // 12  equator
        [[14, 20], [23, 30], [40, 44]],              // 13  S.America, Africa, N Australia
        [[15, 20], [24, 29], [39, 45]],              // 14
        [[16, 20], [25, 28], [39, 44]],              // 15
        [[16, 19], [25, 27], [40, 43]],              // 16  S Africa tip, Australia
        [[17, 18], [42, 43], [46, 46]],              // 17  Patagonia, SE Aus, NZ
        [[17, 18]],                                  // 18
        [[17, 17]],                                  // 19
        [[15, 16]],                                  // 20  Antarctic peninsula
        [[4, 46]],                                   // 21  Antarctica
        [[0, 47]],                                   // 22
        [[0, 47]],                                   // 23
    ];
    function isLand(lat, lon) {
        let col = Math.floor(((lon + 180) / 360) * MAP_W);
        let row = Math.floor(((90 - lat) / 180) * MAP_H);
        if (col < 0) col = 0; else if (col >= MAP_W) col = MAP_W - 1;
        if (row < 0) row = 0; else if (row >= MAP_H) row = MAP_H - 1;
        const ranges = LAND_ROWS[row];
        for (let i = 0; i < ranges.length; i++) if (col >= ranges[i][0] && col <= ranges[i][1]) return true;
        return false;
    }
    const toVec = (lat, lon) => {
        const la = lat * D2R, lo = lon * D2R, c = Math.cos(la);
        return [c * Math.cos(lo), Math.sin(la), c * Math.sin(lo)];
    };
    function fibSphere(n) {
        const out = [], gold = Math.PI * (3 - Math.sqrt(5));
        for (let i = 0; i < n; i++) {
            const y = 1 - (i / (n - 1)) * 2, r = Math.sqrt(Math.max(0, 1 - y * y)), th = gold * i;
            out.push([Math.cos(th) * r, y, Math.sin(th) * r]);
        }
        return out;
    }
    const norm = (v) => { const l = Math.hypot(v[0], v[1], v[2]) || 1; return [v[0] / l, v[1] / l, v[2] / l]; };

    function start(canvas) {
        const id = nextId++;
        const ctx = canvas.getContext('2d');

        // Even sphere sample; we keep the points that fall on land.
        // NOTE: longitude is negated. The camera is at +Z (right-handed, +X = screen
        // right), so on the front hemisphere azimuth atan2(z,x) runs right→left. Mapping
        // texture longitude straight to azimuth mirrors the Earth east-west; negating fixes it.
        const sampleSphere = fibSphere(60000);
        const buildLand = (sample) => {
            const out = [];
            for (let i = 0; i < sampleSphere.length; i++) {
                const p = sampleSphere[i];
                const lat = Math.asin(p[1]) / D2R, lon = -Math.atan2(p[2], p[0]) / D2R;
                if (sample(lat, lon)) out.push(p);
            }
            return out;
        };
        const pickHotspots = (pool) => {
            const hs = [];
            for (let k = 0; k < 9 && pool.length; k++) hs.push(pool[(Math.random() * pool.length) | 0]);
            return hs;
        };

        // Start with the coarse hand-map; upgrade to the real mask once it loads.
        let land = buildLand(isLand);
        let hotspots = pickHotspots(land);

        const maskImg = new Image();
        maskImg.onload = () => {
            try {
                const oc = document.createElement('canvas');
                oc.width = maskImg.naturalWidth; oc.height = maskImg.naturalHeight;
                const octx = oc.getContext('2d', { willReadFrequently: true });
                octx.drawImage(maskImg, 0, 0);
                const W = oc.width, H = oc.height, px = octx.getImageData(0, 0, W, H).data;
                const sample = (lat, lon) => {
                    let x = (((lon + 180) / 360) * W) | 0; if (x < 0) x = 0; else if (x >= W) x = W - 1;
                    let y = (((90 - lat) / 180) * H) | 0; if (y < 0) y = 0; else if (y >= H) y = H - 1;
                    return px[(y * W + x) * 4] > 8; // land = topology above sea level
                };
                land = buildLand(sample);
                hotspots = pickHotspots(land);
            } catch (e) { /* keep the fallback */ }
        };
        maskImg.src = 'earth-mask.png';

        let arcs = [], lastSpawn = 0;
        function spawnArc(t) {
            if (hotspots.length < 2) return;
            const a = hotspots[(Math.random() * hotspots.length) | 0];
            let b = hotspots[(Math.random() * hotspots.length) | 0];
            if (a === b) return;
            const mid = norm([(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2]).map((v) => v * 1.32);
            arcs.push({ a, b, mid, t0: t, life: 2600 + Math.random() * 1400 });
        }

        let ink = [40, 50, 70], red = [180, 50, 40];
        function resolve(name, fb) {
            try {
                const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
                if (!raw) return fb;
                ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.fillStyle = raw; ctx.fillRect(0, 0, 1, 1);
                const d = ctx.getImageData(0, 0, 1, 1).data; return [d[0], d[1], d[2]];
            } catch (e) { return fb; }
        }
        const readColors = () => { ink = resolve('--ink', ink); red = resolve('--red', red); };

        let dpr = 1;
        function resize() {
            dpr = Math.min(window.devicePixelRatio || 1, 2);
            const w = canvas.clientWidth || 1, h = canvas.clientHeight || 1;
            canvas.width = Math.max(1, Math.round(w * dpr)); canvas.height = Math.max(1, Math.round(h * dpr));
        }
        resize(); readColors();
        const ro = new ResizeObserver(resize); ro.observe(canvas);
        const mo = new MutationObserver(readColors);
        mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });

        // Interaction: drag to spin (horizontal), with momentum.
        let rot = -0.6, tilt = 0.41, vel = 0, dragging = false, lastX = 0, lastY = 0;
        const onDown = (e) => { dragging = true; lastX = e.clientX; lastY = e.clientY; vel = 0; canvas.style.cursor = 'grabbing'; if (e.pointerId != null) canvas.setPointerCapture(e.pointerId); };
        const onMove = (e) => {
            if (!dragging) return;
            const dx = (e.clientX - lastX) * 0.006, dy = (e.clientY - lastY) * 0.004;
            rot += dx; vel = dx; tilt = Math.max(-0.9, Math.min(0.9, tilt + dy));
            lastX = e.clientX; lastY = e.clientY;
        };
        const onUp = () => { dragging = false; canvas.style.cursor = 'grab'; };
        canvas.style.cursor = 'grab';
        canvas.addEventListener('pointerdown', onDown);
        window.addEventListener('pointermove', onMove);
        window.addEventListener('pointerup', onUp);

        let raf, running = true, last = 0;
        function project(p, cos, sin, st, ct, cx, cy, R) {
            const rx = p[0] * cos - p[2] * sin, rz = p[0] * sin + p[2] * cos;
            const ry = p[1] * ct - rz * st, rz2 = p[1] * st + rz * ct;
            return { x: cx + rx * R, y: cy - ry * R, depth: (rz2 + 1) / 2 };
        }

        function frame(t) {
            if (!running) return;
            if (!last) last = t;
            const dt = Math.min(t - last, 64); last = t;
            const moving = !reduce();
            if (!dragging) { if (moving) rot += dt * 0.00034 + vel; vel *= 0.93; }

            const w = canvas.clientWidth, h = canvas.clientHeight;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, w, h);
            const cx = w / 2, cy = h / 2, R = Math.min(w, h) * 0.44;
            const cos = Math.cos(rot), sin = Math.sin(rot), st = Math.sin(tilt), ct = Math.cos(tilt);
            const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

            // atmosphere glow (outside the disc)
            const g = ctx.createRadialGradient(cx, cy, R * 0.6, cx, cy, R * 1.16);
            g.addColorStop(0, rgba(ink, 0)); g.addColorStop(0.78, rgba(ink, 0.05)); g.addColorStop(1, rgba(ink, 0));
            ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R * 1.16, 0, 7); ctx.fill();

            // ocean: a clean, softly-lit sphere — no speckle. Light from the upper-left.
            const og = ctx.createRadialGradient(cx - R * 0.42, cy - R * 0.42, R * 0.04, cx, cy, R * 1.05);
            og.addColorStop(0, rgba(ink, 0.035)); og.addColorStop(0.7, rgba(ink, 0.085)); og.addColorStop(1, rgba(ink, 0.17));
            ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.fillStyle = og; ctx.fill();
            ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.strokeStyle = rgba(ink, 0.16); ctx.lineWidth = 1; ctx.stroke();

            // land (continents) — near hemisphere only; crisp dots over the clean ocean
            for (let i = 0; i < land.length; i++) {
                const pr = project(land[i], cos, sin, st, ct, cx, cy, R);
                if (pr.depth < 0.5) continue;                 // occlude far side
                const nd = (pr.depth - 0.5) * 2;              // 0 at limb → 1 at centre
                ctx.beginPath(); ctx.arc(pr.x, pr.y, 0.75 + nd * 1.2, 0, 7);
                ctx.fillStyle = rgba(ink, 0.45 + nd * 0.5); ctx.fill();
            }

            // dynamic threat arcs
            if (moving && t - lastSpawn > 1200) { spawnArc(t); lastSpawn = t; }
            const N = 26;
            arcs = arcs.filter((arc) => t - arc.t0 < arc.life);
            for (const arc of arcs) {
                const age = (t - arc.t0) / arc.life;
                const env = Math.sin(Math.min(1, Math.max(0, age)) * Math.PI); // fade in/out
                const path = []; let frontSum = 0;
                for (let s = 0; s <= N; s++) {
                    const u = s / N, iu = 1 - u;
                    const px = iu * iu * arc.a[0] + 2 * iu * u * arc.mid[0] + u * u * arc.b[0];
                    const py = iu * iu * arc.a[1] + 2 * iu * u * arc.mid[1] + u * u * arc.b[1];
                    const pz = iu * iu * arc.a[2] + 2 * iu * u * arc.mid[2] + u * u * arc.b[2];
                    const pr = project([px, py, pz], cos, sin, st, ct, cx, cy, R);
                    path.push(pr); frontSum += pr.depth;
                }
                const front = frontSum / (N + 1);
                if (front <= 0.45) continue;
                const fa = Math.min(1, (front - 0.45) * 3) * env;
                ctx.beginPath();
                for (let s = 0; s < path.length; s++) s === 0 ? ctx.moveTo(path[s].x, path[s].y) : ctx.lineTo(path[s].x, path[s].y);
                ctx.strokeStyle = rgba(red, 0.55 * fa); ctx.lineWidth = 1.3; ctx.stroke();
                const pp = path[Math.floor(Math.min(0.999, age) * N)];
                ctx.save(); ctx.shadowColor = rgba(red, 0.9); ctx.shadowBlur = 9;
                ctx.beginPath(); ctx.arc(pp.x, pp.y, 2.6, 0, 7); ctx.fillStyle = rgba(red, fa); ctx.fill(); ctx.restore();
            }

            // pulsing hotspots with glow
            const pulse = moving ? (Math.sin(t * 0.004) + 1) / 2 : 0.4;
            for (const p of hotspots) {
                const pr = project(p, cos, sin, st, ct, cx, cy, R);
                if (pr.depth <= 0.5) continue;
                const a = (pr.depth - 0.5) * 2;
                ctx.beginPath(); ctx.arc(pr.x, pr.y, 2.5 + pulse * 7, 0, 7);
                ctx.strokeStyle = rgba(red, a * (1 - pulse) * 0.9); ctx.lineWidth = 1.3; ctx.stroke();
                ctx.save(); ctx.shadowColor = rgba(red, 0.95); ctx.shadowBlur = 10;
                ctx.beginPath(); ctx.arc(pr.x, pr.y, 3, 0, 7); ctx.fillStyle = rgba(red, a); ctx.fill(); ctx.restore();
            }

            raf = requestAnimationFrame(frame);
        }
        raf = requestAnimationFrame(frame);

        instances.set(id, {
            stop() {
                running = false; cancelAnimationFrame(raf); ro.disconnect(); mo.disconnect();
                canvas.removeEventListener('pointerdown', onDown);
                window.removeEventListener('pointermove', onMove);
                window.removeEventListener('pointerup', onUp);
            },
        });
        return id;
    }

    function stop(id) { const i = instances.get(id); if (i) { i.stop(); instances.delete(id); } }
    window.ravelinGlobe = { start, stop };
})();

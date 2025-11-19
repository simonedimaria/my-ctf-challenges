const STARS_PATH_PREFIX = '/assets/stars/';
const NEBULAS_PATH_PREFIX = '/assets/nebulas/';
const LOGO_PATH = '/assets/mhack/mhackerone_logo.png';
const SHIPS_PATH_PREFIX = '/assets/mhack/';

const STAR_FILES = Array.from({ length: 10 }, (_, i) => `star${i + 1}.png`);
const NEBULA_FILES = Array.from({ length: 4 }, (_, i) => `nebula${i + 1}.png`);
const SHIP_FILES = Array.from({ length: 3 }, (_, i) => `mhackerone_spaceshuttle${i + 1}.png`);

const ANGLES = [0, 90, 180, 270];
const MAX_TRIES_PER_SPRITE = 30;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function rand(min, max) {
  return min + Math.random() * (max - min);
}

function pick(arr) {
  return arr[(Math.random() * arr.length) | 0];
}

function sampleScale(power, sMin, sMax) {
  const u = Math.random();
  const t = Math.pow(u, power);
  return sMin + t * (sMax - sMin);
}

function intersects(a, b) {
  return !(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y);
}

function loadImages(prefix, files) {
  return Promise.all(
    files.map(
      file =>
        new Promise((resolve, reject) => {
          const img = new Image();
          img.crossOrigin = 'anonymous';
          img.onload = () => resolve(img);
          img.onerror = () => reject(new Error(`Failed to load ${prefix}${file}`));
          img.src = `${prefix}${file}`;
        }),
    ),
  );
}

function loadImage(path) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error(`Failed to load ${path}`));
    img.src = path;
  });
}

function angleToVec(deg) {
  return {
    x: Math.cos((deg * Math.PI) / 180),
    y: Math.sin((deg * Math.PI) / 180),
  };
}

function shipToDataURL(img, sw, sh) {
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, sw | 0);
  canvas.height = Math.max(1, sh | 0);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL('image/png');
}

function downloadBlob(filename, mime, data) {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function normalizeConfig(raw) {
  const fallback = {
    color: '#090D29',
    stars: { count: 2000, power: 10, sMin: 0.1, sMax: 0.5 },
    nebs: { count: 10, power: 1.5, sMin: 0.1, sMax: 0.5, aMin: 0.4, aMax: 0.9 },
    ships: { count: 10, vmin: 70, vmax: 500 },
  };

  const config = { ...fallback, ...raw };

  const stars = {
    count: Math.max(0, Math.floor(raw?.stars?.count ?? fallback.stars.count)),
    power: Math.max(1, raw?.stars?.power ?? fallback.stars.power),
    sMin: Math.max(0.001, raw?.stars?.sMin ?? fallback.stars.sMin),
    sMax: Math.max(0.001, raw?.stars?.sMax ?? fallback.stars.sMax),
  };
  stars.sMax = Math.max(stars.sMin, Math.min(stars.sMax, 4));

  let aMin = clamp(raw?.nebs?.aMin ?? fallback.nebs.aMin, 0, 1);
  let aMax = clamp(raw?.nebs?.aMax ?? fallback.nebs.aMax, 0, 1);
  if (aMax < aMin) [aMin, aMax] = [aMax, aMin];

  const nebs = {
    count: Math.max(0, Math.floor(raw?.nebs?.count ?? fallback.nebs.count)),
    power: Math.max(1, raw?.nebs?.power ?? fallback.nebs.power),
    sMin: Math.max(0.001, raw?.nebs?.sMin ?? fallback.nebs.sMin),
    sMax: Math.max(0.001, raw?.nebs?.sMax ?? fallback.nebs.sMax),
    aMin,
    aMax,
  };
  nebs.sMax = Math.max(nebs.sMin, Math.min(nebs.sMax, 4));

  let vmin = Math.max(1, raw?.ships?.vmin ?? fallback.ships.vmin);
  let vmax = Math.max(1, raw?.ships?.vmax ?? fallback.ships.vmax);
  if (vmax < vmin) [vmin, vmax] = [vmax, vmin];

  const ships = {
    count: Math.max(0, Math.floor(raw?.ships?.count ?? fallback.ships.count)),
    vmin,
    vmax,
  };

  return {
    color: config.color || fallback.color,
    stars,
    nebs,
    ships,
  };
}

export function createStarfield(canvas) {
  const ctx = canvas.getContext('2d', { alpha: false });
  const runtimeStyle = document.createElement('style');
  runtimeStyle.id = 'shuttle-runtime';
  document.head.appendChild(runtimeStyle);

  let STAR_IMGS = [];
  let NEB_IMGS = [];
  let SHIP_IMGS = [];
  let LOGO_IMG = null;
  let SHUTTLE_REV = 0;

  let LAST_PLACEMENTS = null;
  let LAST_SHIPS_SNAPSHOT = [];
  let currentConfig = normalizeConfig();

  let pendingAssetsPromise = null;

  function sizeCanvas() {
    const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1));
    const W = Math.floor(window.innerWidth);
    const H = Math.floor(window.innerHeight);
    canvas.width = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { W, H };
  }

  function tryPlace(img, W, H, power, sMin, sMax, avoidRects) {
    for (let attempt = 0; attempt < MAX_TRIES_PER_SPRITE; attempt += 1) {
      const angle = pick(ANGLES);
      const scale = sampleScale(power, sMin, sMax);
      const sw = img.naturalWidth * scale;
      const sh = img.naturalHeight * scale;
      if (sw <= 0 || sh <= 0) continue;

      const bw = angle % 180 === 0 ? sw : sh;
      const bh = angle % 180 === 0 ? sh : sw;
      if (bw > W || bh > H) continue;

      const x = Math.random() * (W - bw);
      const y = Math.random() * (H - bh);
      const rect = { x, y, w: bw, h: bh };

      if (avoidRects && avoidRects.some(r => intersects(r, rect))) continue;

      return { x, y, sw, sh, bw, bh, angle, scale };
    }
    return null;
  }

  function drawPlacement(targetCtx, img, placement, alpha = 1) {
    const cx = placement.x + placement.bw / 2;
    const cy = placement.y + placement.bh / 2;
    targetCtx.save();
    targetCtx.globalAlpha = alpha;
    targetCtx.translate(cx, cy);
    targetCtx.rotate(((placement.angle || 0) * Math.PI) / 180);
    targetCtx.drawImage(img, -placement.sw / 2, -placement.sh / 2, placement.sw, placement.sh);
    targetCtx.restore();
  }

  function composeLayer(items, W, H) {
    if (!items || !items.length) return null;
    const offscreen = document.createElement('canvas');
    offscreen.width = W;
    offscreen.height = H;
    const g = offscreen.getContext('2d');
    for (const placement of items) {
      drawPlacement(g, placement.img, placement, placement.alpha ?? 1);
    }
    return offscreen.toDataURL('image/png');
  }

  let dummyHosts = [];

  function ensureShuttleHosts(count) {
    while (dummyHosts.length < count) {
      let host = document.createElement('div');
      host.style.cssText = 'position:fixed;top:0;left:0;width:0;height:0;overflow:hidden;pointer-events:none;';
      document.body.insertBefore(host, document.body.firstChild);
      dummyHosts.push(host);
    }
    while (dummyHosts.length > count) {
      const host = dummyHosts.pop();
      host.remove();
    }
  }
  
  function selectorForIndex(index) {
    return `body > :nth-child(${index + 1})::before`;
  }

  function buildShuttleCSS(rev = 0) {
    if (!LAST_SHIPS_SNAPSHOT.length) return '';

    ensureShuttleHosts(LAST_SHIPS_SNAPSHOT.length);

    let css = `html,body{position:relative !important;}
`;
    LAST_SHIPS_SNAPSHOT.forEach((ship, index) => {
      const selector = selectorForIndex(index);
      const duration = `${Math.max(1, ship.duration).toFixed(2)}s`;
      const name = `shuttle_${rev}_${index}`;
      css += `@keyframes ${name}{from{left:${ship.x0.toFixed(2)}px;top:${ship.y0.toFixed(2)}px;}to{left:${ship.x1.toFixed(2)}px;top:${ship.y1.toFixed(2)}px;}}
`;
      css += `${selector}{content:'' !important;position:fixed !important;left:${ship.x0.toFixed(2)}px;top:${ship.y0.toFixed(2)}px;width:${ship.sw.toFixed(2)}px !important;height:${ship.sh.toFixed(2)}px !important;background-image:url(${ship.dataURL}) !important;background-repeat:no-repeat !important;background-position:center center !important;background-size:100% 100% !important;transform:rotate(${ship.angle.toFixed(2)}deg) !important;animation:${name} ${duration} linear infinite !important;pointer-events:none !important;z-index:3 !important;}
`;
    });
    return css;
  }

  function updateRuntimeShuttleCSS() {
    SHUTTLE_REV += 1;
    runtimeStyle.textContent = buildShuttleCSS(SHUTTLE_REV);
  }

  function spawnShip(W, H, ships) {
    const img = SHIP_IMGS[(Math.random() * SHIP_IMGS.length) | 0];
    if (!img) return null;

    const side = ['l', 'r', 't', 'b'][(Math.random() * 4) | 0];
    const margin = 60;
    let x;
    let y;
    let base;

    if (side === 'l') {
      x = -margin;
      y = rand(0, H);
      base = 0;
    } else if (side === 'r') {
      x = W + margin;
      y = rand(0, H);
      base = 180;
    } else if (side === 't') {
      x = rand(0, W);
      y = -margin;
      base = 90;
    } else {
      x = rand(0, W);
      y = H + margin;
      base = 270;
    }

    const angle = base + rand(-50, 50);
    const speed = rand(ships.vmin, ships.vmax);
    const scale = rand(0.1, 0.28);
    const sw = img.naturalWidth * scale;
    const sh = img.naturalHeight * scale;
    const vector = angleToVec(angle);
    const vx = vector.x * speed;
    const vy = vector.y * speed;

    return { img, x, y, vx, vy, angle, sw, sh };
  }

  function buildShuttlePaths(W, H) {
    const ships = currentConfig.ships;
    LAST_SHIPS_SNAPSHOT = [];

    for (let i = 0; i < ships.count; i += 1) {
      const ship = spawnShip(W, H, ships);
      if (!ship) continue;

      const margin = 120;
      let tx = Number.POSITIVE_INFINITY;
      let ty = Number.POSITIVE_INFINITY;

      if (ship.vx > 0) {
        tx = (W + margin - ship.x) / ship.vx;
      } else if (ship.vx < 0) {
        tx = (-margin - ship.x) / ship.vx;
      }

      if (ship.vy > 0) {
        ty = (H + margin - ship.y) / ship.vy;
      } else if (ship.vy < 0) {
        ty = (-margin - ship.y) / ship.vy;
      }

      let duration = Math.min(tx, ty);
      if (!Number.isFinite(duration) || duration <= 0) {
        duration = 5;
      }

      const x1 = ship.x + ship.vx * duration;
      const y1 = ship.y + ship.vy * duration;
      let dataURL = '';

      try {
        dataURL = shipToDataURL(ship.img, ship.sw, ship.sh);
      } catch (error) {
        console.warn('Ship export failed, falling back to source URL.', error);
        dataURL = ship.img.src;
      }

      LAST_SHIPS_SNAPSHOT.push({
        dataURL,
        x0: ship.x,
        y0: ship.y,
        x1,
        y1,
        duration,
        angle: ship.angle,
        sw: ship.sw,
        sh: ship.sh,
      });
    }
  }

  function buildThemeCSS() {
    if (!LAST_PLACEMENTS) return '';

    const {
      viewport: { W, H },
      bg,
    } = LAST_PLACEMENTS;

    const layers = [];
    const logoURL = LAST_PLACEMENTS.logo ? composeLayer([LAST_PLACEMENTS.logo], W, H) : null;
    const starsURL = composeLayer(LAST_PLACEMENTS.stars, W, H);
    const nebsURL = composeLayer(LAST_PLACEMENTS.nebulas, W, H);

    if (logoURL) layers.push(`url(${logoURL})`);
    if (starsURL) layers.push(`url(${starsURL})`);
    if (nebsURL) layers.push(`url(${nebsURL})`);

    const images = layers.join(',');
    const pos = '50% 50%';
    const positions = Array(layers.length).fill(pos).join(',');
    const sizes = Array(layers.length).fill('cover').join(',');
    const repeats = Array(layers.length).fill('no-repeat').join(',');
    const attaches = Array(layers.length).fill('fixed').join(',');

    let css = `/* Ctrl+Space CTF special edition firefox theme */
`;
    css += `@font-face{font-family:'VCR OSD Mono';src:url('/assets/VCR_OSD_MONO_1.001.ttf') format('truetype');font-weight:400;font-style:normal;font-display:swap}
`;
    css += `:root{--theme-bg-color:${bg} !important;--space-ink:#F7FAFF !important;--space-muted:#CCD5FF !important;--space-yellow:#FFF275 !important;--space-pink:#FF51E1 !important;--space-violet:#B08CFF !important;--space-cyan:#66FFF9 !important;--space-teal:#33DEE6 !important;--card-bg:color-mix(in srgb,var(--theme-bg-color) 84%,black) !important;--card-border:rgba(255,255,255,.12) !important;--radius:12px !important}
`;
    css += `html,body{min-height:100% !important}
`;
    css += `body{color:var(--space-ink) !important;background-color:var(--theme-bg-color) !important;background-image:${images} !important;background-position:${positions} !important;background-size:${sizes} !important;background-repeat:${repeats} !important;background-attachment:${attaches} !important;font-family:'VCR OSD Mono',monospace !important}
`;
    css += `h1,h2{--grad:radial-gradient(circle,rgba(254,198,42,1) 0%, rgba(159,40,142,1) 50%, rgba(0,162,255,1) 100%) !important;background:var(--grad) !important;-webkit-background-clip:text !important;background-clip:text !important;color:transparent !important}
`;
    css += `a{color:var(--space-yellow) !important;text-decoration:none !important}a:hover{color:var(--space-pink) !important;text-decoration:underline !important}
`;
    css += `button{padding:.6rem 1rem !important;border-radius:var(--radius) !important;border:1px solid var(--card-border) !important;background:rgba(255,255,255,.06) !important;color:var(--space-ink) !important}
`;
    css += buildShuttleCSS();
    return css;
  }

  function render() {
    if (!currentConfig) return;
    const { W, H } = sizeCanvas();
    const { color, stars, nebs } = currentConfig;

    ctx.fillStyle = color;
    ctx.fillRect(0, 0, W, H);

    const nebRects = [];
    const nebulas = [];
    const starz = [];

    for (let i = 0; i < nebs.count; i += 1) {
      const img = pick(NEB_IMGS);
      if (!img) break;

      const placement = tryPlace(img, W, H, nebs.power, nebs.sMin, nebs.sMax, nebRects);
      if (!placement) continue;

      const t = (placement.scale - nebs.sMin) / ((nebs.sMax - nebs.sMin) || 1);
      const alpha = nebs.aMin + Math.max(0, Math.min(1, t)) * (nebs.aMax - nebs.aMin);

      drawPlacement(ctx, img, placement, alpha);
      nebRects.push({ x: placement.x, y: placement.y, w: placement.bw, h: placement.bh });
      nebulas.push({ img, ...placement, alpha });
    }

    for (let i = 0; i < stars.count; i += 1) {
      const img = pick(STAR_IMGS);
      if (!img) break;

      const placement = tryPlace(img, W, H, stars.power, stars.sMin, stars.sMax, null);
      if (!placement) continue;

      drawPlacement(ctx, img, placement, 1);
      starz.push({ img, ...placement, alpha: 1 });
    }

    let logo = null;
    if (LOGO_IMG) {
      const margin = 12;
      const targetHeight = Math.max(16, H * 0.15);
      const scale = targetHeight / LOGO_IMG.naturalHeight;
      const targetWidth = LOGO_IMG.naturalWidth * scale;
      const x = Math.floor(W - margin - targetWidth);
      const y = Math.floor(margin);
      const placement = {
        img: LOGO_IMG,
        x,
        y,
        bw: targetWidth,
        bh: targetHeight,
        sw: targetWidth,
        sh: targetHeight,
        angle: 0,
        scale,
        alpha: 1,
      };
      drawPlacement(ctx, LOGO_IMG, placement, 1);
      logo = placement;
    }

    LAST_PLACEMENTS = {
      viewport: { W, H },
      bg: color,
      nebulas,
      stars: starz,
      logo,
    };

    buildShuttlePaths(W, H);
    updateRuntimeShuttleCSS();
  }

  async function loadAssets() {
    if (pendingAssetsPromise) {
      return pendingAssetsPromise;
    }

    pendingAssetsPromise = Promise.all([
      loadImages(STARS_PATH_PREFIX, STAR_FILES)
        .then(images => {
          STAR_IMGS = images;
        })
        .catch(error => {
          console.warn(error);
          STAR_IMGS = [];
        }),
      loadImages(NEBULAS_PATH_PREFIX, NEBULA_FILES)
        .then(images => {
          NEB_IMGS = images;
        })
        .catch(error => {
          console.warn(error);
          NEB_IMGS = [];
        }),
      loadImages(SHIPS_PATH_PREFIX, SHIP_FILES)
        .then(images => {
          SHIP_IMGS = images;
        })
        .catch(error => {
          console.warn(error);
          SHIP_IMGS = [];
        }),
      loadImage(LOGO_PATH)
        .then(image => {
          LOGO_IMG = image;
        })
        .catch(error => {
          console.warn(error);
          LOGO_IMG = null;
        }),
    ]).finally(() => {
      pendingAssetsPromise = null;
    });

    return pendingAssetsPromise;
  }

  function setConfig(nextConfig) {
    currentConfig = normalizeConfig(nextConfig);
    render();
  }

  function downloadPNG() {
    try {
      if (canvas.toBlob) {
        canvas.toBlob(
          blob => {
            if (!blob) return;
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = 'theme.png';
            anchor.click();
            setTimeout(() => URL.revokeObjectURL(url), 500);
          },
          'image/png',
        );
      } else {
        const anchor = document.createElement('a');
        anchor.href = canvas.toDataURL('image/png');
        anchor.download = 'theme.png';
        anchor.click();
      }
    } catch (error) {
      alert('PNG export failed (likely due to CORS).');
      console.error(error);
    }
  }

  function downloadCSS() {
    try {
      const css = buildThemeCSS();
      if (!css) {
        alert('CSS export is unavailable until images render.');
        return;
      }
      downloadBlob('theme.css', 'text/css', css);
    } catch (error) {
      alert('CSS export failed.');
      console.error(error);
    }
  }

  function destroy() {
    runtimeStyle.remove();
    dummyHosts.forEach(node => node.remove());
    dummyHosts = [];
  }

  return {
    loadAssets,
    setConfig,
    render,
    downloadPNG,
    downloadCSS,
    destroy,
  };
}

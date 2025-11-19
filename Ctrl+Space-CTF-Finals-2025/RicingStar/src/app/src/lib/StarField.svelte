<script>
  import { onMount } from 'svelte';
  import { createStarfield } from './starfieldEngine';

  const props = $props();
  const config = $derived(props.config);
  let canvasEl;
  let engine = null;
  let assetsLoaded = $state(false);

  const toPlain = value => JSON.parse(JSON.stringify(value));
  
  function applyConfig(nextConfig) {
    if (!engine || typeof engine.setConfig !== 'function') {
      console.warn('Starfield engine missing setConfig', engine);
      return;
    }
    engine.setConfig(toPlain(nextConfig));
  }

  $effect(() => {
    if (!assetsLoaded) return;
    applyConfig(config);
  });

  onMount(() => {
    let cancelled = false;
    engine = createStarfield(canvasEl);
    if (!engine || typeof engine.setConfig !== 'function') {
      console.error('createStarfield returned unexpected value', engine);
    }

    const handleResize = () => {
      if (assetsLoaded) {
        engine.render();
      }
    };

    window.addEventListener('resize', handleResize);

    (async () => {
      try {
        await engine.loadAssets();
        if (!cancelled) {
          assetsLoaded = true;
          applyConfig(config);
        }
      } catch (error) {
        console.error('Failed to load assets.', error);
      }
    })();

    return () => {
      cancelled = true;
      window.removeEventListener('resize', handleResize);
      engine?.destroy();
      engine = null;
    };
  });

  export function render() {
    if (engine && assetsLoaded) {
      engine.render();
    }
  }

  export function updateConfig(nextConfig) {
    if (!assetsLoaded) {
      return;
    }
    applyConfig(nextConfig ?? config);
  }

  export function downloadPNG() {
    if (engine && assetsLoaded) {
      engine.downloadPNG();
    }
  }

  export function downloadCSS() {
    if (engine && assetsLoaded) {
      engine.downloadCSS();
    }
  }
</script>

<canvas bind:this={canvasEl} aria-label="Star + Nebula field"></canvas>

<script>
  import Hero from '$lib/Hero.svelte';
  import StarField from '$lib/StarField.svelte';
  import Toolbar from '$lib/Toolbar.svelte';
  import { browser } from '$app/environment';
  import { onMount } from 'svelte';

  const DEFAULT_CONFIG = Object.freeze({
    color: '#090D29',
    stars: { count: 2000, power: 10, sMin: 0.1, sMax: 0.5 },
    nebs: { count: 10, power: 1.5, sMin: 0.1, sMax: 0.5, aMin: 0.4, aMax: 0.9 },
    ships: { count: 10, vmin: 70, vmax: 500 },
  });

  const EXT_ZIP_PATH = '/ext.zip';
  const LOGO_PATH = '/assets/mhack/mhackerone_logo.png';

  let config = $state(structuredClone(DEFAULT_CONFIG));
  let editorOpen = $state(false);
  let showLogo = $state(true);
  let starfieldRef;

  function syncRoute() {
    if (!browser) return;
    editorOpen = window.location.hash === '#editor';
  }

  function openEditor() {
    if (!browser) return;
    if (window.location.hash !== '#editor') {
      window.location.hash = '#editor';
    } else {
      editorOpen = true;
    }
  }

  function closeEditor() {
    if (!browser) return;
    history.pushState('', document.title, window.location.pathname + window.location.search);
    editorOpen = false;
  }

  function setNestedValue(path, value) {
    const segments = path.split('.');
    const next = JSON.parse(JSON.stringify(config));
    let cursor = next;
    for (let i = 0; i < segments.length - 1; i += 1) {
      cursor = cursor[segments[i]];
    }
    cursor[segments.at(-1)] = value;
    config = next;
  }

  function handleToolbarChange(event) {
    const { path, value } = event.detail;
    setNestedValue(path, value);
    starfieldRef?.updateConfig(config);
  }

  function handleRegen() {
    starfieldRef?.updateConfig(config);
    starfieldRef?.render();
  }

  function handleDownloadPng() {
    starfieldRef?.downloadPNG();
  }

  function handleDownloadCss() {
    starfieldRef?.downloadCSS();
  }

  function handleLogoError() {
    showLogo = false;
  }

  onMount(() => {
    syncRoute();
    if (!browser) return undefined;
    const handler = () => syncRoute();
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  });

  $effect(() => {
    if (!browser) return;
    if (editorOpen) {
      if (window.location.hash !== '#editor') {
        window.location.hash = '#editor';
      }
    } else if (window.location.hash === '#editor') {
      history.replaceState('', document.title, window.location.pathname + window.location.search);
    }
  });
</script>

{#if !editorOpen}
  <Hero extensionUrl={EXT_ZIP_PATH} on:openeditor={openEditor} />
{/if}

<Toolbar
  config={config}
  open={editorOpen}
  on:change={handleToolbarChange}
  on:regen={handleRegen}
  on:downloadpng={handleDownloadPng}
  on:downloadcss={handleDownloadCss}
  on:closeeditor={closeEditor}
/>

{#if showLogo}
  <img class="logo" src={LOGO_PATH} alt="mhackerone logo" decoding="async" on:error={handleLogoError} />
{/if}

<StarField bind:this={starfieldRef} {config} />

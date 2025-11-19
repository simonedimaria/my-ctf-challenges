<script>
  import { createEventDispatcher } from 'svelte';

  const props = $props();
  const extensionUrl = $derived(props.extensionUrl);
  const dispatch = createEventDispatcher();

  function openEditor() {
    dispatch('openeditor');
  }
</script>

<section class="hero" aria-labelledby="hero-title">
  <h1 id="hero-title">RicingStar</h1>
  <p>
    The unique <b>Ctrl+Space CTF special edition FF theme</b> is here! Give your Firefox a space themed look with a customizable starfield and flying mhackeroni™ shuttles all over your tabs. <br>
    Made with only CSS and low permissions WebExtension, you can safely trust the vibe. Test it now by downloading it and loading with <code>Load temporary add-on</code> in <a href="about:debugging#/runtime/this-firefox"><code>about:debugging#/runtime/this-firefox</code></a>
  </p>
  <div class="cta">
    <button class="btn primary" type="button" on:click={openEditor}>
      Editor mode
    </button>
    <a class="btn" href={extensionUrl} download>
      Download
    </a>
  </div>
  <div class="release">
    <h4>Release notes</h4>
    <ul>
      <li>
        <strong>v1.0.0</strong> 🚀 First public release! <a href={extensionUrl} download>Download now</a>
      </li>
      <li>
        <strong>v0.7.0</strong> ✏️ New editor mode! You can now customize your starfield as you like and export the CSS in the extension's <code>theme.css</code> file to apply it in your tabs.
      </li>
      <li>
        <strong>v0.6.0</strong> 🛸 Flying mhackeroni™ spaceshuttles all over the screen! 
      </li>
      <li>
        <strong>v0.5.0</strong> 👾 Changed font to VCR OSD.
      </li>
      <li>
        <strong>v0.4.0</strong> ™️ Added mhackeroni™ logo.
      </li>
      <li>
        <strong>v0.3.0</strong> 🌀 Added customizable nebulas.
      </li>
      <li>
        <strong>v0.2.0</strong> ✨ Added customizable stars.
      </li>
      <li>
        <strong>v0.1.0</strong> 🌌 Added customizable background palette.
      </li>
    </ul>
  </div>
</section>

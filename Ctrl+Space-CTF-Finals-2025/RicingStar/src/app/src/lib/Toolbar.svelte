<script>
  import { createEventDispatcher } from 'svelte';

  const props = $props();
  const config = $derived(props.config);
  const open = $derived(props.open ?? false);

  const dispatch = createEventDispatcher();

  function toNumber(value, fallback = 0) {
    const parsed = parseFloat(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function toInt(value, fallback = 0) {
    const parsed = parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function update(path, value) {
    dispatch('change', { path, value });
  }

  function handleColor(event) {
    update('color', event.target.value);
  }

  const updateHandlers = {
    'stars.count': event => update('stars.count', Math.max(0, toInt(event.target.value, config.stars.count))),
    'stars.power': event => update('stars.power', Math.max(1, toNumber(event.target.value, config.stars.power))),
    'stars.sMin': event => update('stars.sMin', Math.max(0.001, toNumber(event.target.value, config.stars.sMin))),
    'stars.sMax': event => update('stars.sMax', Math.max(0.001, toNumber(event.target.value, config.stars.sMax))),
    'nebs.count': event => update('nebs.count', Math.max(0, toInt(event.target.value, config.nebs.count))),
    'nebs.power': event => update('nebs.power', Math.max(1, toNumber(event.target.value, config.nebs.power))),
    'nebs.sMin': event => update('nebs.sMin', Math.max(0.001, toNumber(event.target.value, config.nebs.sMin))),
    'nebs.sMax': event => update('nebs.sMax', Math.max(0.001, toNumber(event.target.value, config.nebs.sMax))),
    'nebs.aMin': event => update('nebs.aMin', Math.max(0, Math.min(1, toNumber(event.target.value, config.nebs.aMin)))),
    'nebs.aMax': event => update('nebs.aMax', Math.max(0, Math.min(1, toNumber(event.target.value, config.nebs.aMax)))),
    'ships.count': event => update('ships.count', Math.max(0, toInt(event.target.value, config.ships.count))),
    'ships.vmin': event => update('ships.vmin', Math.max(1, toNumber(event.target.value, config.ships.vmin))),
    'ships.vmax': event => update('ships.vmax', Math.max(1, toNumber(event.target.value, config.ships.vmax))),
  };

  function handleInput(key, event) {
    updateHandlers[key](event);
  }

  function regen() {
    dispatch('regen');
  }

  function downloadPng() {
    dispatch('downloadpng');
  }

  function downloadCss() {
    dispatch('downloadcss');
  }

  function closeEditor() {
    dispatch('closeeditor');
  }
</script>

<section class:is-open={open} class="toolbar" role="group" aria-label="Star field controls">
  <h3>Background</h3>
  <label>
    BG color
    <input type="color" value={config.color} oninput={handleColor} />
    <small class="hint"></small>
  </label>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>

  <h3>Stars</h3>
  <label>
    Count
    <input
      type="number"
      min="0"
      step="1"
      value={config.stars.count}
      oninput={(event) => handleInput('stars.count', event)}
    />
    <small class="hint"></small>
  </label>
  <label>
    Distance
    <input
      type="number"
      min="1"
      step="0.1"
      value={config.stars.power}
      oninput={(event) => handleInput('stars.power', event)}
    />
    <small class="hint"></small>
  </label>
  <label>
    Min scale
    <input
      type="number"
      min="0.01"
      step="0.01"
      value={config.stars.sMin}
      oninput={(event) => handleInput('stars.sMin', event)}
    />
  </label>
  <label>
    Max scale
    <input
      type="number"
      min="0.01"
      step="0.01"
      value={config.stars.sMax}
      oninput={(event) => handleInput('stars.sMax', event)}
    />
  </label>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>

  <h3>Nebulas</h3>
  <label>
    Count
    <input
      type="number"
      min="0"
      step="1"
      value={config.nebs.count}
      oninput={(event) => handleInput('nebs.count', event)}
    />
  </label>
  <label>
    Distance
    <input
      type="number"
      min="1"
      step="0.1"
      value={config.nebs.power}
      oninput={(event) => handleInput('nebs.power', event)}
    />
  </label>
  <label>
    Min scale
    <input
      type="number"
      min="0.01"
      step="0.01"
      value={config.nebs.sMin}
      oninput={(event) => handleInput('nebs.sMin', event)}
    />
  </label>
  <label>
    Max scale
    <input
      type="number"
      min="0.01"
      step="0.01"
      value={config.nebs.sMax}
      oninput={(event) => handleInput('nebs.sMax', event)}
    />
  </label>
  <label>
    Min alpha
    <input
      type="number"
      min="0"
      max="1"
      step="0.05"
      value={config.nebs.aMin}
      oninput={(event) => handleInput('nebs.aMin', event)}
    />
  </label>
  <label>
    Max alpha
    <input
      type="number"
      min="0"
      max="1"
      step="0.05"
      value={config.nebs.aMax}
      oninput={(event) => handleInput('nebs.aMax', event)}
    />
  </label>
  <div aria-hidden="true"></div>
  <div aria-hidden="true"></div>

  <h3>Shuttles</h3>
  <label>
    Count
    <input
      type="number"
      min="0"
      step="1"
      value={config.ships.count}
      oninput={(event) => handleInput('ships.count', event)}
    />
    <small class="hint"></small>
  </label>
  <label>
    Min speed (px/s)
    <input
      type="number"
      min="1"
      step="1"
      value={config.ships.vmin}
      oninput={(event) => handleInput('ships.vmin', event)}
    />
  </label>
  <label>
    Max speed (px/s)
    <input
      type="number"
      min="1"
      step="1"
      value={config.ships.vmax}
      oninput={(event) => handleInput('ships.vmax', event)}
    />
    <small class="hint"></small>
  </label>

  <div class="toolbar-actions">
    <button type="button" onclick={regen}>
      Regenerate
    </button>
    <button type="button" onclick={downloadPng}>
      Download PNG
    </button>
    <button type="button" onclick={downloadCss}>
      Download CSS Theme
    </button>
    <button type="button" onclick={closeEditor}>
      Close editor
    </button>
  </div>
</section>

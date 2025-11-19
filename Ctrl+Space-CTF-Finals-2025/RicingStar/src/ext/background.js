// background.js

async function setup() {
  await browser.scripting.registerContentScripts([{
    id: "bridge",
    js: ["contentscript.js"],
    matches: ["*://*/*"],
    world: "ISOLATED"
  }]);
}

async function applyTheme(msg, sender) {
  const extInfo = await browser.management.getSelf();
  const ENV = extInfo.installType;
  if (ENV !== "development") return;
  if (sender.id !== browser.runtime.id) return;
  const defaultOpts = {
    origin: "AUTHOR",
    target: { tabId: sender.tab.id }
  };
  const opts = Object.assign(defaultOpts, msg);
  await browser.scripting.insertCSS(opts);
}

browser.runtime.onMessage.addListener(applyTheme);
browser.runtime.onInstalled.addListener(setup);
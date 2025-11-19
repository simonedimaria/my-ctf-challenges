// contentscript.js

function validateCssRules(cssRules) {
    for (const rule of cssRules) {
        if (![CSSStyleRule, CSSFontFaceRule, CSSKeyframesRule].some(type => rule instanceof type)) {
            throw new Error("[SPTE] Only CSS style-rules allowed");
        }
        validateCssRules(rule?.cssRules ?? []);
    }
}

function validateInsertOptions(opts) {
    if (opts.css && opts.files) {
        throw new Error("[SPTE] Cannot specify both CSS and files options");
    }

    if (opts.css && typeof opts.css === "string") {
        const stylesheet = new CSSStyleSheet();
        stylesheet.replaceSync(opts.css);
        validateCssRules(stylesheet.cssRules);
    }
    else if (opts.files && Array.isArray(opts.files)) {
        for (const fileUrl of opts.files) {
            if (new URL(fileUrl).origin !== new URL(browser.runtime.getURL("")).origin) {
                throw new Error("[SPTE] Invalid file origin");
            }
        }
    }
    else {
        throw new Error("[SPTE] Either CSS or files options must be specified");
    }

    if (opts.origin && opts.origin !== "AUTHOR") {
        throw new Error("[SPTE] Invalid origin specified");
    }
}

async function applyDefaultTheme() {
    let fetchedCss = await (await fetch("http://127.0.0.1:80/assets/theme.css")).text();
    browser.runtime.sendMessage(browser.runtime.id, { css: fetchedCss }, {});
};

window.addEventListener("message", evt => {
    if (evt.origin !== window.origin) return;
    const options = evt.data || evt.data.wrappedJSObject;
    validateInsertOptions(options);
    const details = { ...options };
    browser.runtime.sendMessage(browser.runtime.id, details, {});
});

applyDefaultTheme();
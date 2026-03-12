/**
 * Injected into Antigravity's webview via CDP Runtime.evaluate.
 * Scans the DOM for accept/reject buttons and reports them back
 * through window.__airlockGetPending().
 *
 * This file runs in a BROWSER context (not Node.js).
 * It is loaded by cdpHandler.ts at runtime.
 *
 * The script is wrapped by cdpHandler with a sessionId parameter
 * to enable page-level ownership: only the enforcer instance that
 * first injected into a page will process its buttons.
 */
(function (injectedSessionId) {
    "use strict";

    if (typeof window === "undefined") return;
    if (window.__airlockInjected) return;
    window.__airlockInjected = true;
    window.__airlockOwnerSession = injectedSessionId || "unknown";

    let running = true;
    let idCounter = 0;

    // ── Helpers ────────────────────────────────────────────────────

    function getDocuments(root) {
        root = root || document;
        const docs = [root];
        try {
            // Traverse iframes
            const iframes = root.querySelectorAll("iframe, frame");
            for (const iframe of iframes) {
                try {
                    const doc = iframe.contentDocument || (iframe.contentWindow && iframe.contentWindow.document);
                    if (doc) {
                        const childDocs = getDocuments(doc);
                        for (const d of childDocs) docs.push(d);
                    }
                } catch (e) { /* cross-origin */ }
            }
            // Traverse shadow roots
            const allEls = root.querySelectorAll("*");
            for (const el of allEls) {
                if (el.shadowRoot) {
                    const childDocs = getDocuments(el.shadowRoot);
                    for (const d of childDocs) docs.push(d);
                }
            }
        } catch (e) { /* ignore */ }
        return docs;
    }

    function queryAll(selector) {
        const results = [];
        const docs = getDocuments();
        for (const doc of docs) {
            try {
                const els = doc.querySelectorAll(selector);
                for (const el of els) results.push(el);
            } catch (e) { /* ignore */ }
        }
        return results;
    }

    // ── Exclusion / inclusion guards ──────────────────────────────

    const EXCLUDED_AREAS = [
        "#workbench\\.parts\\.sidebar",
        "#workbench\\.parts\\.activitybar",
        "#workbench\\.parts\\.titlebar",
        "#workbench\\.parts\\.statusbar",
        ".menubar-menu-button",
        ".title-actions",
        '[class*="explorer"]',
        ".tabs-container",
        ".composite.viewlet",
        ".sidebar",
        ".activity-bar-container",
    ];

    const INCLUDED_AREAS = [
        "#antigravity\\.agentPanel",
        "#workbench\\.parts\\.auxiliarybar",
        '[class*="agent"]',
        '[class*="chat"]',
        '[class*="conversation"]',
        '[class*="agentic"]',
    ];

    function isInConversationArea(el) {
        for (const sel of EXCLUDED_AREAS) {
            try { if (el.closest(sel)) return false; } catch (e) { /* ignore */ }
        }
        for (const sel of INCLUDED_AREAS) {
            try { if (el.closest(sel)) return true; } catch (e) { /* ignore */ }
        }
        return true;
    }

    // ── Button text extraction ────────────────────────────────────

    function getButtonOwnText(el) {
        let ownText = "";
        for (const node of el.childNodes) {
            if (node.nodeType === Node.TEXT_NODE) {
                ownText += node.textContent;
            } else if (node.nodeType === Node.ELEMENT_NODE) {
                const tag = node.tagName ? node.tagName.toLowerCase() : "";
                if (tag === "input" || tag === "label" || tag === "checkbox") continue;
                const childText = (node.textContent || "").trim();
                if (childText.length <= 30 && !childText.toLowerCase().includes("always")) {
                    ownText += " " + childText;
                }
            }
        }
        ownText = ownText.trim();
        if (!ownText) {
            ownText = (el.textContent || "").trim();
        }
        return ownText.toLowerCase();
    }

    // ── Accept button detection ───────────────────────────────────

    const ACCEPT_PATTERNS = [
        "accept", "accept all", "run", "run all", "run command",
        "retry", "apply", "execute", "confirm",
        "allow once", "allow", "proceed", "continue",
        "yes", "ok", "save", "approve", "enable",
        "install", "update", "overwrite",
    ];
    const REJECT_PATTERNS = [
        "skip", "reject", "cancel", "close", "refine", "deny",
        "no", "dismiss", "abort", "ask every time",
        "always run", "always allow", "always proceed", "always auto",
    ];

    function isAcceptButton(el) {
        if (!isInConversationArea(el)) return false;
        const text = getButtonOwnText(el);
        if (text.length === 0 || text.length > 100) return false;
        if (REJECT_PATTERNS.some(function (r) { return text.includes(r); })) return false;
        if (!ACCEPT_PATTERNS.some(function (p) { return text.includes(p); })) return false;

        const style = window.getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        return (
            style.display !== "none" &&
            rect.width > 0 &&
            style.pointerEvents !== "none" &&
            !el.disabled
        );
    }

    // ── Command text extraction (for banned-command checking) ─────

    function findNearbyCommandText(el) {
        const selectors = ["pre", "code", "pre code"];
        let commandText = "";
        let container = el.parentElement;
        let depth = 0;

        while (container && depth < 10) {
            let sibling = container.previousElementSibling;
            let sibCount = 0;
            while (sibling && sibCount < 5) {
                if (sibling.tagName === "PRE" || sibling.tagName === "CODE") {
                    const t = (sibling.textContent || "").trim();
                    if (t.length > 0) commandText += " " + t;
                }
                for (const sel of selectors) {
                    const codeEls = sibling.querySelectorAll(sel);
                    for (const codeEl of codeEls) {
                        const t = (codeEl.textContent || "").trim();
                        if (t.length > 0 && t.length < 5000) commandText += " " + t;
                    }
                }
                sibling = sibling.previousElementSibling;
                sibCount++;
            }
            if (commandText.length > 10) break;
            container = container.parentElement;
            depth++;
        }

        // Also check aria-label / title
        const aria = el.getAttribute("aria-label");
        if (aria) commandText += " " + aria;
        const title = el.getAttribute("title");
        if (title) commandText += " " + title;

        return commandText.trim().toLowerCase();
    }

    function categorizeButton(text) {
        const terminal = ["run", "execute", "command", "terminal"];
        for (const kw of terminal) {
            if (text.includes(kw)) return "terminal";
        }
        return "agent";
    }

    // ── Public API exposed to the extension via CDP ───────────────

    window.__airlockGetPending = function () {
        if (!running) return { ownerSession: window.__airlockOwnerSession, buttons: [] };

        var selectors = [
            "button",
            '[role="button"]',
            "a.button",
            'div[role="button"]',
            "vscode-button",            // Webview UI toolkit
            ".monaco-button",           // VS Code native buttons
            ".monaco-text-button",
            '[class*="action-item"] a',  // VS Code action items
            '.action-label',            // VS Code action labels
        ];
        var found = [];
        for (var si = 0; si < selectors.length; si++) {
            var els = queryAll(selectors[si]);
            for (var ei = 0; ei < els.length; ei++) {
                found.push(els[ei]);
            }
        }

        var unique = [];
        var seen = new Set();
        for (var fi = 0; fi < found.length; fi++) {
            if (!seen.has(found[fi])) {
                seen.add(found[fi]);
                unique.push(found[fi]);
            }
        }

        var pending = [];
        for (var ui = 0; ui < unique.length; ui++) {
            var el = unique[ui];
            if (!isAcceptButton(el)) continue;
            var text = getButtonOwnText(el);
            var id = el.dataset.__airlockId || ("airlock-" + (++idCounter));
            el.dataset.__airlockId = id;

            var cat = categorizeButton(text);
            var commandText = findNearbyCommandText(el) || undefined;
            pending.push({ id: id, text: text, type: cat, commandText: commandText });
        }

        return { ownerSession: window.__airlockOwnerSession, buttons: pending };
    };

    // Diagnostic function: returns info about all buttons found in the DOM
    window.__airlockDiagnostic = function () {
        const docs = getDocuments();
        const allButtons = [];
        for (const doc of docs) {
            try {
                const btns = doc.querySelectorAll("button, [role='button'], .monaco-button, .monaco-text-button");
                for (const b of btns) {
                    const text = getButtonOwnText(b);
                    const inArea = isInConversationArea(b);
                    const isAccept = isAcceptButton(b);
                    const style = window.getComputedStyle(b);
                    const rect = b.getBoundingClientRect();
                    allButtons.push({
                        tag: b.tagName,
                        text: text.substring(0, 60),
                        inConvArea: inArea,
                        isAccept: isAccept,
                        visible: style.display !== "none" && rect.width > 0,
                        disabled: b.disabled,
                        classes: (b.className || "").toString().substring(0, 80),
                    });
                }
            } catch (e) { /* ignore */ }
        }
        return { docCount: docs.length, buttonCount: allButtons.length, buttons: allButtons };
    };

    window.__airlockGetButtonText = getButtonOwnText;

    window.__airlockStop = function () {
        running = false;
    };
})("__AIRLOCK_SESSION_ID__");

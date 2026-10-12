/* Digital Guardian - text analysis page helpers */
(function () {
    "use strict";

    const textarea = document.getElementById("content");
    const counter = document.getElementById("char-count");
    const pasteBtn = document.getElementById("paste-btn");
    const clearBtn = document.getElementById("clear-btn");
    const hint = document.getElementById("paste-hint");
    const form = document.getElementById("scan-form");

    function updateCount() {
        if (counter && textarea) counter.textContent = String(textarea.value.length);
    }

    if (textarea) {
        textarea.addEventListener("input", updateCount);
        updateCount();
    }

    if (pasteBtn) {
        pasteBtn.addEventListener("click", async function () {
            if (!navigator.clipboard || !navigator.clipboard.readText) {
                if (hint) {
                    hint.hidden = false;
                    hint.textContent = "Clipboard access is unavailable in this browser. Please paste manually with Ctrl/Cmd+V.";
                }
                return;
            }
            try {
                const text = await navigator.clipboard.readText();
                if (!textarea) return;
                textarea.value = (textarea.value ? textarea.value + "\n" : "") + text;
                updateCount();
                textarea.focus();
            } catch (err) {
                if (hint) {
                    hint.hidden = false;
                    hint.textContent = "Clipboard permission was denied. Paste manually with Ctrl/Cmd+V.";
                }
            }
        });
    }

    if (clearBtn && textarea) {
        clearBtn.addEventListener("click", function () {
            textarea.value = "";
            updateCount();
            textarea.focus();
        });
    }

    if (form) {
        form.addEventListener("submit", function () {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && textarea && textarea.value.trim()) {
                submitBtn.disabled = true;
                submitBtn.textContent = "Analysing…";
            }
        });
    }
})();

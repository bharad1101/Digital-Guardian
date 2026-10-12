/* Digital Guardian - image / screenshot analysis page */
(function () {
    "use strict";

    const dropzone = document.getElementById("img-dropzone");
    const fileInput = document.getElementById("img-file");
    const preview = document.getElementById("img-preview");
    const analyzeBtn = document.getElementById("img-analyze");
    const clearBtn = document.getElementById("img-clear");
    const resultBox = document.getElementById("img-result");

    let currentFile = null;
    let clientQrPayload = null;

    function showLoading(message) {
        resultBox.innerHTML = "";
        const box = document.createElement("div");
        box.className = "loading-state";
        const spinner = document.createElement("span");
        spinner.className = "spinner";
        box.appendChild(spinner);
        box.appendChild(document.createTextNode(message || "Analysing…"));
        resultBox.appendChild(box);
    }

    function showError(message) {
        resultBox.innerHTML = "";
        const callout = document.createElement("div");
        callout.className = "callout danger";
        callout.textContent = message;
        resultBox.appendChild(callout);
    }

    function reset() {
        currentFile = null;
        clientQrPayload = null;
        fileInput.value = "";
        preview.classList.add("hidden");
        preview.removeAttribute("src");
        analyzeBtn.disabled = true;
        clearBtn.disabled = true;
    }

    function tryClientQr(file, done) {
        clientQrPayload = null;
        if (!window.jsQR) { done(); return; }
        const reader = new FileReader();
        reader.onload = function () {
            const img = new Image();
            img.onload = function () {
                try {
                    const canvas = document.createElement("canvas");
                    canvas.width = img.naturalWidth;
                    canvas.height = img.naturalHeight;
                    const ctx = canvas.getContext("2d", { willReadFrequently: true });
                    ctx.drawImage(img, 0, 0);
                    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const code = window.jsQR(data.data, canvas.width, canvas.height);
                    if (code && code.data) clientQrPayload = code.data;
                } catch (e) { /* ignore */ }
                done();
            };
            img.onerror = done;
            img.src = reader.result;
        };
        reader.onerror = done;
        reader.readAsDataURL(file);
    }

    function handleFile(file) {
        if (!file) return;
        if (!file.type.startsWith("image/")) { showError("Please choose an image file."); return; }
        currentFile = file;
        analyzeBtn.disabled = false;
        clearBtn.disabled = false;
        const reader = new FileReader();
        reader.onload = function () {
            preview.src = reader.result;
            preview.classList.remove("hidden");
        };
        reader.readAsDataURL(file);
        tryClientQr(file, function () {
            if (clientQrPayload) {
                resultBox.innerHTML = "";
                const callout = document.createElement("div");
                callout.className = "callout";
                callout.textContent = "A QR code was detected in the image and will be analysed.";
                resultBox.appendChild(callout);
            }
        });
    }

    if (dropzone) {
        dropzone.addEventListener("click", function () { fileInput.click(); });
        dropzone.addEventListener("keydown", function (e) {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
        });
        ["dragenter", "dragover"].forEach(function (evt) {
            dropzone.addEventListener(evt, function (e) { e.preventDefault(); dropzone.classList.add("dragover"); });
        });
        ["dragleave", "drop"].forEach(function (evt) {
            dropzone.addEventListener(evt, function (e) { e.preventDefault(); dropzone.classList.remove("dragover"); });
        });
        dropzone.addEventListener("drop", function (e) {
            const files = e.dataTransfer && e.dataTransfer.files;
            if (files && files.length) handleFile(files[0]);
        });
    }
    fileInput.addEventListener("change", function () {
        if (fileInput.files.length) handleFile(fileInput.files[0]);
    });

    analyzeBtn.addEventListener("click", async function () {
        if (!currentFile) return;
        showLoading("Extracting QR and text from the image…");
        const form = new FormData();
        form.append("image", currentFile);
        if (clientQrPayload) form.append("qr_payload", clientQrPayload);
        try {
            const data = await DG.api("/api/v1/analyze/image", { method: "POST", body: form });
            resultBox.innerHTML = "";
            resultBox.appendChild(DG.buildResult(data));
        } catch (err) {
            showError(err.message);
        }
    });

    clearBtn.addEventListener("click", reset);
})();

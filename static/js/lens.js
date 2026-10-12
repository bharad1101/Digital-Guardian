/* =========================================================
   DIGITAL GUARDIAN - Guardian Lens (QR) client
   ========================================================= */
(function () {
    "use strict";

    const resultBox = document.getElementById("lens-result");
    const statusEl = document.getElementById("camera-status");

    let stream = null;
    let scanning = false;
    let detector = null;
    let currentFile = null;

    // ------------------------------------------------------ tabs
    document.querySelectorAll(".tab-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            document.querySelectorAll(".tab-btn").forEach(function (b) { b.classList.remove("active"); });
            btn.classList.add("active");
            document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.add("hidden"); });
            const panel = document.getElementById("panel-" + btn.dataset.tab);
            if (panel) panel.classList.remove("hidden");
        });
    });

    // ------------------------------------------------------ result rendering
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

    function renderResult(data) {
        resultBox.innerHTML = "";
        resultBox.appendChild(DG.buildResult(data));

        // Explicit, warned destination opening (never automatic).
        const url = data.payload && data.payload.url;
        if (url && /^https?:\/\//i.test(url)) {
            const actions = document.createElement("div");
            actions.className = "flex gap-1 wrap mt-2";
            const risky = data.risk_score >= 40;
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = risky ? "btn btn-danger" : "btn";
            btn.textContent = risky ? "Open destination (risky — verify first)" : "Open destination";
            btn.addEventListener("click", function () {
                const warning = risky
                    ? "Digital Guardian flagged this destination as " + DG.levelLabel(data.threat_level) +
                      ". Opening it may be unsafe. Continue?"
                    : "Open " + url + " in a new tab?";
                if (window.confirm(warning)) {
                    window.open(url, "_blank", "noopener,noreferrer");
                }
            });
            actions.appendChild(btn);
            resultBox.appendChild(actions);
        }
    }

    async function analyzeQr(payload) {
        showLoading("Analysing QR payload…");
        try {
            const data = await DG.api("/api/v1/analyze/qr", { method: "POST", json: { payload: payload } });
            renderResult(data);
        } catch (err) {
            showError(err.message);
        }
    }

    // ------------------------------------------------------ camera
    function currentStatus(text) { if (statusEl) statusEl.textContent = text; }

    async function startCamera() {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            currentStatus("Camera is not supported by this browser. Use Upload or Paste.");
            return;
        }
        const video = document.getElementById("lens-video");
        try {
            stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: { ideal: "environment" } }, audio: false
            });
            video.srcObject = stream;
            scanning = true;

            if ("BarcodeDetector" in window) {
                try {
                    detector = new window.BarcodeDetector({ formats: ["qr_code"] });
                    currentStatus("Point the camera at a QR code.");
                    scanWithDetector();
                    return;
                } catch (e) { detector = null; }
            }
            currentStatus("Detecting with in-browser decoder. Point at a QR code.");
            scanWithJsQR();
        } catch (err) {
            currentStatus("Camera permission denied or unavailable. Use Upload or Paste.");
        }
    }

    function stopCamera() {
        scanning = false;
        detector = null;
        if (stream) {
            stream.getTracks().forEach(function (t) { t.stop(); });
            stream = null;
        }
        const video = document.getElementById("lens-video");
        if (video) video.srcObject = null;
        currentStatus("Camera stopped.");
    }

    async function scanWithDetector() {
        const video = document.getElementById("lens-video");
        if (!scanning || !detector) return;
        try {
            const codes = await detector.detect(video);
            if (codes.length && codes[0].rawValue) {
                const payload = codes[0].rawValue;
                stopCamera();
                await analyzeQr(payload);
                return;
            }
        } catch (e) { /* keep scanning */ }
        if (scanning) requestAnimationFrame(scanWithDetector);
    }

    let jsqrCanvas = null;
    function scanWithJsQR() {
        const video = document.getElementById("lens-video");
        if (!scanning) return;
        if (!window.jsQR) {
            currentStatus("In-browser QR decoding is unavailable. Use Upload or Paste.");
            return;
        }
        if (!jsqrCanvas) jsqrCanvas = document.createElement("canvas");
        const w = video.videoWidth, h = video.videoHeight;
        if (w && h) {
            jsqrCanvas.width = w; jsqrCanvas.height = h;
            const ctx = jsqrCanvas.getContext("2d", { willReadFrequently: true });
            ctx.drawImage(video, 0, 0, w, h);
            const imageData = ctx.getImageData(0, 0, w, h);
            const code = window.jsQR(imageData.data, w, h);
            if (code && code.data) {
                stopCamera();
                analyzeQr(code.data);
                return;
            }
        }
        if (scanning) requestAnimationFrame(scanWithJsQR);
    }

    document.getElementById("start-camera").addEventListener("click", startCamera);
    document.getElementById("stop-camera").addEventListener("click", stopCamera);

    // ------------------------------------------------------ upload / drag-drop
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("lens-file");
    const preview = document.getElementById("lens-preview");
    const ocrBtn = document.getElementById("lens-ocr-btn");

    function decodeImageFile(file) {
        if (!file) return;
        if (!file.type.startsWith("image/")) {
            showError("Please choose an image file.");
            return;
        }
        currentFile = file;
        ocrBtn.classList.remove("hidden");
        const reader = new FileReader();
        reader.onload = function () {
            preview.src = reader.result;
            preview.classList.remove("hidden");
            const img = new Image();
            img.onload = function () {
                if (!window.jsQR) { showError("In-browser QR decoding unavailable. Use ‘Analyse with OCR’."); return; }
                const canvas = document.createElement("canvas");
                canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
                const ctx = canvas.getContext("2d", { willReadFrequently: true });
                ctx.drawImage(img, 0, 0);
                const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = window.jsQR(data.data, canvas.width, canvas.height);
                if (code && code.data) {
                    analyzeQr(code.data);
                } else {
                    resultBox.innerHTML = "";
                    const callout = document.createElement("div");
                    callout.className = "callout warn";
                    callout.textContent = "No QR code was found in this image. Use “Analyse this image with OCR” to extract and inspect any text.";
                    resultBox.appendChild(callout);
                }
            };
            img.onerror = function () { showError("That image could not be loaded."); };
            img.src = reader.result;
        };
        reader.readAsDataURL(file);
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
            if (files && files.length) decodeImageFile(files[0]);
        });
    }
    fileInput.addEventListener("change", function () {
        if (fileInput.files.length) decodeImageFile(fileInput.files[0]);
    });

    async function analyzeImageWithOcr() {
        if (!currentFile) { showError("Choose an image first."); return; }
        showLoading("Extracting text and QR from the image…");
        const form = new FormData();
        form.append("image", currentFile);
        try {
            const data = await DG.api("/api/v1/analyze/image", { method: "POST", body: form });
            renderResult(data);
        } catch (err) {
            showError(err.message);
        }
    }
    if (ocrBtn) ocrBtn.addEventListener("click", analyzeImageWithOcr);

    // ------------------------------------------------------ manual / clipboard
    document.getElementById("analyze-manual").addEventListener("click", function () {
        const value = document.getElementById("manual-payload").value.trim();
        if (!value) { showError("Enter a QR payload or URL first."); return; }
        analyzeQr(value);
    });

    document.getElementById("paste-payload").addEventListener("click", async function () {
        const ta = document.getElementById("manual-payload");
        if (!navigator.clipboard || !navigator.clipboard.readText) {
            showError("Clipboard access is unavailable in this browser. Paste manually.");
            return;
        }
        try {
            const text = await navigator.clipboard.readText();
            ta.value = text;
            ta.focus();
        } catch (e) {
            showError("Clipboard permission was denied. Paste manually.");
        }
    });

    window.addEventListener("beforeunload", stopCamera);
})();

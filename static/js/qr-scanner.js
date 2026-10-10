/**
 * ============================================================
 * DIGITAL GUARDIAN - GUARDIAN LENS
 * QR SECURITY SCANNER
 * ============================================================
 *
 * This JavaScript:
 *
 * 1. Opens the device camera
 * 2. Attempts to detect QR codes
 * 3. Extracts the QR payload
 * 4. Sends the payload to Flask
 * 5. Displays the security analysis
 * 6. Allows the user to manually open a destination
 *
 * ============================================================
 */


// ============================================================
// DOM ELEMENTS
// ============================================================

const video =
    document.getElementById("qr-video");

const startButton =
    document.getElementById("start-camera");

const stopButton =
    document.getElementById("stop-camera");

const message =
    document.getElementById("camera-message");

const manualPayload =
    document.getElementById("manual-payload");

const analyzeManualButton =
    document.getElementById("analyze-manual");

const resultBox =
    document.getElementById("qr-result");

const resultType =
    document.getElementById("result-type");

const resultUrl =
    document.getElementById("result-url");

const resultIndicators =
    document.getElementById("result-indicators");

const openSafeButton =
    document.getElementById("open-safe");


// ============================================================
// APPLICATION STATE
// ============================================================

let stream = null;

let scanning = false;

let detector = null;


// ============================================================
// START CAMERA
// ============================================================

async function startCamera() {

    // --------------------------------------------------------
    // Check browser camera support
    // --------------------------------------------------------

    if (
        !navigator.mediaDevices ||
        !navigator.mediaDevices.getUserMedia
    ) {

        message.textContent =
            "Camera access is not supported by this browser.";

        return;
    }


    // --------------------------------------------------------
    // Request camera permission
    // --------------------------------------------------------

    try {

        stream =
            await navigator.mediaDevices.getUserMedia({

                video: {
                    facingMode: {
                        ideal: "environment"
                    }
                },

                audio: false

            });


        // ----------------------------------------------------
        // Connect camera stream to video element
        // ----------------------------------------------------

        video.srcObject = stream;

        scanning = true;


        message.textContent =
            "Camera active. Point it at a QR code.";


        // ----------------------------------------------------
        // Check BarcodeDetector API
        // ----------------------------------------------------

        if ("BarcodeDetector" in window) {

            detector =
                new BarcodeDetector({
                    formats: ["qr_code"]
                });


            message.textContent =
                "QR scanner active. Point your camera at a QR code.";


            scanFrame();

        } else {

            message.textContent =
                "Camera is active, but automatic QR detection " +
                "is not supported by this browser. " +
                "Use the manual analyzer below.";
        }


    } catch (error) {

        console.error(
            "Camera error:",
            error
        );


        message.textContent =
            "Camera permission was denied or the camera is unavailable.";
    }
}


// ============================================================
// STOP CAMERA
// ============================================================

function stopCamera() {

    scanning = false;


    if (stream) {

        stream
            .getTracks()
            .forEach(
                function(track) {

                    track.stop();

                }
            );

        stream = null;
    }


    video.srcObject = null;


    message.textContent =
        "Camera stopped.";
}


// ============================================================
// QR DETECTION LOOP
// ============================================================

async function scanFrame() {

    // --------------------------------------------------------
    // Stop if scanner is no longer active
    // --------------------------------------------------------

    if (
        !scanning ||
        !detector
    ) {

        return;
    }


    try {

        // ----------------------------------------------------
        // Detect QR codes in current video frame
        // ----------------------------------------------------

        const barcodes =
            await detector.detect(video);


        // ----------------------------------------------------
        // QR code found
        // ----------------------------------------------------

        if (barcodes.length > 0) {

            const payload =
                barcodes[0].rawValue;


            if (payload) {

                // Stop camera after successful detection

                stopCamera();


                // Send QR data to Flask

                await analyzePayload(payload);
            }
        }


    } catch (error) {

        console.error(
            "QR detection error:",
            error
        );
    }


    // --------------------------------------------------------
    // Continue scanning
    // --------------------------------------------------------

    if (scanning) {

        requestAnimationFrame(
            scanFrame
        );
    }
}


// ============================================================
// ANALYZE QR PAYLOAD
// ============================================================

async function analyzePayload(payload) {

    payload =
        (payload || "").trim();


    // --------------------------------------------------------
    // Validate payload
    // --------------------------------------------------------

    if (!payload) {

        return;
    }


    try {

        // ----------------------------------------------------
        // Send QR payload to Flask API
        // ----------------------------------------------------

        const response =
            await fetch(
                "/api/analyze-qr",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        payload: payload
                    })

                }
            );


        // ----------------------------------------------------
        // Convert response to JSON
        // ----------------------------------------------------

        const data =
            await response.json();


        // ----------------------------------------------------
        // Handle API error
        // ----------------------------------------------------

        if (!response.ok) {

            alert(
                data.error ||
                "Unable to analyze QR code."
            );

            return;
        }


        // ----------------------------------------------------
        // Display result
        // ----------------------------------------------------

        displayResult(data);


    } catch (error) {

        console.error(
            "Analysis error:",
            error
        );


        alert(
            "Unable to connect to Digital Guardian."
        );
    }
}


// ============================================================
// DISPLAY ANALYSIS RESULT
// ============================================================

function displayResult(data) {

    // --------------------------------------------------------
    // Show result box
    // --------------------------------------------------------

    resultBox.classList.remove("hidden");


    // --------------------------------------------------------
    // Payload type
    // --------------------------------------------------------

    resultType.textContent =
        data.qr_analysis.payload_type ||
        "Unknown";


    // --------------------------------------------------------
    // Destination
    // --------------------------------------------------------

    resultUrl.textContent =
        data.qr_analysis.url ||
        data.qr_analysis.payload ||
        "No destination";


    // --------------------------------------------------------
    // Clear previous indicators
    // --------------------------------------------------------

    resultIndicators.innerHTML = "";


    // --------------------------------------------------------
    // Get indicators
    // --------------------------------------------------------

    const indicators =
        data.qr_analysis.indicators || [];


    // --------------------------------------------------------
    // No indicators
    // --------------------------------------------------------

    if (indicators.length === 0) {

        const li =
            document.createElement("li");


        li.textContent =
            "No QR-specific suspicious indicators were detected.";


        resultIndicators.appendChild(li);

    }


    // --------------------------------------------------------
    // Display indicators
    // --------------------------------------------------------

    else {

        indicators.forEach(
            function(indicator) {

                const li =
                    document.createElement("li");


                li.textContent =
                    indicator;


                resultIndicators.appendChild(li);

            }
        );
    }


    // --------------------------------------------------------
    // Enable destination button only for HTTP/HTTPS URLs
    // --------------------------------------------------------

    if (
        data.qr_analysis.url &&
        (
            data.qr_analysis.url.startsWith(
                "http://"
            ) ||

            data.qr_analysis.url.startsWith(
                "https://"
            )
        )
    ) {

        openSafeButton.disabled =
            false;


        openSafeButton.onclick =
            function() {

                /*
                 * The destination is NOT opened
                 * automatically.
                 *
                 * The user must explicitly press
                 * the button.
                 */

                window.open(
                    data.qr_analysis.url,
                    "_blank",
                    "noopener,noreferrer"
                );

            };


    } else {

        openSafeButton.disabled =
            true;


        openSafeButton.onclick =
            null;
    }
}


// ============================================================
// MANUAL QR ANALYSIS
// ============================================================

analyzeManualButton.addEventListener(
    "click",
    function() {

        const payload =
            manualPayload.value.trim();


        // ----------------------------------------------------
        // Empty input
        // ----------------------------------------------------

        if (!payload) {

            alert(
                "Enter a URL or QR payload first."
            );

            return;
        }


        // ----------------------------------------------------
        // Analyze
        // ----------------------------------------------------

        analyzePayload(payload);

    }
);


// ============================================================
// START CAMERA BUTTON
// ============================================================

startButton.addEventListener(
    "click",
    function() {

        startCamera();

    }
);


// ============================================================
// STOP CAMERA BUTTON
// ============================================================

stopButton.addEventListener(
    "click",
    function() {

        stopCamera();

    }
);


// ============================================================
// CLEANUP WHEN PAGE IS CLOSED
// ============================================================

window.addEventListener(
    "beforeunload",
    function() {

        stopCamera();

    }
);

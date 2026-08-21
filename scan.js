/* ==========================================
        scan.js
        Malware Detection Scanner
========================================== */


// ==========================================
// LOGIN PROTECTION
// ==========================================

if (localStorage.getItem("loggedIn") !== "true") {

    window.location.href = "login.html";

}


// ==========================================
// DISPLAY USERNAME
// ==========================================

const storedUser = JSON.parse(
    localStorage.getItem("user")
);

if (
    storedUser &&
    document.getElementById("username")
) {

    document.getElementById("username").textContent =
        storedUser.fullname;

}


// ==========================================
// LIVE CLOCK
// ==========================================

function updateClock() {

    const now = new Date();

    const clock =
        document.getElementById("clock");

    if (clock) {

        clock.textContent =
            now.toLocaleTimeString();

    }

}

setInterval(updateClock, 1000);

updateClock();


// ==========================================
// LOGOUT
// ==========================================

const logoutBtn =
    document.getElementById("logoutBtn");

if (logoutBtn) {

    logoutBtn.addEventListener("click", function () {

        localStorage.removeItem("loggedIn");
        localStorage.removeItem("user");
        localStorage.removeItem("currentUser");

        window.location.href = "login.html";

    });

}


// ==========================================
// FILE INPUT ELEMENTS
// ==========================================

const fileInput =
    document.getElementById("fileInput");

const fileName =
    document.getElementById("fileName");

const fileSize =
    document.getElementById("fileSize");

const fileExtension =
    document.getElementById("fileExtension");

const lastModified =
    document.getElementById("lastModified");


// ==========================================
// DISPLAY FILE INFORMATION
// ==========================================

function displayFileInformation(file) {

    if (!file) return;

    fileName.textContent =
        file.name;

    fileSize.textContent =
        (file.size / 1024).toFixed(2) + " KB";

    const extension =
        file.name.includes(".")
            ? file.name.substring(
                file.name.lastIndexOf(".")
            )
            : "No extension";

    fileExtension.textContent =
        extension;

    lastModified.textContent =
        new Date(
            file.lastModified
        ).toLocaleString();

}


// ==========================================
// FILE SELECTION
// ==========================================

if (fileInput) {

    fileInput.addEventListener(
        "change",
        function () {

            const file =
                this.files[0];

            if (!file) return;

            displayFileInformation(file);

        }
    );

}


// ==========================================
// DRAG AND DROP
// ==========================================

const dropArea =
    document.getElementById("dropArea");

if (dropArea) {

    dropArea.addEventListener(
        "dragover",
        function (event) {

            event.preventDefault();

            dropArea.style.borderColor =
                "#00d4ff";

        }
    );


    dropArea.addEventListener(
        "dragleave",
        function () {

            dropArea.style.borderColor =
                "#0b3d91";

        }
    );


    dropArea.addEventListener(
        "drop",
        function (event) {

            event.preventDefault();

            dropArea.style.borderColor =
                "#0b3d91";

            const files =
                event.dataTransfer.files;

            if (!files || files.length === 0) {
                return;
            }

            const file =
                files[0];

            try {

                fileInput.files =
                    files;

            } catch (error) {

                console.log(
                    "Could not assign dropped file."
                );

            }

            displayFileInformation(file);

        }
    );

}


// ==========================================
// DOWNLOAD REPORT
// ==========================================

const reportBtn =
    document.getElementById(
        "downloadReport"
    );

if (reportBtn) {

    reportBtn.addEventListener(
        "click",
        function () {

            const scanId = localStorage.getItem("lastScanId");
            if (!scanId) {
                alert("Run a scan first to generate its PDF report.");
                return;
            }
            window.open("http://127.0.0.1:5000/report/" + scanId + "/pdf", "_blank");

        }
    );

}


// ==========================================
// SCAN ELEMENTS
// ==========================================

const scanButton =
    document.getElementById("scanBtn");

const progressBar =
    document.getElementById("progress");

const statusText =
    document.getElementById("status");

const logBox =
    document.getElementById("logBox");

const filesChecked =
    document.getElementById("files");

const threatsFound =
    document.getElementById("threats");

const prediction =
    document.getElementById("prediction");

const confidence =
    document.getElementById("confidence");

const riskLevel =
    document.getElementById("riskLevel");

const historyTable =
    document.getElementById("historyTable");


// ==========================================
// ADD LOG MESSAGE
// ==========================================

function addLog(message) {

    if (!logBox) return;

    const time =
        new Date().toLocaleTimeString();

    logBox.innerHTML += `
        <p>[${time}] ${message}</p>
    `;

    logBox.scrollTop =
        logBox.scrollHeight;

}


// ==========================================
// START SCAN
// ==========================================

if (scanButton) {

    scanButton.addEventListener(
        "click",
        startScan
    );

}


function startScan() {

    if (
        !fileInput ||
        fileInput.files.length === 0
    ) {

        alert(
            "Please select a file first."
        );

        return;

    }


    // Reset interface

    progressBar.style.width =
        "0%";

    statusText.textContent =
        "Initializing Scan...";

    logBox.innerHTML =
        "<p>[System] Initializing scan...</p>";

    filesChecked.textContent =
        "0";

    threatsFound.textContent =
        "0";

    prediction.textContent =
        "Scanning...";

    confidence.textContent =
        "0%";


    scanButton.disabled =
        true;


    scanButton.innerHTML = `
        <i class="fa-solid fa-spinner fa-spin"></i>
        Scanning...
    `;


    let progress = 0;


    const steps = [

        "Loading selected file...",

        "Extracting file metadata...",

        "Calculating file entropy...",

        "Checking file activity...",

        "Checking rename activity...",

        "Analyzing file characteristics...",

        "Extracting machine learning features...",

        "Preparing Random Forest model...",

        "Running malware detection model...",

        "Generating final prediction..."

    ];


    let currentStep = 0;


    const scanInterval =
        setInterval(function () {

            progress += 10;


            if (progressBar) {

                progressBar.style.width =
                    progress + "%";

            }


            if (statusText) {

                statusText.textContent =
                    progress +
                    "% Completed";

            }


            if (steps[currentStep]) {

                addLog(
                    steps[currentStep]
                );

            }


            currentStep++;


            if (progress >= 100) {

                clearInterval(
                    scanInterval
                );

                finishScan();

            }

        }, 500);

}


// ==========================================
// SEND FILE TO FLASK BACKEND
// ==========================================

function finishScan() {

    const selectedFile =
        fileInput.files[0];


    if (!selectedFile) {

        resetScanButton();

        alert(
            "No file selected."
        );

        return;

    }


    const formData =
        new FormData();


    formData.append(
        "file",
        selectedFile
    );


    addLog(
        "Uploading file to malware detection backend..."
    );


    /*
    IMPORTANT:

    Your Flask app currently has:

        POST /scan

    Therefore we MUST send the file to:

        http://127.0.0.1:5000/scan
    */


    fetch(
        "http://127.0.0.1:5000/scan",
        {

            method: "POST",

            body: formData

        }
    )


    // ======================================
    // HANDLE SERVER RESPONSE
    // ======================================

    .then(async function (response) {

        let data;

        try {

            data =
                await response.json();

        }

        catch (error) {

            throw new Error(
                "The backend returned an invalid response."
            );

        }


        if (!response.ok) {

            throw new Error(
                data.message ||
                "Backend returned HTTP " +
                response.status
            );

        }


        return data;

    })


    // ======================================
    // DISPLAY RESULT
    // ======================================

    .then(function (data) {

        console.log(
            "Backend response:",
            data
        );


        if (data.success === false) {

            throw new Error(
                data.message ||
                "Scan failed."
            );

        }


        // Files scanned

        if (filesChecked) {

            filesChecked.textContent =
                "1";

        }


        // Prediction

        const result =
            data.prediction ||
            "Unknown";


        if (prediction) {

            prediction.textContent =
                result;

        }


        // Threat count

        if (threatsFound) {

            if (
                result.toLowerCase()
                    === "malware"
            ) {

                threatsFound.textContent =
                    "1";

            }

            else {

                threatsFound.textContent =
                    "0";

            }

        }


        // Confidence

        if (confidence) {

            const confidenceValue =
                data.confidence !== undefined
                    ? data.confidence
                    : 0;

            confidence.textContent =
                confidenceValue + "%";

        }


        // Risk level

        if (riskLevel) {

            const risk =
                data.risk ||
                data.threat_level ||
                "UNKNOWN";


            riskLevel.textContent =
                risk;


            if (
                risk.toUpperCase()
                    === "HIGH"
            ) {

                riskLevel.className =
                    "risk high";

            }

            else if (
                risk.toUpperCase()
                    === "MEDIUM"
            ) {

                riskLevel.className =
                    "risk medium";

            }

            else {

                riskLevel.className =
                    "risk low";

            }

        }


        // Behaviour features
        const features = data;
        const featureMap = {
            writeCount: features.write_count,
            deleteCount: features.delete_count,
            createCount: features.create_count,
            renameCount: features.rename_count,
            writeEntropy: features.write_entropy,
            extDiversity: features.ext_diversity,
            sensitivePath: features.sensitive_path_access,
            readWriteRatio: features.read_write_ratio
        };
        Object.keys(featureMap).forEach(function(id) {
            const el = document.getElementById(id);
            if (el) el.textContent = featureMap[id];
        });

        if (data.scan_id) {
            localStorage.setItem("lastScanId", data.scan_id);
        }


        // Scan status

        if (statusText) {

            statusText.textContent =
                "Scan Completed Successfully.";

        }


        addLog(
            "Backend analysis completed."
        );


        addLog(
            "Prediction: " +
            result
        );


        if (data.confidence !== undefined) {

            addLog(
                "Confidence: " +
                data.confidence +
                "%"
            );

        }


        addLog(
            "File: " +
            selectedFile.name
        );


        // Add history

        addHistory();


        // Reset button

        resetScanButton();

    })


    // ======================================
    // ERROR HANDLING
    // ======================================

    .catch(function (error) {

        console.error(
            "SCAN ERROR:",
            error
        );


        if (statusText) {

            statusText.textContent =
                "Scan Failed.";

        }


        addLog(
            "ERROR: " +
            error.message
        );


        resetScanButton();


        alert(
            "Scan failed: " +
            error.message
        );

    });

}


// ==========================================
// RESET SCAN BUTTON
// ==========================================

function resetScanButton() {

    if (!scanButton) return;

    scanButton.disabled =
        false;

    scanButton.innerHTML = `
        <i class="fa-solid fa-play"></i>
        Start Scan
    `;

}


// ==========================================
// ADD SCAN HISTORY
// ==========================================

function addHistory() {

    if (!historyTable) return;


    const file =
        fileName.textContent;


    const status =
        prediction.textContent;


    const time =
        new Date().toLocaleTimeString();


    if (
        historyTable.innerHTML
            .includes("No scans yet")
    ) {

        historyTable.innerHTML =
            "";

    }


    const row =
        document.createElement("tr");


    const statusClass =
        status.toLowerCase()
            === "safe"
            ? "low"
            : "high";


    row.innerHTML = `

        <td>
            ${file}
        </td>

        <td>

            <span class="${statusClass}">

                ${status}

            </span>

        </td>

        <td>
            ${time}
        </td>

    `;


    historyTable.prepend(row);

}
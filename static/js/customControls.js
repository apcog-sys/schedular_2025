
class VenueControl extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: "open" });

        this.shadowRoot.innerHTML = `
            <style>
                .venue-container { padding: 10px; border: 1px solid #ccc; border-radius: 5px; background: #f9f9f9; }
                .venue-container label { display: block; margin-top: 10px; font-weight: bold; }
                .venue-container input { width: 100%; padding: 5px; margin-top: 5px; }
            </style>
            <div class="venue-container">
                <label>Building: <input type="text" id="building"></label>
                <label>Street: <input type="text" id="street"></label>
                <label>Area: <input type="text" id="area"></label>
                <label>City: <input type="text" id="city"></label>
                <label>State: <input type="text" id="state"></label>
                <label>Country: <input type="text" id="country"></label>
                <label>URL Address: <input type="url" id="url_address"></label>
                <label>Latitude: <input type="text" id="latitude"></label>
                <label>Longitude: <input type="text" id="longitude"></label>
            </div>
        `;
    }

    // **Populate venue details if data exists**
    set value(venueData) {
        if (!venueData) return;
        if (typeof venueData === "string") venueData = JSON.parse(venueData);

        this.shadowRoot.getElementById("building").value = venueData.building || "";
        this.shadowRoot.getElementById("street").value = venueData.street || "";
        this.shadowRoot.getElementById("area").value = venueData.area || "";
        this.shadowRoot.getElementById("city").value = venueData.city || "";
        this.shadowRoot.getElementById("state").value = venueData.state || "";
        this.shadowRoot.getElementById("country").value = venueData.country || "";
        this.shadowRoot.getElementById("url_address").value = venueData.url_address || "";
        this.shadowRoot.getElementById("latitude").value = venueData.latitude || "";
        this.shadowRoot.getElementById("longitude").value = venueData.longitude || "";
    }

    // **Get venue data as JSON**
    get value() {
        return JSON.stringify({
            building: this.shadowRoot.getElementById("building").value,
            street: this.shadowRoot.getElementById("street").value,
            area: this.shadowRoot.getElementById("area").value,
            city: this.shadowRoot.getElementById("city").value,
            state: this.shadowRoot.getElementById("state").value,
            country: this.shadowRoot.getElementById("country").value,
            url_address: this.shadowRoot.getElementById("url_address").value,
            latitude: this.shadowRoot.getElementById("latitude").value,
            longitude: this.shadowRoot.getElementById("longitude").value
        });
    }
}

// **Register the custom element**
customElements.define("venue-control", VenueControl);



class ScheduleControl extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: "open" });

        this.schedule = {}; // Object to store schedule data

        this.shadowRoot.innerHTML = `
            <style>
                .schedule-container { padding: 10px; border: 1px solid #ccc; border-radius: 5px; background: #f9f9f9; }
                .date-container { display: flex; justify-content: space-between; margin-bottom: 10px; }
                .date-container label { font-weight: bold; }
                .day-entry { display: flex; align-items: center; margin-bottom: 5px; }
                .day-entry select, .day-entry input { margin-right: 5px; }
                .remove-btn { background: red; color: white; border: none; cursor: pointer; padding: 3px 6px; border-radius: 3px; }
            </style>
            <div class="schedule-container">
                <div class="date-container">
                    <label>Start Date: <input type="date" id="startDate"></label>
                    <label>End Date: <input type="date" id="endDate"></label>
                </div>
                <label>Work Days & Timings:</label>
                <div id="scheduleList"></div>
                <button id="addScheduleBtn">+ Add Work Day</button>
            </div>
        `;

        this.scheduleList = this.shadowRoot.getElementById("scheduleList");
        this.startDateInput = this.shadowRoot.getElementById("startDate");
        this.endDateInput = this.shadowRoot.getElementById("endDate");
        this.shadowRoot.getElementById("addScheduleBtn").addEventListener("click", () => this.addScheduleRow());
    }

    // **✅ Populate schedule if data exists, otherwise prepare for input**
    set value(scheduleData) {
        if (!scheduleData) {
            console.warn("No schedule data provided. Initializing empty fields.");
            return;
        }

        if (typeof scheduleData === "string") {
            try {
                scheduleData = JSON.parse(scheduleData);
            } catch (e) {
                console.error("Invalid JSON schedule data:", e);
                return;
            }
        }

        // Populate dates if available
        if (scheduleData.startDate) this.startDateInput.value = scheduleData.startDate;
        if (scheduleData.endDate) this.endDateInput.value = scheduleData.endDate;

        // Populate work days if available, otherwise leave empty
        this.scheduleList.innerHTML = "";
        if (scheduleData.workDays && Object.keys(scheduleData.workDays).length > 0) {
            for (let day in scheduleData.workDays) {
                scheduleData.workDays[day].forEach(([startTime, endTime]) => {
                    this.addScheduleRow(day, startTime, endTime);
                });
            }
        }
        scheduleData={}
    }

    // **✅ Add a new work day row for input**
    addScheduleRow(day = "", startTime = "", endTime = "") {
        const row = document.createElement("div");
        row.className = "day-entry";

        const daySelect = document.createElement("select");
        ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"].forEach((dayName) => {
            const option = document.createElement("option");
            option.value = dayName.toLowerCase();
            option.textContent = dayName;
            if (day === option.value) option.selected = true;
            daySelect.appendChild(option);
        });

        const startInput = document.createElement("input");
        startInput.type = "time";
        startInput.className = "start-time";
        startInput.value = startTime;

        const endInput = document.createElement("input");
        endInput.type = "time";
        endInput.className = "end-time";
        endInput.value = endTime;

        const removeBtn = document.createElement("button");
        removeBtn.className = "remove-btn";
        removeBtn.textContent = "X";
        removeBtn.addEventListener("click", () => this.removeScheduleRow(row));

        row.appendChild(daySelect);
        row.appendChild(startInput);
        row.appendChild(endInput);
        row.appendChild(removeBtn);

        this.scheduleList.appendChild(row);
    }

    // **✅ Remove a schedule entry**
    removeScheduleRow(row) {
        this.scheduleList.removeChild(row);
    }

    // **✅ Get schedule data as JSON**

    get value() {
        let scheduleData = {};
        this.scheduleList.childNodes.forEach((row) => {
            console.log("Row data :::",row.children[0],row.children[1],row.children[2])
            const day = row.querySelector("select")?.value;
            const startTime = row.querySelector(".start-time")?.value;
            const endTime = row.querySelector(".end-time")?.value;
            console.log(day,startTime,endTime);
            if (day && startTime && endTime) {
                if (!scheduleData[day]) scheduleData[day] = [];
                scheduleData[day].push([startTime, endTime]);
            }
        });
        return JSON.stringify({
            startDate: this.shadowRoot.getElementById("startDate").value,
            endDate: this.shadowRoot.getElementById("endDate").value,
            workDays: scheduleData
        });
    }
}

// **✅ Register the custom element**
customElements.define("schedule-control", ScheduleControl);

class AttachmentControl extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: "open" });
        this.shadowRoot.innerHTML = `
            <style>
                .attachment-container { padding: 10px; border: 1px solid #ccc; border-radius: 5px; background: #f9f9f9; text-align: center; }
                
                video, canvas, audio, img { margin-top: 10px; width: 100%; max-width: 300px; display: none; }
                input, select { display: block; margin: 10px auto; align-items: left; }
                .image-wrapper, 
                .video-wrapper,
                .audio-wrapper{
                    position: relative;
                    display: flex;
                    flex-grow: 1;  // Allow elements to expand inside a flex container 
                    justify-content: left;
                    align-items: left;
                   
                }
                .fileWrapper{
                    position: relative;
                    display: flex;
                    flex-grow: 1;  // Allow elements to expand inside a flex container 
                    justify-content: left;
                    align-items: left;
                   
                }
               .delete-fileWrapper-btn {
                    background: rgba(255, 255, 255, 0.8);
                    color: white;
                    border: none;
                    border-radius: 5px;
                    width: 20px;
                    height: 20px;
                    font-size: 12px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 0;
                    margin-right: 8px; // Adds space between button and filename 
                    z-index: 10;
                }

                

                .delete-btn {
                    position: absolute;
                    top: 5px;
                    right: 5px;
                    background: rgba(255, 255, 255, 0.8);
                    color: white;
                    border: none;
                    border-radius: 50%;
                    width: 20px;
                    position: absolute;
                    height: 20px;
                    font-size: 12px;
                    cursor: pointer;
                    display: flex;
                    align-items: left;
                    justify-content: left;
                    padding: 0;
                    left: 5px;  // Move the button to the left 
                    top: 5px;
                    z-index: 10;
                    border-radius: 5px;
                }

                .delete-btn:hover {
                    background: rgba(255, 0, 0, 1);
                }
               

                #file_save-as-pdf,
                #image_save-as-pdf,
                #audio_save-as-pdf,
                #video_save-as-pdf {
                    margin-right: 5px;
                }
            </style>
            <div class="attachment-container">
               
                <div id="fileContainer" style="display:none;">
                    <input type="file" id="fileInput" multiple style="display:block;"  style="align-items=left;  text-align=left; ">
                    <div id="fileList"></div>
                    <div id="file_pdf">
                        <!--  <input type="checkbox" id="file_save-as-pdf"> Save as PDF -->
                    </div>
                </div>
                <div id="imageCaptureContainer" style="display:none;">
                    <video autoplay></video>
                    <button id="captureImage"  style="align-items=left;  text-align=left; ">Capture Image</button>
                    <div id="imageList"></div>
                    <div id="image_pdf">
                        <!--  <input type="checkbox" id="image_save-as-pdf"> Save as PDF -->
                    </div>
                </div>

                <div id="recordedAudiosContainer" style="display:none;">
                    <button id="toggleRecording"  style="align-items=left;  text-align=left; ">🎤 Start Recording</button>
                    <audio controls></audio>
                    <div id="audioList"></div>
                    <div id="audio_pdf">
                        <!--  <input type="checkbox" id="audio_save-as-pdf"> Save as PDF -->
                    </div>
                </div>

                <div id="videoRecordContainer" style="display:none;">
                    <video autoplay></video>
                    <button id="toggleVideoRecording"  style="align-items=left;  text-align=left; ">🎬 Start Recording</button>
                    <video id="recordedVideo" controls></video>
                    <div id="videoList"></div>
                    <div id="video_pdf">
                        <!--  <input type="checkbox" id="video_save-as-pdf"> Save as PDF -->
                    </div>
                </div>

                <div id="qrCodeContainer" style="display:none;">
                    <input type="text" id="qrText" placeholder="Enter text for QR">
                    <button id="generateQR">Generate QR Code</button>
                    <div id="qrCode"></div>
                </div>
            </div>


        `;
        this.init();
    }

    init() {
       
        
        this.fileInput = this.shadowRoot.getElementById("fileContainer");
        this.fileList = this.shadowRoot.getElementById("fileList");
        
        this.imageCaptureContainer = this.shadowRoot.getElementById("imageCaptureContainer");
        this.video_image = this.shadowRoot.querySelector("#imageCaptureContainer video");
        this.captureImageBtn = this.shadowRoot.getElementById("captureImage");
        this.imageList = this.shadowRoot.getElementById("imageList");

        this.audioContainer = this.shadowRoot.getElementById("recordedAudiosContainer");
        this.audioButton = this.shadowRoot.getElementById("toggleRecording");
        this.audioElement = this.shadowRoot.querySelector("audio");
        this.audioList = this.shadowRoot.getElementById("audioList");

        this.videoContainer = this.shadowRoot.getElementById("videoRecordContainer");
        this.video = this.shadowRoot.querySelector("#videoRecordContainer video");
        this.videoRecordButton = this.shadowRoot.getElementById("toggleVideoRecording");
        this.recordedVideo = this.shadowRoot.getElementById("recordedVideo");
        this.videoList = this.shadowRoot.getElementById("videoList");
        
        this.captureImageBtn.addEventListener("click", () => this.captureImage());
        this.audioButton.addEventListener("click", () => this.toggleAudioRecording());
        this.videoRecordButton.addEventListener("click", () => this.toggleVideoRecording());

        this.qrCodeContainer = this.shadowRoot.getElementById("qrCodeContainer");
        this.qrCodeDiv = this.shadowRoot.getElementById("qrCode");
       // this.qr_fileInput.addEventListener("change", (event) => this.generateQRCode(event));
    }
        
    // Handle dropdown selection change
    handleSelection(typedata) {
        console.log(typedata)
        //let type = this.attachmentType.value;
        let type = typedata;

        // Hide/show respective input areas
        //this.fileInput.style.display = type === "file" ? "block" : "none";
        this.fileInput.style.display = "block" ;
        this.imageCaptureContainer.style.display = type === "image" ? "block" : "none";
        this.audioContainer.style.display = type === "audio" ? "block" : "none";
        this.videoContainer.style.display = type === "video" ? "block" : "none";

        // Stop the live video feed if a new selection is made
        if (this.mediaStream) {
            this.mediaStream.getTracks().forEach(track => track.stop());
            this.mediaStream = null;
        }

         // Handle file selection
        //if (type === "file") {
            this.shadowRoot.getElementById("fileContainer").addEventListener("change", (event) => {
                this.fileList.innerHTML = ""; // Clear previous file list
                Array.from(event.target.files).forEach((file) => {
                    let fileWrapper = document.createElement("div");
                    fileWrapper.classList.add("fileWrapper");

                    let deleteBtn = document.createElement("button");
                    deleteBtn.textContent = "❌";
                    deleteBtn.classList.add("delete-fileWrapper-btn");
                    deleteBtn.addEventListener("click", () => fileWrapper.remove());

                    let fileName = document.createElement("span");
                    fileName.textContent = file.name;

                    // Append elements in correct order
                    fileWrapper.appendChild(deleteBtn);
                    fileWrapper.appendChild(fileName);
                    
                    
                    this.fileList.appendChild(fileWrapper);
                });
            });
        //}

        // Handle image capture
        if (type === "image") {
            this.shadowRoot.getElementById("fileContainer").addEventListener("change", (event) => {
                this.fileList.innerHTML = ""; // Clear previous file list
                Array.from(event.target.files).forEach((file) => {
                    let fileWrapper = document.createElement("div");
                    fileWrapper.classList.add("fileWrapper");

                    let deleteBtn = document.createElement("button");
                    deleteBtn.textContent = "❌";
                    deleteBtn.classList.add("delete-fileWrapper-btn");
                    deleteBtn.addEventListener("click", () => fileWrapper.remove());

                    let fileName = document.createElement("span");
                    fileName.textContent = file.name;

                    // Append elements in correct order
                    fileWrapper.appendChild(deleteBtn);
                    fileWrapper.appendChild(fileName);
                    
                    
                    this.fileList.appendChild(fileWrapper);
                });
            });
            navigator.mediaDevices.getUserMedia({ video: true }).then(stream => {
                this.video_image.srcObject = stream;
                this.video_image.style.display = "block";
                this.mediaStream = stream;
            }).catch(console.error);
        }

        // Handle video capture
        if (type === "video") {
            this.shadowRoot.getElementById("fileContainer").addEventListener("change", (event) => {
                this.fileList.innerHTML = ""; // Clear previous file list
                Array.from(event.target.files).forEach((file) => {
                    let fileWrapper = document.createElement("div");
                    fileWrapper.classList.add("fileWrapper");

                    let deleteBtn = document.createElement("button");
                    deleteBtn.textContent = "❌";
                    deleteBtn.classList.add("delete-fileWrapper-btn");
                    deleteBtn.addEventListener("click", () => fileWrapper.remove());

                    let fileName = document.createElement("span");
                    fileName.textContent = file.name;

                    // Append elements in correct order
                    fileWrapper.appendChild(deleteBtn);
                    fileWrapper.appendChild(fileName);
                    
                    
                    this.fileList.appendChild(fileWrapper);
                });
            });
            navigator.mediaDevices.getUserMedia({ video: true }).then(stream => {
                this.video.srcObject = stream;
                this.video.style.display = "block";
                this.mediaStream = stream;
            }).catch(console.error);
        }

        // Handle QR Code selection
        if (type === "qr") {
            this.fileInput.addEventListener("change", () => this.generateQRCode());
        }
    }

    captureImage() {
    let canvas = document.createElement("canvas");
    let ctx = canvas.getContext("2d");
    canvas.width = this.video_image.videoWidth;
    canvas.height = this.video_image.videoHeight;
    ctx.drawImage(this.video_image, 0, 0, canvas.width, canvas.height);

    let imgWrapper = document.createElement("div");
    imgWrapper.classList.add("image-wrapper");

    let img = document.createElement("img");
    img.src = canvas.toDataURL("image/png");
    img.style.width = "100px";
    img.style.margin = "5px";
    img.style.display = "block"; 

    let deleteBtn = document.createElement("button");
    deleteBtn.textContent = "❌";
    deleteBtn.classList.add("delete-btn");
    deleteBtn.addEventListener("click", () => imgWrapper.remove());
    imgWrapper.appendChild(deleteBtn);
    imgWrapper.appendChild(img);
    
    this.imageList.appendChild(imgWrapper);
}

    generateQRCode(event) {
            let file = event.target.files[0];
            if (!file) return;
            
            let fileType = file.type.split("/")[0];
            if (fileType === "audio" || fileType === "video") {
                alert("Audio and video files are not supported for QR code generation.");
                return;
            }
            
            let reader = new FileReader();
            reader.onload = () => {
                this.qrCodeContainer.style.display = "block";
                this.qrCodeDiv.innerHTML = "";
                new QRCode(this.qrCodeDiv, {
                    text: reader.result,
                    width: 200,
                    height: 200
                });
            };
            reader.readAsText(file);
        }

    toggleAudioRecording() {
        if (!this.mediaRecorder || this.mediaRecorder.state === "inactive") {
            navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
                this.mediaRecorder = new MediaRecorder(stream);
                this.audioChunks = [];

                this.mediaRecorder.ondataavailable = event => this.audioChunks.push(event.data);
                this.mediaRecorder.onstop = () => {
                    let audioBlob = new Blob(this.audioChunks, { type: "audio/webm" });
                    let audioURL = URL.createObjectURL(audioBlob);

                    let recordedAudiosContainer = document.getElementById("recordedAudiosContainer");
                    if (!recordedAudiosContainer) {
                        recordedAudiosContainer = document.createElement("div");
                        recordedAudiosContainer.id = "recordedAudiosContainer";
                        document.body.appendChild(recordedAudiosContainer);
                    }

                    let audioWrapper = document.createElement("div");
                    audioWrapper.classList.add("audio-wrapper");

                    let recordedAudio = document.createElement("audio");
                    recordedAudio.src = audioURL;
                    recordedAudio.controls = true;
                    recordedAudio.style.display = "block";

                    let deleteBtn = document.createElement("button");
                    deleteBtn.textContent = "❌";
                    deleteBtn.classList.add("delete-btn");
                    deleteBtn.addEventListener("click", () => audioWrapper.remove());
                    audioWrapper.appendChild(deleteBtn);
                    audioWrapper.appendChild(recordedAudio);
                    
                    this.audioList.appendChild(audioWrapper);
                };

                this.mediaRecorder.start();
                this.audioButton.textContent = "🛑 Stop Recording";
            });
        } else {
            this.mediaRecorder.stop();
            this.audioButton.textContent = "🎤 Start Recording";
        }
    }

    toggleVideoRecording() {
        if (!this.videoRecorder || this.videoRecorder.state === "inactive") {
            // Start recording
            navigator.mediaDevices.getUserMedia({ video: true, audio: true }).then(stream => {
                if (!this.mediaStream) {  // Ensure the preview runs only once
                    this.video.srcObject = stream;
                    this.video.style.display = "block";
                    this.mediaStream = stream;
                }
                
                this.videoRecorder = new MediaRecorder(stream);
                this.videoChunks = [];

                this.videoRecorder.ondataavailable = event => this.videoChunks.push(event.data);
                this.videoRecorder.onstop = () => {
                    let videoBlob = new Blob(this.videoChunks, { type: "video/webm" });
                    let videoURL = URL.createObjectURL(videoBlob);

                    let recordedVideosContainer = document.getElementById("recordedVideosContainer");
                    if (!recordedVideosContainer) {
                        recordedVideosContainer = document.createElement("div");
                        recordedVideosContainer.id = "recordedVideosContainer";
                        document.body.appendChild(recordedVideosContainer);
                    }

                    let videoWrapper = document.createElement("div");
                    videoWrapper.classList.add("video-wrapper");

                    let recordedVideo = document.createElement("video");
                    recordedVideo.src = videoURL;
                    recordedVideo.controls = true;
                    recordedVideo.style.display = "block";
                    recordedVideo.style.width = "100%";

                    let deleteBtn = document.createElement("button");
                    deleteBtn.textContent = "❌";
                    deleteBtn.classList.add("delete-btn");
                    deleteBtn.addEventListener("click", () => videoWrapper.remove());

                    videoWrapper.appendChild(deleteBtn);
                    videoWrapper.appendChild(recordedVideo);
                    this.videoList.appendChild(videoWrapper);
                };

                this.videoRecorder.start();
                this.videoRecordButton.textContent = "🛑 Stop Recording";
            }).catch(console.error);
        } else {
            // Stop recording, but keep the live preview ON
            this.videoRecorder.stop();
            this.videoRecordButton.textContent = "🎬 Start Recording";
        }
    }
    
    
}
customElements.define("attachment-control", AttachmentControl);



/*
class AttachmentControl extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: "open" });
        this.attachmentType = this.getAttribute("type") || "file"; // Get type from attribute
        this.render();
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>
                :host {
                    display: block;
                    font-family: Arial, sans-serif;
                }
                .container {
                    margin: 10px 0;
                }
                button {
                    margin: 5px;
                    padding: 5px 10px;
                    cursor: pointer;
                }
                video, audio {
                    display: block;
                    margin-top: 10px;
                    width: 100%;
                    max-width: 300px;
                }
            </style>
            <div class="container">
                <input type="file" id="fileInput" hidden />
                <button id="chooseFile">Choose File</button>
                <button id="capture" hidden>Capture</button>
                <video id="videoPreview" autoplay playsinline hidden></video>
                <audio id="audioPreview" controls hidden></audio>
            </div>
        `;

        this.fileInput = this.shadowRoot.getElementById("fileInput");
        this.chooseFileButton = this.shadowRoot.getElementById("chooseFile");
        this.captureButton = this.shadowRoot.getElementById("capture");
        this.videoPreview = this.shadowRoot.getElementById("videoPreview");
        this.audioPreview = this.shadowRoot.getElementById("audioPreview");

        this.setupUI();
        this.addEventListeners();
    }

    setupUI() {
        if (this.attachmentType === "image" || this.attachmentType === "video") {
            this.captureButton.hidden = false;
            this.captureButton.textContent = "Capture";
        } else if (this.attachmentType === "audio") {
            this.captureButton.hidden = false;
            this.captureButton.textContent = "Record Audio";
        }
    }

    addEventListeners() {
        this.chooseFileButton.addEventListener("click", () => this.fileInput.click());
        this.fileInput.addEventListener("change", (event) => this.handleFileSelection(event));
        this.captureButton.addEventListener("click", () => this.startCapture());
    }

    handleFileSelection(event) {
        const file = event.target.files[0];
        console.log("Selected file:", file);
    }

    startCapture() {
        if (this.attachmentType === "image" || this.attachmentType === "video") {
            this.captureMedia("video");
        } else if (this.attachmentType === "audio") {
            this.captureMedia("audio");
        }
    }

    async captureMedia(type) {
        try {
            const stream = await navigator.mediaDevices.getUserMedia(type === "video" ? { video: true } : { audio: true });
            
            if (type === "video") {
                this.videoPreview.srcObject = stream;
                this.videoPreview.hidden = false;
            } else if (type === "audio") {
                this.audioPreview.srcObject = stream;
                this.audioPreview.hidden = false;
            }
        } catch (error) {
            console.error(`Error accessing ${type}:`, error);
        }
    }
}

customElements.define("attachment-control", AttachmentControl);
*/


class QRControl extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.render();
    }

    connectedCallback() {
        this.generateQRCode();
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>
                :host {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    padding: 10px;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                }
                canvas {
                    margin: 10px 0;
                }
                button {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    padding: 8px 12px;
                    cursor: pointer;
                    border-radius: 5px;
                }
                button:hover {
                    background-color: #0056b3;
                }
            </style>
            <input type="text" id="qrInput" placeholder="Enter text for QR Code">
            <button id="generateBtn">Generate QR Code</button>
            <div id="qrContainer"></div>
        `;

        this.shadowRoot.querySelector('#generateBtn').addEventListener('click', () => this.generateQRCode());
    }

    generateQRCode() {
        const qrContainer = this.shadowRoot.querySelector('#qrContainer');
        qrContainer.innerHTML = ''; // Clear previous QR code
        const qrInput = this.shadowRoot.querySelector('#qrInput').value;
        
        if (!qrInput) {
            alert('Please enter text to generate QR code.');
            return;
        }
        
        new QRCode(qrContainer, {
            text: qrInput,
            width: 128,
            height: 128,
        });
    }
}

customElements.define('qr-control', QRControl);



function setSelectedOption(selectId, value) {
    const selectElement = document.getElementById(selectId);
    if (selectElement) {
        selectElement.value = value;
    }
}
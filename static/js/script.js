// Open IndexedDB to store offline requests
const DB_NAME = "OfflineQueueDB";
const STORE_NAME = "requests";
let db;

const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB chunks for file uploads

var sending = false;

function get_data_list(selected_item,where_data){
    document.getElementById("tab_page_header").style.display = "block";
    console.log(selected_item,where_data);
    console.log(selectedItemFromDropdown);
    page_load_conf.event="data_list";
    console.log(">>>>>",  page_load_conf);
    data_list_body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["*"],
            "where_data":where_data
        }
    }
    
    //if(tab_status[page_load_conf.tab]==0){
        console.log(page_load_conf.tab, tab_status[page_load_conf.tab])
        console.log(data_list_body)
        if(selectedItemFromDropdown === "m"){
            fetchData();    
        }
        else if(selected_item) {
            console.log(">>>>>",selected_item)
            data_list_body.type=selected_item;
            data_list_body.tab=page_load_conf.tab;
            console.log(MainConfig[page_load_conf.tab][selected_item].getDataApi)
            API_call(domain,MainConfig[page_load_conf.tab][selected_item].getDataApi,data_list_body,"POST")
        }
        
        else{present_Data({})}
}

function present_Data(data,item) {
    console.log(data, item);
    console.log(selectedItemFromDropdown)
    var display_data;
    var field_data = {}; // Ensure it's initialized properly
    var config_path;
    console.log(page_load_conf.tab)
    if (item !== undefined){display_data=data[0];  
        
        config_path=MainConfig[page_load_conf.tab][item]; 
        selectedItemFromDropdown=item;  
        field_data = config_path.job.list
        console.log(2)
    }
    else{
        display_data=data;  
       // config_path=MainConfig[page_load_conf.tab]; 
       console.log(">>>>>",page_load_conf.tab, MainConfig)
       if (MainConfig[page_load_conf.tab]) {
        config_path = MainConfig[page_load_conf.tab];
        } else {
            console.error("Invalid tab:", page_load_conf.tab);
            return;
        }
        selectedItemFromDropdown=null;  console.log(1);
    }
    //if (item==undefined){display_data=data;  config_path=MainConfig[page_load_conf.tab]; selectedItemFromDropdown=null;  console.log(1)}
    //else{display_data=data[0];  config_path=MainConfig[page_load_conf.tab][item]; selectedItemFromDropdown=item;  console.log(2)}
    console.log(page_load_conf.tab)
    console.log(MainConfig[page_load_conf.tab])
    console.log(config_path)
    /*if (config_path.Roles.includes(role)) {
        field_data = config_path.job.list;
        console.log(field_data);
    }
    else if (role === "Approver") {
        field_data = config_path.approve;
    }*/
    var data_list = {
        tab_name: page_load_conf.tab,
        controls: config_path.controls,
        data: display_data,
        fields: field_data
    };

    console.log(data_list);
    console.log(selectedItemFromDropdown)
    createTable(data_list);
}

function updateEntry(Id, updatedData) {
    let apiEndpoint =""
    var update_body={
        "requestor_id":"",
        "request_token":"",
        "tab":page_load_conf.tab,
        "qry":updatedData
    }
    
    console.log(selectedItemFromDropdown)
    try{
       
        if(selectedItemFromDropdown!=null) {
            
            let key = MainConfig[page_load_conf.tab][selectedItemFromDropdown].key;
            apiEndpoint=domain + MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.update.api;
            update_body[key]=Id;
            update_body.type= selectedItemFromDropdown
            console.log(apiEndpoint,update_body)
        
        }
        else{
            apiEndpoint=MainConfig[page_load_conf.tab+"_config"].job.update.api;
            update_body=MainConfig[page_load_conf.tab+"_config"].key;
        }
    }catch(err){console.log("Error in data extraction",err)}

    
    console.log(update_body)
    var requestData={
        "domain":domain,
        "endpoint":MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.update.api,
        "body":update_body,
        "method":"PUT",
        "file":null,
        "status":"pending"
    }
    console.log(requestData)
    storeRequest(requestData)
   /* fetch(apiEndpoint, {
        method: "PUT",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(update_body)
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert("updated successfully!");
            get_data_list(selectedItemFromDropdown,{});
            } else {
            alert("Update failed: " + (data.message || "Unknown error"));
        }
    })
    .catch(error => {
        console.error("Update request failed:", error);
        alert("An error occurred while updating the entity.");
    });*/
}

function createEntry(newEntry) {
    let apiEndpoint =""
    var creation_body={
        "requestor_id":"",
        "request_token":"",
        "type":"",
        "qry":newEntry
    }
    

    console.log(selectedItemFromDropdown)
    try{
       
        if(selectedItemFromDropdown!=null) {
            apiEndpoint=domain + MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.create.api;
            creation_body.type= selectedItemFromDropdown
            creation_body.tab= page_load_conf.tab
            console.log(apiEndpoint,creation_body)
        
        }
        else{
            apiEndpoint=MainConfig[page_load_conf.tab+"_config"].job.create.api;
            update_body=MainConfig[page_load_conf.tab+"_config"].key;
        }
    }catch(err){console.log("Error in data extraction",err)}


    console.log(creation_body)
    var requestData={
        "domain":domain,
        "endpoint":MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.create.api,
        "body":creation_body,
        "method":"POST",
        "file":null,
        "status":"pending"
    }
    console.log(requestData)
    storeRequest(requestData)
}

/** Function to add a new schedule row **/
 function addScheduleRow() {
    let scheduleContainer = document.getElementById('scheduleContainer');

    let rowDiv = document.createElement('div');
    rowDiv.className = 'd-flex gap-2 align-items-center mb-2 schedule-row';

    // Day Selection
    let daySelect = document.createElement('select');
    daySelect.className = 'form-control day-select';
    ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"].forEach((day, index) => {
        let option = document.createElement('option');
        option.value = index; // Store as number (0=Sunday, 6=Saturday)
        option.textContent = day;
        daySelect.appendChild(option);
    });

    // Start & End Time Inputs
    let startInput = document.createElement('input');
    startInput.type = 'time';
    startInput.className = 'form-control start-time';

    let endInput = document.createElement('input');
    endInput.type = 'time';
    endInput.className = 'form-control end-time';

    // Delete Button
    let deleteButton = document.createElement('button');
    deleteButton.textContent = "X";
    deleteButton.className = 'btn btn-danger btn-sm';
    deleteButton.onclick = function () {
        scheduleContainer.removeChild(rowDiv);
    };

    rowDiv.appendChild(daySelect);
    rowDiv.appendChild(startInput);
    rowDiv.appendChild(endInput);
    rowDiv.appendChild(deleteButton);

    scheduleContainer.appendChild(rowDiv);
}

// Ensure scheduleContainer exists
let scheduleContainer = document.getElementById('scheduleContainer');

// Mapping days to indices (0=Sunday, 6=Saturday)
const dayMapping = {
    "sun": 0,
    "mon": 1,
    "tue": 2,
    "wed": 3,
    "thu": 4,
    "fri": 5,
    "sat": 6
};

// Function to safely parse JSON strings
function safeParse(jsonString) {
    try {
        return JSON.parse(jsonString);
    } catch (e) {
        console.error("Invalid JSON string:", jsonString);
        return null;
    }
}

// Function to populate schedule rows based on workDaysData
function populateSchedule(workDaysData) {
    Object.keys(dayMapping).forEach(dayKey => {
        let dayData = safeParse(workDaysData[dayKey]);
        if (dayData && dayData.timings) {
            dayData.timings.forEach(timeSlot => {
                let startTime = timeSlot[0];
                let endTime = timeSlot[1];
                addScheduleRow(dayKey, startTime, endTime);
            });
        }
    });
}

// Updated addScheduleRow function to accept parameters
function addScheduleRow_edit(dayKey = "", startTime = "", endTime = "") {
    let rowDiv = document.createElement('div');
    rowDiv.className = 'd-flex gap-2 align-items-center mb-2 schedule-row';

    // Day Selection Dropdown
    let daySelect = document.createElement('select');
    daySelect.className = 'form-control day-select';
    let days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    
    days.forEach((day, index) => {
        let option = document.createElement('option');
        option.value = index;  // Store as number (0=Sunday, 6=Saturday)
        option.textContent = day;
        if (dayMapping[dayKey] === index) {
            option.selected = true;
        }
        daySelect.appendChild(option);
    });

    // Start & End Time Inputs
    let startInput = document.createElement('input');
    startInput.type = 'time';
    startInput.className = 'form-control start-time';
    startInput.value = startTime;

    let endInput = document.createElement('input');
    endInput.type = 'time';
    endInput.className = 'form-control end-time';
    endInput.value = endTime;

    // Delete Button
    let deleteButton = document.createElement('button');
    deleteButton.textContent = "X";
    deleteButton.className = 'btn btn-danger btn-sm';
    deleteButton.onclick = function () {
        scheduleContainer.removeChild(rowDiv);
    };

    rowDiv.appendChild(daySelect);
    rowDiv.appendChild(startInput);
    rowDiv.appendChild(endInput);
    rowDiv.appendChild(deleteButton);

    scheduleContainer.appendChild(rowDiv);
}


document.getElementById("toggleButton").addEventListener("click", function () {
    let content = document.getElementById("tab_page_filter");
    content.style.display = (content.style.display === "none" || content.style.display === "") ? "block" : "none";
});


async function viewFile(filename) {
    fetch(`/view_file?filename=${encodeURIComponent(filename)}`)
        .then(response => response.json())
        .then(data => {
            let previewContainer = document.getElementById("filePreviewContainer");
            previewContainer.innerHTML = "";

            if (data.type === "text") {
                let textElement = document.createElement("pre");
                textElement.style.whiteSpace = "pre-wrap";
                textElement.textContent = data.content;
                previewContainer.appendChild(textElement);
            } 
            else if (data.type === "image") {
                let imgElement = document.createElement("img");
                imgElement.src = data.content;
                imgElement.className = "img-fluid rounded";
                previewContainer.appendChild(imgElement);
            } 
            else {
                previewContainer.innerHTML = "<p class='text-danger'>Unsupported file format</p>";
            }

            let previewModal = new bootstrap.Modal(document.getElementById("previewModal"));
            previewModal.show();
        })
        .catch(error => console.error("Error viewing file:", error));
}

function openDB() {
    return new Promise((resolve, reject) => {
        let request = indexedDB.open(DB_NAME, 3);

        request.onupgradeneeded = (event) => {
            let db = event.target.result;

            if (!db.objectStoreNames.contains(STORE_NAME)) {
                let store = db.createObjectStore(STORE_NAME, { keyPath: "id", autoIncrement: true });
                store.createIndex("status", "status", { unique: false });
            }
        };

        request.onsuccess = (event) => {
            resolve(event.target.result);
        };

        request.onerror = (event) => {
            reject("Error opening IndexedDB: " + event.target.error);
        };
    });
}

// Store request offline
async function storeRequest(requestData) {
    let db = await openDB();
    let transaction = db.transaction(STORE_NAME, "readwrite");
    let store = transaction.objectStore(STORE_NAME);

    let requestObject = {
        domain: requestData.domain,
        endpoint: requestData.endpoint,
        body: requestData.body,
        method: requestData.method,
        status: "pending",
        requestResponses:""
    };

    store.add(requestObject);
    console.log("[IndexedDB] Request stored offline:", requestObject);
}
/*
async function processOfflineRequests() {
    if (sending) return;

    sending = true;
    let db = await openDB();
    let transaction = db.transaction(STORE_NAME, "readonly");
    let store = transaction.objectStore(STORE_NAME);
    let getAll = store.getAll();
    
    getAll.onsuccess = async () => {
        let requests = getAll.result.filter(req => req.status === "pending");

        if (requests.length === 0) {
            console.log("[IndexedDB] No pending requests.");
            sending = false;
            return;
        }

        for (let request of requests) {
            console.log("[Processing] Sending API request:", request);

            let apiEndpoint = "";
            let creation_body = request.body;
            let requestResponses = []; // Store all responses
            
            try {
                if (selectedItemFromDropdown != null) {
                    apiEndpoint = domain + request.endpoint;
                    creation_body.type = selectedItemFromDropdown;
                    creation_body.tab = page_load_conf.tab;
                } else {
                    apiEndpoint = domain + request.endpoint;
                }

                try{
                    // ✅ Check if a file exists in the request
                    if (creation_body.file) {
                        console.log("[File Upload] File detected, starting upload...");
                        
                        let fileUploadData = creation_body.file;
                        let fileResponse = await fetch(fileUploadData.url, {
                            method: fileUploadData.method,
                            body: fileUploadData.body
                        });

                        let fileResult = await fileResponse.json();
                        requestResponses.push({ type: "file_upload", response: fileResult });

                        if (!fileResponse.ok) {
                            console.error("[File Upload Failed] File upload failed, skipping API request.");
                            continue; // ❌ Skip API request if file upload fails
                        }

                        console.log("[File Upload Success] File uploaded successfully:", fileResult);

                        // ✅ Remove 'file' key and update request body with uploaded file name
                        delete creation_body.file;
                        creation_body[fileUploadData.fieldName] = fileResult.fileName; // Store uploaded file name
                    }
                } catch (error) {
                    console.error("[File Upload Error] Failed to upload file:", error);
                }

                // ✅ Proceed to the regular API request after successful file upload
                console.log(apiEndpoint, JSON.stringify(creation_body));
                let response = await fetch(apiEndpoint, {
                    method: request.method,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(creation_body)
                });

                let data = await response.json();
                requestResponses.push({ type: "api_request", response: data });

                if (data.message) {
                    console.log(`[Success] Request ID ${request.id} processed successfully. Response: ${requestResponses}`);
                    await updateStoredRequest(request.id, "archive", requestResponses); // Archive request
                    tab_status[page_load_conf.tab] = 0;
                    get_data_list(selectedItemFromDropdown, {});
                } else {
                    console.warn(`[Failure] Request ID ${request.id} failed: ${data.message || "Unknown error"}`);
                }
            } catch (error) {
                console.error(`[API Error] Failed to process request ID ${request.id}:`, error);
            }
        }

        sending = false;
    };

    getAll.onerror = () => {
        console.error("[IndexedDB] Error retrieving stored requests.");
        sending = false;
    };
}*/

async function processOfflineRequests() {
    if (sending) return;

    sending = true;
    let db = await openDB();
    let transaction = db.transaction(STORE_NAME, "readonly");
    let store = transaction.objectStore(STORE_NAME);
    let getAll = store.getAll();

    getAll.onsuccess = async () => {
        let requests = getAll.result.filter(req => req.status === "pending");

        if (requests.length === 0) {
            console.log("[IndexedDB] No pending requests.");
            sending = false;
            return;
        }

        console.log(`[Processing] Found ${requests.length} pending requests. Processing in chunks...`);

        for (let i = 0; i < requests.length; i += CHUNK_SIZE) {
            let chunk = requests.slice(i, i + CHUNK_SIZE);
            console.log(`[Processing] Sending batch ${i / CHUNK_SIZE + 1} (${chunk.length} requests)`);

            let chunkPromises = chunk.map(async (request) => {
                console.log("[Processing] Sending API request:", request);

                let apiEndpoint = domain + request.endpoint;
                let creation_body = { ...request.body };
                let requestResponses = [];

                try {
                    if (selectedItemFromDropdown != null) {
                        creation_body.type = selectedItemFromDropdown;
                        creation_body.tab = page_load_conf.tab;
                    }

                    // ✅ Handle file upload (normal or chunked)
                    if (creation_body.file) {
                        console.log("[File Upload] File detected, starting upload...");

                        let fileUploadData = creation_body.file;
                        let file = fileUploadData.file;
                        let fileName = file.name;
                        let totalChunks = Math.ceil(file.size / CHUNK_SIZE);
                        let uploadedChunks = 0;

                        for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                            let start = chunkIndex * CHUNK_SIZE;
                            let end = Math.min(start + CHUNK_SIZE, file.size);
                            let fileChunk = file.slice(start, end);

                            let formData = new FormData();
                            formData.append("file", fileChunk);
                            formData.append("fileName", fileName);
                            formData.append("chunkIndex", chunkIndex);
                            formData.append("totalChunks", totalChunks);

                            console.log(`[File Upload] Uploading chunk ${chunkIndex + 1}/${totalChunks}`);

                            try {
                                let fileResponse = await fetch(fileUploadData.url, {
                                    method: "POST",
                                    body: formData
                                });

                                let fileResult = await fileResponse.json();
                                requestResponses.push({ type: "file_upload", chunkIndex, response: fileResult });

                                if (!fileResponse.ok) {
                                    console.error("[File Upload Failed] Chunk upload failed.");
                                    return;
                                }

                                uploadedChunks++;
                                console.log(`[File Upload] Chunk ${chunkIndex + 1} uploaded successfully.`);
                            } catch (error) {
                                console.error("[File Upload Error] Chunk upload failed:", error);
                                return;
                            }
                        }

                        if (uploadedChunks === totalChunks) {
                            // ✅ Notify the server to merge chunks
                            try {
                                let mergeResponse = await fetch(fileUploadData.url + "/merge", {
                                    method: "POST",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({ fileName, totalChunks })
                                });

                                let mergeResult = await mergeResponse.json();
                                requestResponses.push({ type: "file_merge", response: mergeResult });

                                if (!mergeResponse.ok) {
                                    console.error("[File Merge Failed] Failed to merge file chunks.");
                                    return;
                                }

                                console.log("[File Upload Success] File merged successfully:", mergeResult);
                                delete creation_body.file;
                                creation_body[fileUploadData.fieldName] = mergeResult.fileName;
                            } catch (error) {
                                console.error("[File Merge Error] Failed to merge file:", error);
                                return;
                            }
                        }
                    }

                    // ✅ Proceed to API request
                    console.log(apiEndpoint, JSON.stringify(creation_body));
                    let response = await fetch(apiEndpoint, {
                        method: request.method,
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(creation_body)
                    });

                    let data = await response.json();
                    requestResponses.push({ type: "api_request", response: data });

                    if (data.message) {
                        console.log(`[Success] Request ID ${request.id} processed successfully.`);
                        await updateStoredRequest(request.id, "archive", requestResponses);
                        tab_status[page_load_conf.tab] = 0;
                        get_data_list(selectedItemFromDropdown, {});
                    } else {
                        console.warn(`[Failure] Request ID ${request.id} failed: ${data.message || "Unknown error"}`);
                    }
                } catch (error) {
                    console.error(`[API Error] Failed to process request ID ${request.id}:`, error);
                }
            });

            await Promise.all(chunkPromises);
        }

        sending = false;
        console.log("[Processing] All pending requests have been processed.");
    };

    getAll.onerror = () => {
        console.error("[IndexedDB] Error retrieving stored requests.");
        sending = false;
    };
}




// Function to update request status in IndexedDB
async function updateStoredRequest(id, newStatus, responses) {
    let db = await openDB();
    let transaction = db.transaction(STORE_NAME, "readwrite");
    let store = transaction.objectStore(STORE_NAME);

    let request = store.get(id);

    request.onsuccess = () => {
        let record = request.result;
        if (record) {
            record.status = newStatus; // Set status to 'archive'
            record.requestResponses = responses; // Set status to 'archive'
            store.put(record);
            console.log(`[IndexedDB] Updated request ID ${id} to ${newStatus}.`);
        }
    };

    request.onerror = () => {
        console.error("[IndexedDB] Error updating request.");
    };
}

// Timer to check and process offline requests every 15 seconds
setInterval(async function () {
    if (navigator.onLine && !sending) {
        console.log("[Scheduler] Checking for pending requests...");
        await processOfflineRequests();
    }
}, 15000);

// Also, process requests immediately when the user comes online
window.addEventListener("online", () => {
    console.log("[Network] Connection restored! Processing offline requests...");
    processOfflineRequests();
});


async function fetchData() {
    try {
        let db = await openDB();
        let transaction = db.transaction(STORE_NAME, "readonly");
        let store = transaction.objectStore(STORE_NAME);
        let getAll = store.getAll();

        getAll.onsuccess = () => {
            let data = getAll.result;
            console.log("[IndexedDB] Fetched all records:", data);
            if (data.length === 0) {
                console.log("[IndexedDB] No records found.");
                return;
            }
            present_Data([data],selectedItemFromDropdown);
            // displayTable(data);
        };

        getAll.onerror = () => {
            console.error("Failed to fetch data from IndexedDB.");
        };

    } catch (error) {
        console.error(error);
    }
}

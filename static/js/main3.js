var page_load_conf={
    rows_PP:null,
    sort_col:null,
    page_count:0,
    tab:"",
    role:"",
    event:"",
    user_name:"",
    sessionId:""
};
// Pagination Variables
let currentPage = 1;
let rowsPerPage = 5; // Change this value to adjust the number of rows per page

var  caldata={},    selectedItemFromDropdown=null,  role="Admin";
var tab_status={};
var file_rowdata=[];
page_load_conf.user_name="Sahique"; page_load_conf.sessionId="458523shgjs";
page_load_conf.role="Admin";    page_load_conf.qry={};
var domain="http://127.0.0.1:5000/"
console.log(page_load_conf);
document.addEventListener("DOMContentLoaded", function () {
    load_tabs();
});
//load_tabs()

function load_tabs() {
    var ul = document.getElementById("tab_list");
    var tab_pg_content = document.getElementById("tab_page_content");
    var send_data = JSON.stringify(page_load_conf);
    var end_point = domain + "get_user_tabs";

    const getData = async (url = end_point, api_method = "POST", api_body = send_data) => {
        console.log(api_body);
        var response = await fetch(url, {
            method: api_method,
            body: api_body,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            return await response.json();
        }
        return null;
    };

    getData().then(data => {
        if (!data || !data.tab_list) return;
        
        console.log((data.tab_list))
        tab_list = data.tab_list;
        console.log(tab_list[0]);

        for (var i = 0; i < tab_list.length; i++) {
            var li = document.createElement("li");
            li.className = "nav-item";

            var a = document.createElement("a");
            a.setAttribute('data-bs-toggle', 'tab');  // Corrected for Bootstrap 5
            a.href = `#${tab_list[i].Name}`;
            a.innerHTML = tab_list[i].Name;
            a.className = 'nav-link';

            a.addEventListener('click', function () {
                const tabName = this.innerHTML.trim(); 
                page_load_conf.tab = tabName;  
                tab_status[tabName] = 0;         
                get_data_list();
            });

            tab_href_div = document.createElement('div');
            tab_href_div.id = tab_list[i].Name;
            tab_href_div.className = "tab-pane fade";
            tab_href_div.innerHTML = "This is tab page " + tab_list[i].Name;

            tab_pg_content.append(tab_href_div);
            li.appendChild(a);
            ul.appendChild(li);

            tab_status[tab_list[i].Name] = 0;
        }

        // Activate Bootstrap tab functionality
        var tabTriggerList = [].slice.call(document.querySelectorAll('#tab_list a'));
        tabTriggerList.forEach(function (tab) {
            new bootstrap.Tab(tab);
        });

        console.log(tab_status);
    });
}

function API_call(domain,endpoint,body,method){
    var end_point = domain+endpoint;
    console.log(end_point, method)
    const getData = async(url=end_point,api_method=method,api_body=body) => {     
        console.log(api_body);
        var response;
        if (method !== "GET"){
            response = await fetch(url,{
                method: api_method,
                body: JSON.stringify(api_body), // string or object
                headers : { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            });
        }
        else{
            console.log("inside get")
            response = await fetch(url,{
                method: api_method,
                headers : { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            });
        }
        if (response.ok) {
            const raps = await response.json(); 
            if (raps){myresult = raps;}
            else{myresult = "No data found";}

        }
        return (myresult);
    }
    getData().then(data => {
        console.log(data, page_load_conf.tab,body.type)
        if (body.type){present_Data(data,body.type)}
        else{present_Data(data,null)}
    });
    tab_status[page_load_conf.tab]=1;
    console.log(tab_status);
    
}

/*displayObjectList*/

function createTable(responseData) {
    caldata=responseData;
    var status="";
    console.log(selectedItemFromDropdown)
    console.log(responseData);
    document.getElementById("tab_page_content").style.display = "block";
    const container = document.getElementById("tab_page_header");   
    if (!container) {
        console.error(`Element with id 'tab_page_content' not found.`);
        return;
    }
     // Create a div for buttons
     console.log(selectedItemFromDropdown)
     var divControls = document.createElement('div');
     if(selectedItemFromDropdown === null){
        try {
            container.innerHTML = ""; 
            console.log("///////////////////////")
            divControls.className = 'mb-3 d-flex gap-2';
            responseData.controls.forEach(control => {
                if (control.roles && control.roles.includes(role)) {
                    let input = null;

                    if (control.type === "select") {
                        let selectContainer = document.createElement('div');
                        selectContainer.className = 'custom-dropdown';
                        
                        input = document.createElement('select');
                        input.className = 'form-control dropdown-select';
                        input.name = control.tag || control.name;
                        input.setAttribute('id', control.tag); // Unique ID for each dropdown

                        // Add a default "Select Config" option
                        let defaultOption = document.createElement('option');
                        defaultOption.value = control.tag;
                        defaultOption.textContent = control.textContent;
                        defaultOption.disabled = true;
                        defaultOption.selected = true;
                        input.appendChild(defaultOption);

                        // Get options from JSON config or use a fallback array
                        let data = control.options || ["Config A", "Config B", "Config C"];
                        console.log(`Dropdown '${control.name}' Options:`, data);

                        if (Array.isArray(data) && data.length > 0) {
                            data.forEach(value => {
                                let option = document.createElement('option');
                                option.value = value;
                                option.textContent = value;
                                input.appendChild(option);
                            });
                        } else {
                            console.warn(`No options available for '${control.name}'.`);
                        }

                        // Add an onchange event listener
                        input.addEventListener("change", function () {
                            console.log(`Selected Config: ${this.value}`, control.tag);
                            
                            if(control.tag === "entriesPerPage"){rowsPerPage=this.value;  displayPage(1);}
                            else if(control.tag ==="items"){selectedItemFromDropdown=this.value;    get_data_list(this.value,{}); }
                           
                        });
                        
                        

                        //let selectContainer = document.createElement('div');
                        selectContainer.appendChild(input);

                        divControls.appendChild(selectContainer);
                    } 
                    else { // For buttons
                        input = document.createElement('button');
                        input.setAttribute('onclick', control.function);
                        input.className = control.class;
                        input.innerHTML = control.name;
                        divControls.appendChild(input);
                    }
                }
            });
            container.appendChild(divControls);
        }
        catch (err) {
            status=status + err.message;
            console.log(err.message);
        }
     }
    ////////////////////////////////////////////////////////


    //////////////////////////////////////////////////////////

    // Create Search Bar
    const contentContainer = document.getElementById("tab_page_content");
    //console.log("clearing content container");
    if (selectedItemFromDropdown != null  || selectedItemFromDropdown == null){ contentContainer.innerHTML = ""; }
    let searchInput = document.createElement("input");
    searchInput.setAttribute("type", "text");
    searchInput.setAttribute("placeholder", "Search...");
    searchInput.className = "form-control mb-3";
    searchInput.addEventListener("input", function () {
        filterTable(this.value);
    });
    

    // Table Wrapper
    let tableWrapper = document.createElement('div');
    tableWrapper.id = 'tableWrapper';
    tableWrapper.className = 'table-responsive';

    let table = document.createElement('table');
    table.className = 'table table-bordered table-striped table-hover';
    table.setAttribute("id", "dataTable");

    // Create Table Header
    let thead = document.createElement('thead');
    thead.className = 'table-dark sticky-top';

    let headerRow = document.createElement('tr');


    let received_Data = responseData.fields.data[0];
    let visibleFields = received_Data.fields.filter(field => field.show);
    const filterContainer = document.getElementById("tab_page_filter");
    // Ensure filterValues is initialized before use
    if (typeof filterValues === "undefined") {
        var filterValues = {}; // Initialize globally if not already defined
    }
    // Check if filter form already exists, if not, create it
    let filterForm = document.getElementById("filterForm");
    if (!filterForm) {
        filterForm = document.createElement("div");
        filterForm.id = "filterForm";
        //filterForm.className = "filter-form d-flex gap-2 align-items-center mb-3"; // Flex styling
        filterForm.className = "filter-form d-flex flex-wrap gap-2 align-items-center mb-3";

        filterContainer.appendChild(filterForm);
    }

    //////////////////////////////////  FILTER START   ////////////////////////////////////////////////////

        // Clear existing filter inputs before adding new ones
        filterForm.innerHTML = "";
        var hasField = false;
        document.getElementById("filter_btn").style.display = "block";
        document.getElementById("show_btn").style.display = "block";
    
        // Restore filters from sessionStorage if available
        /*let savedFilters = sessionStorage.getItem("savedFilters");
        //let savedFilters = sessionStorage.getItem(page_load_conf.tab.selectedItemFromDropdown.filter_values);
        if (savedFilters) {
            filterValues = JSON.parse(savedFilters);
        }*/
    
        console.log("page_load_conf:", page_load_conf);
        console.log("page_load_conf.tab:", page_load_conf?.tab);
        console.log("selectedItemFromDropdown:",selectedItemFromDropdown);
        console.log("page_load_conf.tab.selectedItemFromDropdown:", page_load_conf?.tab?.selectedItemFromDropdown);
            
        // Ensure selectedItemFromDropdown exists before retrieving data
        if (selectedItemFromDropdown) {
            let key = String(selectedItemFromDropdown); // Convert to string if necessary
            let savedFilters = sessionStorage.getItem(key);
            
            filterValues = savedFilters ? JSON.parse(savedFilters) : {}; // Parse if exists, else default to {}
        } else {
            console.warn("selectedItemFromDropdown is undefined.");
        }
    
        // Create input fields for each visible column
        console.log(visibleFields);
        visibleFields.forEach(element => {
            try {
                console.log(element.filter_type, element);
                
                let fieldWrapper = document.createElement("div");
                fieldWrapper.className = "mb-3"; // Ensures proper spacing and alignment
                
                if (element.filter_type === "datetime") {
                    var datTimeFilterObj = filterValues[element.key || element.field] || [{ "start": "", "end": "" }];
        
                    let label1 = document.createElement("label");
                    label1.innerHTML = element.field + " FROM:";
                    label1.className = "form-label";
        
                    let input1 = document.createElement("input");
                    input1.type = "datetime-local";
                    input1.placeholder = "FROM";
                    input1.className = "form-control";
                    input1.name = element.field;
                    input1.value = datTimeFilterObj[0].start;
        
                    input1.addEventListener("input", function () {
                        datTimeFilterObj[0].start = this.value;
                        filterValues[element.key || element.field] = [...datTimeFilterObj];
                    });
        
                    let label2 = document.createElement("label");
                    label2.innerHTML = element.field + " TO:";
                    label2.className = "form-label";
        
                    let input2 = document.createElement("input");
                    input2.type = "datetime-local";
                    input2.placeholder = "TO";
                    input2.className = "form-control";
                    input2.name = element.field;
                    input2.value = datTimeFilterObj[0].end;
        
                    input2.addEventListener("input", function () {
                        datTimeFilterObj[0].end = this.value;
                        filterValues[element.key || element.field] = [...datTimeFilterObj];
                    });
        
                    fieldWrapper.appendChild(label1);
                    fieldWrapper.appendChild(input1);
                    fieldWrapper.appendChild(label2);
                    fieldWrapper.appendChild(input2);   fieldWrapper.appendChild(document.createElement('br'));
                } 
                else if (element.filter_type === "dropdown") {
                    let label = document.createElement("label");
                    label.innerHTML = element.field;
                    label.className = "form-label";
        
                    let select = document.createElement("select");
                    select.className = "form-select";
                    select.name = element.field;
        
                    let defaultOption = document.createElement("option");
                    defaultOption.value = "";
                    defaultOption.textContent = "Select " + element.field;
                    select.appendChild(defaultOption);
        
                    function populateOptions(options) {
                        options.forEach(value => {
                            let option = document.createElement("option");
                            option.value = value;
                            option.textContent = value;
                            if (filterValues[element.key || element.field] === value) {
                                option.selected = true;
                            }
                            select.appendChild(option);
                        });
                    }
        
                    if (element.filter_helper) {
                        fetchHelperData(element.filter_helper).then(helperOptions => {
                            if (Array.isArray(helperOptions)) {
                                populateOptions(helperOptions);
                            }
                        }).catch(error => console.error("Error fetching helper data:", error));
                    } else if (Array.isArray(element.filter_default_value)) {
                        populateOptions(element.filter_default_value);
                    }
        
                    select.addEventListener("change", function () {
                        filterValues[element.key || element.field] = this.value;
                    });
        
                    //fieldWrapper.appendChild(label);
                    fieldWrapper.appendChild(select);   fieldWrapper.appendChild(document.createElement('br'));
                } 
                else if (element.filter_type === "textbox" || element.filter_type === "lable") {
                    let label = document.createElement("label");
                    label.innerHTML = element.label || element.field;
                    label.className = "form-label";
        
                    let input = document.createElement("input");
                    input.setAttribute("type", "text");
                    input.setAttribute("placeholder", element.label || element.field);
                    input.className = "form-control";
                    input.value = filterValues[element.key || element.field] || element.filter_default_value || "";
        
                    if (element.filter_type === "lable") {
                        input.setAttribute("readonly", true);
                    }
                    input.addEventListener("input", function () {
                        filterValues[element.key || element.field] = this.value;
                    });
        
                    //fieldWrapper.appendChild(label);
                    fieldWrapper.appendChild(input);    fieldWrapper.appendChild(document.createElement('br'));
                }
                
                filterForm.appendChild(fieldWrapper);
                hasField = true;
            } catch (err) {
                console.log(err);
            }
        });
        
        // Add the Filter button
        if (hasField) {
            let filterButtonWrapper = document.createElement("div");
            filterButtonWrapper.className = "mb-3 text-center";
            
            let filterButton = document.createElement("button");
            filterButton.textContent = "OK";
            filterButton.className = "btn btn-primary";
        
            filterButton.addEventListener("click", function () {
                let filterQuery = { where: { ...filterValues } };
                console.log("Filter Query:", filterQuery);
                console.log(selectedItemFromDropdown, filterValues);
        
                // Store filterValues in sessionStorage for persistence
                //sessionStorage.setItem("savedFilters", JSON.stringify(filterValues));
                //sessionStorage.setItem(page_load_conf.tab.selectedItemFromDropdown, JSON.stringify(filterValues));
                // Ensure page_load_conf and selectedItemFromDropdown exist
                    // Ensure page_load_conf and selectedItemFromDropdown exist before storing
                if (selectedItemFromDropdown) {
                    let key = String(selectedItemFromDropdown);
                    console.log("Saving to sessionStorage - Key:", key, "Values:", filterValues);
                    sessionStorage.setItem(key, JSON.stringify(filterValues));
                } else {
                    console.warn("selectedItemFromDropdown is undefined.");
                }
    
                get_data_list(selectedItemFromDropdown, filterValues);
            });
            filterButtonWrapper.appendChild(document.createElement('br'));
            filterButtonWrapper.appendChild(filterButton);
            filterForm.appendChild(filterButtonWrapper);
        }
    

    //////////////////////////////////  FILTER END   ////////////////////////////////////////////////////


    // Add Edit Column if applicable
    if (received_Data.edit_option) {
        let editTh = document.createElement('th');
        editTh.className = "text-center";
        editTh.textContent = "Edit";
        editTh.setAttribute('scope', 'col');
        headerRow.appendChild(editTh);
    }

   //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Store previous checkbox states for different dropdown selections
    let previousSelectionsMap = {};
    let lastSelectedItem = null;

    visibleFields.forEach(element => {
        let th = document.createElement('th');
        th.className = "text-center sortable";
        th.setAttribute('scope', 'col');
        th.setAttribute("data-field", element.field);
        
        // Create a container div for text and arrow
        let thContent = document.createElement('div');
        thContent.style.display = "flex";
        thContent.style.alignItems = "center";
        thContent.style.justifyContent = "center";
        thContent.style.cursor = "pointer";
        
        // Column Name
        let columnText = document.createElement('span');
        columnText.textContent = element.lang[global_settings.language] || element.field.replace(/_/g, ' ').toUpperCase();
        columnText.style.marginRight = "5px";
        
        // Arrow Icon
        let sortIcon = document.createElement('span');
        sortIcon.className = "bi bi-arrow-up-down"; // Bootstrap sort icon
        
        let sortDirection = 1; // 1 = Ascending, -1 = Descending
        
        // Sort on click with arrow toggle
        thContent.addEventListener("click", function () {
            sortTable(element.field, sortDirection);
            sortDirection *= -1; // Toggle direction
            sortIcon.innerHTML = sortDirection === 1 ? "&#9650;" : "&#9660;"; // ▲ ▼
        });

        // Append elements
        thContent.appendChild(columnText);
        thContent.appendChild(sortIcon);
        th.appendChild(thContent);
        headerRow.appendChild(th);
    });

    // Manage column visibility panel
    let columnPanel = document.getElementById("show_columns_panel");

    // If the selected item changes, clear previous checkboxes
    if (selectedItemFromDropdown !== lastSelectedItem) {
        columnPanel.innerHTML = "";
        previousSelectionsMap[selectedItemFromDropdown] = {}; // Reset selection tracking
    }

    // Fetch previous selections for this dropdown item
    let previousSelections = previousSelectionsMap[selectedItemFromDropdown] || {};

    visibleFields.forEach(element => {
        let columnItem = document.createElement("div");
        columnItem.className = "column-item";

        let checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.setAttribute("data-field", element.field);

        // Restore previous selection if it exists, else default to checked
        checkbox.checked = previousSelections.hasOwnProperty(element.field) ? previousSelections[element.field] : true;

        let label = document.createElement("label");
        label.textContent = element.lang[global_settings.language] || element.field.replace(/_/g, ' ').toUpperCase();
        label.style.marginLeft = "5px";

        columnItem.appendChild(checkbox);
        columnItem.appendChild(label);
        columnPanel.appendChild(columnItem);
    });

    // Ensure only one "Update" button exists
    if (!document.getElementById("update_columns_btn")) {
        let updateButton = document.createElement("button");
        updateButton.id = "update_columns_btn";
        updateButton.textContent = "OK";
        updateButton.className = "btn btn-primary mt-2";
        updateButton.onclick = function () {
            let selectedColumns = [];
            let checkboxes = document.querySelectorAll("#show_columns_panel input[type='checkbox']");

            // Update selection tracking for the current dropdown item
            previousSelectionsMap[selectedItemFromDropdown] = {};

            checkboxes.forEach(cb => {
                let field = cb.getAttribute("data-field");
                previousSelectionsMap[selectedItemFromDropdown][field] = cb.checked;
                if (cb.checked) {
                    selectedColumns.push(field);
                }
            });

            // Show/hide table columns based on selection
            document.querySelectorAll("th, td").forEach(cell => {
                let field = cell.getAttribute("data-field");
                if (field) {
                    cell.style.display = selectedColumns.includes(field) ? "" : "none";
                }
            });
        };

        columnPanel.appendChild(updateButton);
    }

    lastSelectedItem = selectedItemFromDropdown; // Update last selected item
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Add Delete Column if applicable
    if (received_Data.delete_option) {
        let deleteTh = document.createElement('th');
        deleteTh.className = "text-center";
        deleteTh.textContent = "Delete";
        deleteTh.setAttribute('scope', 'col');
        headerRow.appendChild(deleteTh);
    }

    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Create Table Body
    let tbody = document.createElement('tbody');
    tbody.setAttribute("id", "entityTableBody");
    console.log(responseData.data)
    responseData.data.forEach(rowData => {
        let tr = document.createElement('tr');
        let rowDataString = JSON.stringify(rowData);

        // Edit Button Column
        if (received_Data.edit_option) {
            let editTd = document.createElement('td');
            editTd.className = "text-center";
            let editButton = document.createElement('button');
            editButton.className = "btn btn-warning btn-sm";
            editButton.innerHTML = `<i class="bi bi-pencil-fill"></i>`;
            editButton.setAttribute('data-row', rowDataString);
            editButton.addEventListener('click', function () {
                let rowData = JSON.parse(this.getAttribute('data-row'));
                editRow(rowData);
            });
            editTd.appendChild(editButton);
            tr.appendChild(editTd);
        }

        visibleFields.forEach(field => {
            let td = document.createElement('td');
            td.className = "text-center";
            td.setAttribute("data-field", field.field);
        
            if (["remark", "schedule", "venue", "photo"].includes(field.field.toLowerCase())) {
                let viewBtn = document.createElement("button");
                viewBtn.className = "btn btn-info btn-sm";
                viewBtn.innerHTML = "View";
        
                // Convert event handler to async function
                viewBtn.onclick = async function () {
                    console.log(1);
        
                    if (selectedItemFromDropdown === "Resource Registry" && field.field.toLowerCase() === "schedule") {
                        console.log(2);
                        let schedule = rowData[field.field] ? JSON.parse(rowData[field.field]) : null;
                        let details = rowData.details;
                        console.log("Schedule Data:", schedule, details);
        
                        if (schedule) {
                            let calendarEl = document.getElementById("calendar");
                            calendarEl.innerHTML = ""; // Clear previous calendar
        
                            let startDate = new Date(schedule.startDate);
                            let endDate = new Date(schedule.endDate);
        
                            if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
                                alert("Invalid event date format!");
                                return;
                            }
        
                            let events = [];
                            let currentDate = new Date(startDate);
        
                            while (currentDate <= endDate) {
                                let dayName = currentDate.toLocaleString("en-US", { weekday: "long" }).toLowerCase();
        
                                if (schedule.workDays[dayName]) {
                                    schedule.workDays[dayName].forEach(timeRange => {
                                        let [startTime, endTime] = timeRange;
                                        let eventDate = new Date(currentDate);
        
                                        let eventStart = new Date(eventDate);
                                        let eventEnd = new Date(eventDate);
        
                                        let [startHour, startMinute] = startTime.split(":").map(Number);
                                        let [endHour, endMinute] = endTime.split(":").map(Number);
        
                                        eventStart.setHours(startHour, startMinute, 0);
                                        eventEnd.setHours(endHour, endMinute, 0);
        
                                        events.push({
                                            title: details || "Scheduled Event",
                                            start: eventStart.toISOString(),
                                            end: eventEnd.toISOString(),
                                            description: `Scheduled Time: ${startTime} - ${endTime}`,
                                            backgroundColor: "#007bff",
                                            textColor: "#ffffff",
                                            borderColor: "#0056b3"
                                        });
                                    });
                                }
                                currentDate.setDate(currentDate.getDate() + 1);
                            }
        
                            console.log("Generated Events:", events);
        
                            let calendar = new FullCalendar.Calendar(calendarEl, {
                                initialView: "dayGridMonth",
                                headerToolbar: {
                                    left: "prev,next today",
                                    center: "title",
                                    right: "dayGridMonth,timeGridWeek,timeGridDay",
                                },
                                events: events,
                                eventDidMount: function (info) {
                                    info.el.setAttribute("title", info.event.extendedProps.description);
                                    info.el.style.padding = "5px";
                                    info.el.style.borderRadius = "5px";
                                },
                                eventClick: function (info) {
                                    alert(`Event: ${info.event.title}\nDetails: ${info.event.extendedProps.description}`);
                                }
                            });
        
                            calendar.render();
        
                            let modalInstance = new bootstrap.Modal(document.getElementById("myCalendar"));
                            modalInstance.show();
                        } else {
                            alert("No work days available.");
                        }
                    } 
                    else if (field.field.toLowerCase() === "remark") {
                        console.log(3);
                        let remarkContent = document.getElementById("remark_content");
        
                        if (page_load_conf.tab === "Resource") {
                            let content = rowData[field.field] ? JSON.stringify(JSON.parse(rowData[field.field]), null, 2) : "No data available";
                            remarkContent.innerText = content;
                        } 
                        else if (page_load_conf.tab === "Entity") {
                            let remarks = rowData[field.field]
                                ? rowData[field.field].split("|").map(item => `<li>${item.trim()}</li>`).join("")
                                : "<li>No remarks available</li>";
                            remarkContent.innerHTML = `<ul>${remarks}</ul>`;
                        }
        
                        let modalInstance = new bootstrap.Modal(document.getElementById("remark_modal"));
                        modalInstance.show();
                    } 
                    else if (field.field.toLowerCase() === "venue") {
                        console.log(4);
                        let remarkContent = document.getElementById("remark_content");
        
                        if (rowData[field.field]) {
                            let jsonData = JSON.parse(rowData[field.field]);
                            let formattedContent = Object.entries(jsonData)
                                .map(([key, value]) => `${key}: ${value}`)
                                .join("\n");
        
                            remarkContent.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${formattedContent}</pre>`;
                        } else {
                            remarkContent.innerText = "No data available";
                        }
        
                        let modalInstance = new bootstrap.Modal(document.getElementById("remark_modal"));
                        modalInstance.show();
                    } 
                    else if (field.field.toLowerCase() === "photo") {
                        file_rowdata =rowData;   console.log(rowData);
                        console.log("Opening photo preview for:", rowData[field.field]);
        
                        if (rowData[field.field]) {
                            try {
                                await viewFile(rowData[field.field]);
                            } catch (error) {
                                console.error("Error loading photo:", error);
                            }
                        } else {
                            console.warn("No photo available for preview.");
                            alert("No photo available.");
                        }
                    }
        
                    console.log(5);
                };
        
                td.appendChild(viewBtn);
            } else {
                td.textContent = rowData[field.field] || "-";
            }
        
            tr.appendChild(td);
        });
        

        // Delete Button Column
        if (received_Data.delete_option) {
            let deleteTd = document.createElement('td');
            deleteTd.className = "text-center";
            let deleteButton = document.createElement('button');
            deleteButton.className = "btn btn-danger btn-sm";
            deleteButton.innerHTML = `<i class="bi bi-trash-fill"></i>`;
            deleteButton.setAttribute('data-row', rowDataString);
            deleteButton.addEventListener('click', function () {
                let rowData = JSON.parse(this.getAttribute('data-row'));
                deleteRow(rowData);
            });
            deleteTd.appendChild(deleteButton);
            tr.appendChild(deleteTd);
        }

        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    tableWrapper.appendChild(table);

    // Append everything to container
    if (page_load_conf.tab !== "EntityConfig" || "NetworkConfig" ||"SystemConfig"){
        container.appendChild(divControls);
    }
    contentContainer.appendChild(searchInput);
    contentContainer.appendChild(tableWrapper);
    trigger( page_load_conf.tab, "list", status)
    // Initialize Pagination
    createPaginationControls();
    displayPage(1);
}

function displayPage(page) {
    let tableBody = document.getElementById("entityTableBody");
    let rows = tableBody.getElementsByTagName("tr");
    let totalPages = Math.ceil(rows.length / rowsPerPage);

    // Ensure valid page number
    if (page < 1) page = 1;
    if (page > totalPages) page = totalPages;
    currentPage = page;

    // Hide all rows
    for (let i = 0; i < rows.length; i++) {
        rows[i].style.display = "none";
    }

    // Show only the rows for the current page
    let start = (currentPage - 1) * rowsPerPage;
    let end = start + rowsPerPage;
    for (let i = start; i < end && i < rows.length; i++) {
        rows[i].style.display = "";
    }

    updatePaginationControls(totalPages);
}

// Create Pagination Controls
function createPaginationControls() {
    let paginationContainer = document.createElement("div");
    paginationContainer.id = "paginationControls";
    paginationContainer.innerHTML="";
    paginationContainer.className = "d-flex justify-content-center mt-3"; // Bootstrap styling

    // Previous Button
    let prevButton = document.createElement("button");
    prevButton.textContent = "Previous";
    prevButton.className = "btn btn-secondary mx-1";
    prevButton.onclick = function () {
        displayPage(currentPage - 1);
    };
    paginationContainer.appendChild(prevButton);

    // Page Numbers Container
    let pageNumbersContainer = document.createElement("span");
    pageNumbersContainer.id = "pageNumbers";
    pageNumbersContainer.className = "mx-2";
    paginationContainer.appendChild(pageNumbersContainer);

    // Next Button
    let nextButton = document.createElement("button");
    nextButton.textContent = "Next";
    nextButton.className = "btn btn-secondary mx-1";
    nextButton.onclick = function () {
        displayPage(currentPage + 1);
    };
    paginationContainer.appendChild(nextButton);

    // Append to content container
    document.getElementById("tab_page_content").appendChild(paginationContainer);
}

// Update Pagination Controls (Page Numbers)
function updatePaginationControls(totalPages) {
    let pageNumbersContainer = document.getElementById("pageNumbers");
    pageNumbersContainer.innerHTML = "";

    for (let i = 1; i <= totalPages; i++) {
        let pageButton = document.createElement("button");
        pageButton.textContent = i;
        pageButton.className = `btn btn-outline-primary mx-1 ${i === currentPage ? 'active' : ''}`;
        pageButton.onclick = function () {
            displayPage(i);
        };
        pageNumbersContainer.appendChild(pageButton);
    }
}

function displayFilter(visibleFields){
    visibleFields.forEach(element => {
        if (element.filter_type=="texbox"){
            let input = document.createElement("input");
            input.setAttribute("type", "text");
            input.setAttribute("placeholder", `${element.label || element.field}`);
            input.className = "form-control";
            input.style.width = "auto"; // Allow input fields to shrink
            
            // Store value on change
            input.addEventListener("input", function () {
                filterValues[element.key || element.field] = this.value;
            });
        }
        else if (element.filter_type=="lable"){
            let input = document.createElement("input");
            input.setAttribute("type", "text");
            input.setAttribute("value", element.filter_default_value);
            input.setAttribute("readonly", true);
            input.className = "form-control";
            input.style.width = "auto"; // Allow input fields to shrink
            
            // Store value on change
            input.addEventListener("input", function () {
                filterValues[element.key || element.field] = this.value;
            });
        }
        filterForm.appendChild(input);
    });
}
// Function to Filter Table Rows
function filterTable(query) {
    let rows = document.querySelectorAll("#entityTableBody tr");
    query = query.toLowerCase();
    rows.forEach(row => {
        let visible = false;
        row.querySelectorAll("td").forEach(cell => {
            if (cell.textContent.toLowerCase().includes(query)) {
                visible = true;
            }
        });
        row.style.display = visible ? "" : "none";
    });
}

// Function to Sort Table
function sortTable(field) {
    let table = document.getElementById("entityTableBody");
    let rows = Array.from(table.querySelectorAll("tr"));
    let ascending = table.getAttribute("data-sort-order") !== "asc";

    rows.sort((rowA, rowB) => {
        let cellA = rowA.querySelector(`td[data-field="${field}"]`).textContent.trim();
        let cellB = rowB.querySelector(`td[data-field="${field}"]`).textContent.trim();

        if (!isNaN(cellA) && !isNaN(cellB)) {
            return ascending ? cellA - cellB : cellB - cellA;
        } else {
            return ascending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
        }
    });

    table.innerHTML = "";
    rows.forEach(row => table.appendChild(row));

    table.setAttribute("data-sort-order", ascending ? "asc" : "desc");
}

function deleteRow(rowData) {
    // Confirm deletion with the user
    var value;
    let apiEndpoint = "";
    let requestData = { requestor_id:"", request_token:"", type:"",qry:{"where_data":{}},"tab":page_load_conf.tab,};
    console.log(selectedItemFromDropdown)
    try{
        if(selectedItemFromDropdown!=null) {
            requestData.qry.where_data[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key] = rowData[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key]
            requestData.type=selectedItemFromDropdown;
            apiEndpoint=domain + MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.cancel.api
        }
    }catch(err){console.log("Error in data extraction",err)}
    
   
    if (!confirm(`Are you sure you want to delete this data ?`)) {
        return;
    }

    // Define API endpoint based on the active tab
    apiEndpoint = MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.cancel.api;
    console.log(requestData, apiEndpoint);

    // Make the API call
    fetch(apiEndpoint, {
        method: "DELETE", // Assuming DELETE uses POST for sending data
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert("Entry deleted successfully!");
            console.log(page_load_conf.tab)
            get_data_list(selectedItemFromDropdown,{});
            //if (page_load_conf.tab === "Entity") { tab_status[page_load_conf.tab]=0; get_entity_list();}
        } else {
            alert("Error: " + (data.message || "Failed to delete entity."));
        }
    })
    .catch(error => {
        console.error("Delete request failed:", error);
        alert("An error occurred while deleting the entity.");
    });
}

function editRow(rowData) {
    console.log(selectedItemFromDropdown);
    console.log("Edit Clicked:", rowData);
    page_load_conf.role = localStorage.getItem("u_role");
    
    // Define a mapping for tab names to API details
    var apiConfigKey="";
    let modal_body = {};
    var key_val =MainConfig[page_load_conf.tab][selectedItemFromDropdown].key
    var api = MainConfig[page_load_conf.tab][selectedItemFromDropdown].getDataApi
    modal_body = {
        "requestor_id": "",
        "request_token": "",
        "type": selectedItemFromDropdown,
        "tab":page_load_conf.tab,
        "qry": {
            "select_fields": ["*"],
            "where_data": { [key_val]: rowData[key_val] }
        }
    };
    console.log(modal_body);
    const end_point = `http://127.0.0.1:5000/${api}`;
    const send_data = JSON.stringify(modal_body);

    console.log("Sending API Request:", send_data);

    // Fetch data from the server
    fetch(end_point, {
        method: "POST",
        body: send_data,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log("Received Data:", data);
        editModalCreation(data,selectedItemFromDropdown);
    })
    .catch(error => console.error("Error fetching data:", error));
}

function editModalCreation(response,selectedItemFromDropdown) {
    var rowData = response[0];
    console.log(rowData,selectedItemFromDropdown);
    let form = document.getElementById('editForm');
    if (!form) {
        console.error("Form element not found!");
        return;
    }

    form.innerHTML = ""; // Clear previous inputs

    let data = {};
    var config_path;
    if (selectedItemFromDropdown==null){config_path=MainConfig[page_load_conf.tab]; }
    else{config_path=MainConfig[page_load_conf.tab][selectedItemFromDropdown]; rowData = response[0][0]; }
    
    console.log(config_path.job);
    if(role == "Admin"){data=config_path.job.update.data[0];}
    else if(role == "Admin"){data=config_path.job.approver.data[0];}
    else{console.log("Role not defined")}

  
    let fields = data.fields || [];
    if (!fields.length) {
        console.error("No fields found in configuration!");
        return;
    }

    fields.forEach(field => {
        if (!field.show) return;

        let formGroup = document.createElement('div');
        formGroup.className = 'form-group mb-3';

        let label = document.createElement('label');
        label.textContent = field.field.replace(/_/g, ' ').toUpperCase();
        label.className = 'form-label';

        let input;
      
        console.log(label, field.field)
        if (field.field === "work_days") {
            input = document.createElement('input');
            input.className = 'form-control';
            input.name = field.field;
            input.id = 'work_days';
            input.readOnly = true;
            input.value = rowData[field.field] || "{}";
            formGroup.appendChild(input);
        
            let eventButton = document.createElement('button');
            eventButton.type = 'button';
            eventButton.textContent = "Open";
            eventButton.className = 'btn btn-primary mt-2';
            
            eventButton.onclick = function () {
                console.log("Raw work_days value:", input.value);
                
                try {
                    let workDaysData = JSON.parse(input.value || "{}");
                    console.log("Parsed Work Days Data:", workDaysData);
                    
                    // Populate modal fields
                    document.getElementById('eventName').value = workDaysData.title || "";
                    document.getElementById('eventDescription').value = workDaysData.description || "";
                    document.getElementById('eventStartDate').value = workDaysData.start_date || ""; 
                    document.getElementById('eventEndDate').value = workDaysData.end_date || "";
        
                    // Clear previous entries
                    let scheduleContainer = document.getElementById('scheduleContainer');
                    scheduleContainer.innerHTML = "";

                    // Populate existing schedule
                    let daysOfWeek = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

                    daysOfWeek.forEach(day => {
                        console.log(day, workDaysData[day]); // Debugging log
                    
                        if (workDaysData[day]) {  
                            let timingsArray = workDaysData[day]; // Already an array
                    
                            if (Array.isArray(timingsArray)) {
                                timingsArray.forEach((timeSlot, index) => {
                                    if (Array.isArray(timeSlot) && timeSlot.length === 2) {
                                        addScheduleRow_edit(day, timeSlot[0], timeSlot[1], index); // Pass day name & start/end times
                                    }
                                });
                            }
                        }
                    });
                    // Show modal
                    let addEventModal = new bootstrap.Modal(document.getElementById('addEventModal'));
                    addEventModal.show();
        
                } catch (error) {
                    console.error("Error parsing workDays JSON:", error);
                }
            };
        
            formGroup.appendChild(eventButton);
        } else if (field.control === "schedule-control") {
            input = document.createElement("schedule-control");
            input.id = field.field;
        
            // Ensure rowData[field.field] contains a valid schedule JSON string
            if (rowData[field.field]) {
                try {
                    const scheduleData = JSON.parse(rowData[field.field]);
                    input.value = scheduleData; // Assign parsed data to the custom element
                } catch (error) {
                    console.error("Invalid schedule data:", error);
                }
            }
        
            // Append input to the DOM if necessary (if inside a form or specific container)
            document.body.appendChild(input); // Change this according to your structure
        
            // Select and use the schedule-control element after appending it
            let scheduleControl = document.getElementById(field.field);
        
        
        } else if (field.control === "venue-control") {
            input = document.createElement("venue-control");
            input.id = field.field;
        
            // Ensure rowData[field.field] contains a valid schedule JSON string
            if (rowData[field.field]) {
                try {
                    const scheduleData = JSON.parse(rowData[field.field]);
                    input.value = scheduleData; // Assign parsed data to the custom element
                } catch (error) {
                    console.error("Invalid venue data:", error);
                }
            }
        
            // Append input to the DOM if necessary (if inside a form or specific container)
            document.body.appendChild(input); // Change this according to your structure
        
            // Select and use the schedule-control element after appending it
            let venueControl = document.getElementById(field.field);
        
        
        } else if (field.control === "checkbox") {
            input = document.createElement('input');
            input.type = 'checkbox';
            input.className = 'form-check-input';
            input.name = field.field;
            input.checked = rowData[field.field] == "true" || rowData[field.field] == 1;
        } else if (field.control === "dropdown" && field.values) {
            input = document.createElement('select');
            input.className = 'form-control';
            input.name = field.field;

            field.values.forEach(value => {
                let option = document.createElement('option');
                option.value = value;
                option.textContent = value;
                if (rowData[field.field] === value) {
                    option.selected = true;
                }
                input.appendChild(option);
            });
        } else if (field.control === "datetime-local") {
            input = document.createElement('input');
            input.type = 'datetime-local';
            input.className = 'form-control';
            input.name = field.field;
        
            // Convert stored date into proper format for datetime-local input
            if (rowData[field.field]) {
                let dateObj = new Date(rowData[field.field]);
                if (!isNaN(dateObj)) {
                    input.value = dateObj.toISOString().slice(0, 16); // Format: YYYY-MM-DDTHH:MM
                }
            }
        } else {
            input = document.createElement('input');
            input.className = 'form-control';
            input.name = field.field;
            input.value = rowData[field.field] || "";
        }

        if (!field.edit) input.setAttribute('disabled', 'true');

        formGroup.appendChild(label);
        formGroup.appendChild(input);
        form.appendChild(formGroup);
    });
    
    document.getElementById("venueForm").onsubmit = function (e) {
        e.preventDefault();
    
        let isValid = true;
        let errorMessage = "";
    
        // Get form values
        let building = document.getElementById('building').value.trim();
        let street = document.getElementById('street').value.trim();
        let area = document.getElementById('area').value.trim();
        let city = document.getElementById('city').value.trim();
        let state = document.getElementById('state').value.trim();
        let country = document.getElementById('country').value.trim();
        let url = document.getElementById('url_address').value.trim();
        let lat = document.getElementById('latitude').value.trim();
        let long = document.getElementById('longitude').value.trim();
    
        // Validation checks
        if (!building || !street || !area || !city || !state || !country) {
            isValid = false;
            errorMessage += "All text fields are required.\n";
        }
    
        // Validate latitude & longitude (must be numbers)
        if (lat && isNaN(lat)) {
            isValid = false;
            errorMessage += "Latitude must be a valid number.\n";
        }
    
        if (long && isNaN(long)) {
            isValid = false;
            errorMessage += "Longitude must be a valid number.\n";
        }
    
        // Validate URL (if provided)
        if (url && !/^https?:\/\/[\w\-]+(\.[\w\-]+)+[/#?]?.*$/.test(url)) {
            isValid = false;
            errorMessage += "Please enter a valid URL.\n";
        }
    
        if (!isValid) {
            alert(errorMessage); // Show validation errors
            return;
        }
    
        // Construct JSON in the required format
        let venueData = {
            building: building,
            street: street,
            area: area,
            city: city,
            state: state,
            country: country,
            url: url,
            lat: lat,
            long: long
        };
    
        console.log("Updated Venue JSON:", venueData);
    
        // Store JSON as a string in the hidden input field
        document.getElementById('venue').value = JSON.stringify(venueData);
    
        // Hide the modal after submission
        bootstrap.Modal.getInstance(document.getElementById('venueModal')).hide();
    };
    

    let editModalElement = document.getElementById('myModal');
    document.getElementById("modal_title").innerHTML = page_load_conf.tab + " Details";

    if (!editModalElement) {
        console.error("Modal not found in the DOM!");
        return;
    }

    editModalElement.removeAttribute("aria-hidden");

    let editModal = new bootstrap.Modal(editModalElement, { backdrop: 'static' });
    editModal.show();

   /* document.getElementById('saveChanges').onclick = function () {
        let updatedData = {"where_data":{},"update":{}};
        console.log(fields)
        fields.forEach(field => {
            if (!field.show) return;
            let input = form.elements[field.field]; 
            console.log(field.field);
            if (field.field === "schedule") {
                console.log(2,field.field);
                let scheduleElement = document.querySelector("schedule-control");
                if (scheduleElement) {
                    updatedData.update[field.field] = (scheduleElement.value);
                } else {
                    console.warn(`Schedule control element not found.`);
                }
                //updatedData.update[field.field] = (input.value); 
                console.log((updatedData.update[field.field]));
            } else {
                console.log(3);
                updatedData.update[field.field] = field.control === 'checkbox' ? input.checked ? 1 : 0 : input.value;
            }
            console.log(4);
        });
       
        //updatedData.where_data=MainConfig[page_load_conf.tab][selectedItemFromDropdown].key:rowData[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key]
        updatedData.where_data[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key] = rowData[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key]
        console.log(updatedData,MainConfig[page_load_conf.tab][selectedItemFromDropdown].key);
        updateEntry(rowData[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key],updatedData)
        editModal.hide();
    };*/

    document.getElementById('saveChanges').onclick = function () {
        let updatedData = { "where_data": {}, "update": {} };
        
        console.log(fields);
    
        fields.forEach(field => {
            if (!field.show) return;
    
            let input = form.elements[field.field];
            let currentValue = rowData[field.field]; // Original value from rowData
            let newValue;
            console.log(input, currentValue);
            if (field.field === "schedule") {
                let scheduleElement = document.querySelector("schedule-control");
                newValue = scheduleElement ? scheduleElement.value : "";
            } else if (field.control === "checkbox") {
                newValue = input.checked ? 1 : 0;
            } else {
                newValue = input.value;
            }
    
            // ✅ Only add changed fields to updatedData
            if (currentValue !== newValue) {
                updatedData.update[field.field] = newValue;
            }
        });
    
        // ✅ Ensure at least one field is being updated
        if (Object.keys(updatedData.update).length === 0) {
            console.log("No changes detected. No update required.");
            editModal.hide();
            return;
        }
    
        // ✅ Set the `where_data` for the update query
        updatedData.where_data[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key] =
            rowData[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key];
    
        console.log("Updated Data:", updatedData);
    
        updateEntry(
            rowData[MainConfig[page_load_conf.tab][selectedItemFromDropdown].key],
            updatedData
        );
    
        editModal.hide();
    };
    
}

// ✅ Function to properly format DateTime for "datetime-local"
function formatDateTime(dateString) {
    if (!dateString) return "";

    let date = new Date(dateString);
    if (isNaN(date.getTime())) return ""; // Handle invalid dates

    return date.toISOString().slice(0, 16); // Formats to "YYYY-MM-DDTHH:MM"
}

async function Registration_modal() {
    console.log("Create New  Modal Opened");

    let form = document.getElementById('createForm');
    if (!form) {
        console.error("Form element not found!");
        return;
    }

    form.innerHTML = ""; // Clear previous inputs
    let data = {};
    console.log(selectedItemFromDropdown)
    try{
       
        if(selectedItemFromDropdown!=null) {data=MainConfig[page_load_conf.tab][selectedItemFromDropdown].job.create.data}
        else{data=MainConfig[page_load_conf.tab].job.create.data}
    }catch(err){console.log("Error in data extraction",err)}

    console.log(data);

    if (!Array.isArray(data) || data.length === 0) {
        console.error("Invalid configuration data!");
        return;
    }

    let fields = [];

    for (const entry of data) {
        for (const field of entry.fields) {
            if (field.control === "dropdown") {
                if (Array.isArray(field.values) && field.values.length > 0) {
                    field.dropdownValues = field.values;
                } else if (entry.helper !== "none") {
                    const fetchedData = await fetchHelperData(entry.helper);
                    field.dropdownValues = Array.isArray(fetchedData) && fetchedData.length > 0 ? fetchedData : (field.default ? [field.default] : []);
                } else {
                    field.dropdownValues = field.default ? [field.default] : [];
                }
            }
        }
        fields = fields.concat(entry.fields);
    }

    console.log(fields);

    if (!fields.length) {
        console.error("No fields found in configuration!");
        return;
    }

    fields.forEach(field => {
        console.log(field);
        if (!field.show) return;

        let formGroup = document.createElement('div');
        formGroup.className = 'form-group mb-3';

        let label = document.createElement('label');
        label.textContent = field.field.replace(/_/g, ' ').toUpperCase();
        label.className = 'form-label';
        console.log(field.control);
        let input;
        
        if (field.control === "dropdown") {
            input = document.createElement('select');
            input.className = 'form-control';
            input.name = field.field;
            input.id = field.field;
            if (field.mandatory) input.required = true;
            
            if (field.dropdownValues && Array.isArray(field.dropdownValues)) {
                field.dropdownValues.forEach(value => {
                    let option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    input.appendChild(option);
                });
            }
        } else if (field.control === "schedule-control"){
            input = document.createElement("schedule-control");
            //input.setAttribute()
            input.id = field.field;
        } else if (field.control === "venue-control"){
            input = document.createElement("venue-control");
            //input.setAttribute()
            input.id = field.field;
        } else if (field.control === "attachment-control"){
           
            
            input = document.createElement("attachment-control");
            //input.setAttribute()
            input.id = field.field;
            input.handleSelection(field.type)
            //input.setAttribute("type", field.type); // Pass type dynamically
            //input.setAttribute("type", "image"); // Pass type dynamically
            //setSelectedOption("attachmentType", "Image");
        }else if (field.control === "checkbox") {
            input = document.createElement('input');
            input.type = 'checkbox';
            input.id = field.field;
            input.className = 'form-check-input';
            input.name = field.field;
            input.checked = field.default ? true : false;
        } else if (field.control === "button") {
            input = document.createElement('button');
            input.type = 'button';
            input.id = field.field;
            input.textContent = field.name || "Button";
            if (field.btn_id) input.id = field.btn_id;
            if (field.class) input.className = field.class;
        } else if (field.control === "file") {
            input = document.createElement('input');
            input.type = 'file';
            input.id = field.field;
            input.className = 'form-control';
            input.name = field.field;
            //const attachment = new AttachmentControl('image');
            //document.body.appendChild(attachment);
            if (field.accept) input.accept = field.accept; // e.g., 'image/*' or 'application/pdf'
            if (field.multiple) input.multiple = true; // Allow multiple file selection if required
        } else {
            input = document.createElement('input');
            input.className = 'form-control';
            input.name = field.field;
            input.id = field.field;
            input.value = field.default || "";
            if (field.mandatory) input.required = true;
            input.type = field.control === "datetime-local" ? "datetime-local" : (field.control || 'text');
        }

        if (field.onchange !== null) { 
            console.log("field.onchange");
            input.onchange = window[field.onchange];
            /*input.onchange = field.onchange;*/
        }
        
       
        if (!field.edit) input.setAttribute('disabled', 'true');

        formGroup.appendChild(label);
        formGroup.appendChild(input);
        form.appendChild(formGroup);
    });

    let editModalElement = document.getElementById('registrationModal');
    if (!editModalElement) {
        console.error("Modal not found in the DOM!");
        return;
    }

    editModalElement.removeAttribute("aria-hidden");
    let editModal = new bootstrap.Modal(editModalElement, { backdrop: 'static' });
    editModal.show();

    document.getElementById('register').onclick = async function () {  // Mark function as async
        let newData = {};
        let isValid = true;
        let firstInvalidField = null;
    
        for (const field of fields) {
            if (!field.show) continue;
            let input = form.elements[field.field];
    
            if (!input && field.control !== 'schedule-control' && field.control !== 'venue-control' && field.control !== 'file') {
                console.warn(`Field ${field.field} is missing in the form.`);
                continue;
            }
    
            if (field.mandatory && input && input.value.trim() === "") {
                isValid = false;
                input.classList.add('is-invalid');
                if (!firstInvalidField) firstInvalidField = input;
            } else if (input) {
                input.classList.remove('is-invalid');
            }
    
            if (field.control === 'checkbox') {
                newData[field.field] = input.checked ? 1 : 0;
            } else if (field.control === 'schedule-control') {
                let scheduleElement = document.querySelector("schedule-control");
                if (scheduleElement) {
                    newData[field.field] = scheduleElement.value;
                    delete newData.entity_id;
                } else {
                    console.warn(`Schedule control element not found.`);
                }
            } else if (field.control === 'venue-control') {
                let venueElement = document.querySelector("venue-control");
                if (venueElement) {
                    newData[field.field] = venueElement.value;
                } else {
                    console.warn(`Venue control element not found.`);
                }
            }else if (field.control === 'attachment-control') {
                let attachmentElement = document.querySelector("attachment-control");
                if (attachmentElement) {
                    newData[field.field] = attachmentElement.value;
                } else {
                    console.warn(`Venue control element not found.`);
                } 
            }
            else if (field.control === "file") {
                //await uploadFile(field, newData); // Await file upload
                newData.file = await storeFileForUpload(field);

            } else if (input) {
                newData[field.field] = input.value;
            }
        }
    
        if (!isValid) {
            alert("Please fill in all required fields before saving.");
            firstInvalidField?.focus();
            return;
        }
    
        console.log("New Data:", newData);
        createEntry(newData);
        editModal.hide();
    };

    document.getElementById('save').onclick = async function () {  // Async function for Save button
        let newData = {};
    
        for (const field of fields) {
            if (!field.show) continue;
            let input = form.elements[field.field];
    
            if (!input && field.control !== 'schedule-control' && field.control !== 'venue-control' && field.control !== 'file') {
                console.warn(`Field ${field.field} is missing in the form.`);
                continue;
            }
    
            if (field.control === 'checkbox') {
                newData[field.field] = input.checked ? 1 : 0;
            } else if (field.control === 'schedule-control') {
                let scheduleElement = document.querySelector("schedule-control");
                newData[field.field] = scheduleElement ? scheduleElement.value : "";
            } else if (field.control === 'venue-control') {
                let venueElement = document.querySelector("venue-control");
                newData[field.field] = venueElement ? venueElement.value : "";
            } else if (field.control === "file") {
                newData.file = await storeFileForUpload(field);  // Store file for later upload
            } else if (input) {
                newData[field.field] = input.value;
            }
        }
    
        // ✅ Always set status to "draft"
        newData.status = "draft";
    
        console.log("New Data (Saved as Draft):", newData);
        createEntry(newData);
        editModal.hide();
    };    
    
    async function uploadFile(field, newData) {
        console.log("Starting file upload process...");
        
        let fileElement = document.querySelector(`input[type="file"]#${field.field}`);
        
        if (fileElement && fileElement.files.length > 0) {
            let file = fileElement.files[0];
            console.log("File selected:", file.name, "Size:", file.size, "Type:", file.type);
    
            let formData = new FormData();
            formData.append("file", file); // Ensure "file" matches Flask's request.files['file']
    
            console.log("FormData contents:");
            for (let pair of formData.entries()) {
                console.log(pair[0], pair[1]);
            }
    
            try {
                console.log("Sending file upload request to server...");
                
                let response = await fetch("http://127.0.0.1:5000/upload", {
                    method: "POST",
                    body: formData
                });
    
                console.log("Response received from server. Status:", response.status);
    
                let result = await response.json();
                console.log("Server response JSON:", result);
    
                if (response.ok) {
                    console.log("File uploaded successfully:", result);
                    newData[field.field] = file.name || "Uploaded Successfully"; // Adjust based on API response
                } else {
                    console.error("File upload failed. Server responded with:", result.message);
                }
            } catch (error) {
                console.error("Error during file upload:", error);
            }
        } else {
            console.warn("No file selected for upload.");
        }
    }

    async function storeFileForUpload(field) {
        console.log("Starting file upload process...");
        
        let fileElement = document.querySelector(`input[type="file"]#${field.field}`);
        
        if (fileElement && fileElement.files.length > 0) {
            let file = fileElement.files[0];
            console.log("File selected:", file.name, "Size:", file.size, "Type:", file.type);
    
            let formData = new FormData();
            formData.append("file", file); // Ensure "file" matches Flask's request.files['file']
    
            console.log("FormData contents:");
            for (let pair of formData.entries()) {
                console.log(pair[0], pair[1]);
            }

            let fileUploadDetails = {url:"http://127.0.0.1:5000/upload", method: "POST",body: formData, fieldName:field.field};
            return fileUploadDetails;
    }
    
    }
  
    /** Function to validate and store schedule temporarily **/
    document.getElementById("venueForm").onsubmit = function (e) {
        e.preventDefault();
    
        let isValid = true;
        let errorMessage = "";
    
        // Get form values
        let building = document.getElementById('building').value.trim();
        let street = document.getElementById('street').value.trim();
        let area = document.getElementById('area').value.trim();
        let city = document.getElementById('city').value.trim();
        let state = document.getElementById('state').value.trim();
        let country = document.getElementById('country').value.trim();
        let url = document.getElementById('url_address').value.trim();
        let lat = document.getElementById('latitude').value.trim();
        let long = document.getElementById('longitude').value.trim();
    
        // Validation checks
        if (!building || !street || !area || !city || !state || !country) {
            isValid = false;
            errorMessage += "All text fields are required.\n";
        }
    
        // Validate latitude & longitude (must be numbers)
        if (lat && isNaN(lat)) {
            isValid = false;
            errorMessage += "Latitude must be a valid number.\n";
        }
    
        if (long && isNaN(long)) {
            isValid = false;
            errorMessage += "Longitude must be a valid number.\n";
        }
    
        // Validate URL (if provided)
        if (url && !/^https?:\/\/[\w\-]+(\.[\w\-]+)+[/#?]?.*$/.test(url)) {
            isValid = false;
            errorMessage += "Please enter a valid URL.\n";
        }
    
        if (!isValid) {
            alert(errorMessage); // Show validation errors
            return;
        }
    
        // Construct JSON in the required format
        let venueData = {
            building: building,
            street: street,
            area: area,
            city: city,
            state: state,
            country: country,
            url: url,
            lat: lat,
            long: long
        };
    
        console.log("Updated Venue JSON:", venueData);
    
        // Store JSON as a string in the hidden input field
        document.getElementById('venue').value = JSON.stringify(venueData);
    
        // Hide the modal after submission
        bootstrap.Modal.getInstance(document.getElementById('venueModal')).hide();
    };
    
    
}

    document.getElementById("eventForm_new").addEventListener("submit", function (event) {
        debugger;
        event.preventDefault(); // Prevent actual form submission

        console.log("✅ Inside event form");

        let eventName = document.getElementById("eventName").value.trim();
        let eventDescription = document.getElementById("eventDescription").value.trim();
        let eventStartDate = document.getElementById("eventStartDate").value;
        let eventEndDate = document.getElementById("eventEndDate").value || null; // Null if empty

        console.log("Event Name:", eventName);
        console.log("Description:", eventDescription);
        console.log("Start Date:", eventStartDate);
        console.log("End Date:", eventEndDate);

        if (!eventName || !eventStartDate) {
            alert("⚠️ Event Name and Start Date are required!");
            return;
        }

        let scheduleRows = document.querySelectorAll(".schedule-row");

        // Mapping numeric day values to corresponding weekdays
        const dayMapping = {
            "0": "sun",
            "1": "mon",
            "2": "tues",
            "3": "wed",
            "4": "thur",
            "5": "fri",
            "6": "sat"
        };

        let eventData = {
            title: eventName,
            description: eventDescription,
            start_date: eventStartDate,
            end_date: eventEndDate
        };

        scheduleRows.forEach((row) => {
            let day = row.querySelector(".day-select").value;
            let startTime = row.querySelector(".start-time").value;
            let endTime = row.querySelector(".end-time").value;

            if (!startTime || !endTime) {
                alert("⚠️ Start and End time are required!");
                return;
            }

            let dayName = dayMapping[day];

            if (!eventData[dayName]) {
                eventData[dayName] = [];
            }

            eventData[dayName].push([startTime, endTime]);
        });

        console.log("📌 Final Event Data:", JSON.stringify(eventData, null, 2));

        let workDaysInput = document.getElementById("work_days");
        if (workDaysInput) {
            workDaysInput.value = JSON.stringify(eventData);
            console.log("✅ Work days saved:", workDaysInput.value);
        } else {
            console.error("❌ work_days input field not found!");
        }

        // Close the modal after saving
        let addEventModal = bootstrap.Modal.getInstance(document.getElementById("addEventModal"));
        addEventModal.hide();

        alert("✅ Schedule saved successfully!");
    });


    // Periodically check for pending requests
    setInterval(async () => {
        if (navigator.onLine) {
            console.log("[Network] Checking pending requests...");
            await processOfflineRequests();
        }
    }, 15000);
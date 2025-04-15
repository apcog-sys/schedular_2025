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
var  caldata={},    selectedItemFromDropdown=null,  role="Admin";
var tab_status={};
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
                refreshTable();   
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
    const container = document.getElementById("tab_page_header");
    if (!container) {
        console.error(`Element with id 'tab_page_content' not found.`);
        return;
    }
     // Create a div for buttons
     console.log(selectedItemFromDropdown)
     var divControls = document.createElement('div');
     if(selectedItemFromDropdown == null){
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
                        defaultOption.value = "";
                        defaultOption.textContent = "Select Config";
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
                            console.log(`Selected Config: ${this.value}`);
                            selectedItemFromDropdown=this.value;    get_data_list(this.value,{}); 
                            /*if (this.value== "Roles") { get_roles_list();}
                            else if (this.value== "Event Categories") {get_eventCategories_list();}
                            else if (this.value== "Resource Categories") {get_resourceCategories_list();}
                            else if (this.value== "Messages") {get_resourceCategories_list();}*/
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
    var  hasField= false;
    // Create input fields for each visible column
    console.log(visibleFields)
    visibleFields.forEach(element => {
        try {
            console.log(element.filter_type)
            
            if(element.filter_type === "datetime"){
                //let br = document.createElement("br");
                //filterForm.appendChild(br);
                var datTimeFilterObj = [{"start":"", "end":""}]; // Ensure an array of two values (FROM, TO)

                let div1 = document.createElement("div");
                div1.className = "mb-3";

                let label1 = document.createElement("label");
                label1.innerHTML = element.field + " FROM:";
                label1.className = "form-label"; // Bootstrap styling

                let input1 = document.createElement("input");
                input1.type = "datetime-local";
                input1.placeholder = "FROM";
                input1.className = "form-control";
                input1.name = element.field;

                // Update the array at index 0 when input changes
                input1.addEventListener("input", function () {
                    datTimeFilterObj[0].start = this.value;
                    filterValues[element.key || element.field] = [...datTimeFilterObj]; // Clone array to avoid reference issues
                });

                div1.appendChild(label1);
                div1.appendChild(input1);
                filterForm.appendChild(div1);

                let div2 = document.createElement("div");
                div2.className = "mb-3";

                let label2 = document.createElement("label");
                label2.innerHTML = element.field + " TO:";
                label2.className = "form-label"; // Bootstrap styling

                let input2 = document.createElement("input");
                input2.type = "datetime-local";
                input2.placeholder = "TO";
                input2.className = "form-control";
                input2.name = element.field;

                // Update the array at index 1 when input changes
                input2.addEventListener("input", function () {
                    datTimeFilterObj[0].end = this.value;
                    filterValues[element.key || element.field] = [...datTimeFilterObj]; // Clone array to avoid reference issues
                });

                div2.appendChild(label2);
                div2.appendChild(input2);
                filterForm.appendChild(div2);   hasField= true;

            }
            else if (element.filter_type === "dropdown") {
                let div = document.createElement("div");
                div.className = "mb-3";
            
                let select = document.createElement("select");
                select.className = "form-select"; // Bootstrap's default select class ensures the arrow is visible
                select.name = element.field;
            
                // Add default empty option
                let defaultOption = document.createElement("option");
                defaultOption.value = "";
                defaultOption.textContent = element.field;
                select.appendChild(defaultOption);
            
                // Function to populate dropdown options
                function populateOptions(options) {
                    options.forEach(value => {
                        let option = document.createElement("option");
                        option.value = value;
                        option.textContent = value;
                        if (filterValues[element.key || element.field] === value) {
                            option.selected = true; // Maintain previous selection
                        }
                        select.appendChild(option);
                    });
                }
            
                // Check if filter_helper is defined
                if (element.filter_helper) {
                    fetchHelperData(element.filter_helper).then(helperOptions => {
                        if (Array.isArray(helperOptions)) {
                            populateOptions(helperOptions);
                        }
                    }).catch(error => console.error("Error fetching helper data:", error));
                } else if (Array.isArray(element.filter_value)) {
                    populateOptions(element.filter_value);
                }
            
                // Store selected value on change
                select.addEventListener("change", function () {
                    filterValues[element.key || element.field] = this.value;
                });
            
                div.appendChild(select);
                filterForm.appendChild(div);
            
                // Set flag indicating at least one field exists
                hasField = true;
            }
            
            else if (element.filter_type === "textbox" || element.filter_type === "lable"){
                
                let input = document.createElement("input");
                input.setAttribute("type", "text");
                input.setAttribute("placeholder", `${element.label || element.field}`);
                input.className = "form-control";
                input.style.width = "auto"; // Allow input fields to shrink
                
                // Maintain previous filter values
                input.value = filterValues[element.key || element.field] || element.filter_value || "";

                if (element.filter_type === "lable") {
                    input.setAttribute("readonly", true);
                }
                input.addEventListener("input", function () {
                    filterValues[element.key || element.field] = this.value;
                });
                
                filterForm.appendChild(input);  hasField= true;
            }
            // Store value on change
            
           
            //if(element.filter_type === "datetime")filterForm.appendChild(input2);
        } catch (err) {
            console.log(err);
        }
    });

    // Add the Filter button
    if(hasField === true){
        let filterButton = document.createElement("button");
        filterButton.textContent = "Filter";
        filterButton.className = "btn btn-primary";

        filterButton.addEventListener("click", function () {
            //validateFilterValues();
            let filterQuery = { where: { ...filterValues } };

            console.log("Filter Query:", filterQuery);
            console.log(selectedItemFromDropdown, filterValues);

            // Refresh only the table data without resetting filters
            get_data_list(selectedItemFromDropdown, filterValues);
        });
        let br = document.createElement("br");
        filterForm.appendChild(br);
        filterForm.appendChild(filterButton);
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

    // Add Dynamic Fields as Table Headers (Sortable)
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
        //sortIcon.style.fontSize = "12px";
        //sortIcon.style.opacity = "0.5";
        

    
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

        // Data Columns
        visibleFields.forEach(field => {
            let td = document.createElement('td');
            td.className = "text-center";
            td.setAttribute("data-field", field.field);

                if (field.field.toLowerCase() === "remark" || field.field.toLowerCase() === "schedule" || field.field.toLowerCase() === "venue") {
                    let viewBtn = document.createElement("button");
                    viewBtn.className = "btn btn-info btn-sm";
                    viewBtn.innerHTML = "View";
                    viewBtn.onclick = function () {
                        console.log(1)
                        /*if (selectedItemFromDropdown === "Resource Registry" && field.field.toLowerCase() === "schedule") {
                            console.log(2);
                            let schedule = rowData[field.field] ? JSON.parse(rowData[field.field]) : null;
                            let details = rowData.details;
                            console.log("Schedule Data:", schedule, details);
                        
                            if (schedule) {
                                let calendarEl = document.getElementById("calendar");
                        
                                // Clear previous calendar instance
                                calendarEl.innerHTML = "";
                        
                                // Convert start & end dates to Date objects
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
                        
                                            // Parse hours and minutes properly
                                            let [startHour, startMinute] = startTime.split(":").map(Number);
                                            let [endHour, endMinute] = endTime.split(":").map(Number);
                        
                                            eventStart.setHours(startHour, startMinute, 0);
                                            eventEnd.setHours(endHour, endMinute, 0);
                        
                                            events.push({
                                                title: `${details} (${startTime} - ${endTime})`,
                                                start: eventStart.toISOString(),
                                                end: eventEnd.toISOString(),
                                                description: `Scheduled Time: ${startTime} - ${endTime}`,
                                                backgroundColor: "#28a745", // Green color for a distinct look
                                                textColor: "#ffffff", // White text for contrast
                                                borderColor: "#1e7e34", // Darker green border
                                            });
                                        });
                                    }
                                    currentDate.setDate(currentDate.getDate() + 1); // Move to the next day
                                }
                        
                                console.log("Generated Events:", events);
                        
                                // Initialize FullCalendar
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
                                        info.el.style.padding = "5px"; // Add padding for better spacing
                                        info.el.style.borderRadius = "5px"; // Round edges for better UI
                                    },
                                    eventClick: function (info) {
                                        alert(`Event: ${info.event.title}\nDetails: ${info.event.extendedProps.description}`);
                                    }
                                });
                        
                                calendar.render();
                        
                                // Show Calendar Modal
                                let modalInstance = new bootstrap.Modal(document.getElementById("myCalendar"));
                                modalInstance.show();
                            } else {
                                alert("No work days available.");
                            }
                        }*/
                        if (selectedItemFromDropdown === "Resource Registry" && field.field.toLowerCase() === "schedule") {
                            console.log(2);
                            let schedule = rowData[field.field] ? JSON.parse(rowData[field.field]) : null;
                            let details = rowData.details;
                            console.log("Schedule Data:", schedule, details);
                        
                            if (schedule) {
                                let calendarEl = document.getElementById("calendar");
                        
                                // Clear previous calendar instance
                                calendarEl.innerHTML = "";
                        
                                // Convert start & end dates
                                let startDate = new Date(schedule.startDate);
                                let endDate = new Date(schedule.endDate);
                        
                                if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
                                    alert("Invalid event date format!");
                                    return;
                                }
                        
                                let events = [];
                                let currentDate = new Date(startDate);
                        
                                // Mapping of weekday names to numbers
                                const weekDayMap = {
                                    sunday: 0, monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6
                                };
                        
                                while (currentDate <= endDate) {
                                    let dayName = currentDate.toLocaleString("en-US", { weekday: "long" }).toLowerCase();
                        
                                    if (schedule.workDays[dayName]) {
                                        schedule.workDays[dayName].forEach(timeRange => {
                                            let [startTime, endTime] = timeRange;
                                            let eventDate = new Date(currentDate);
                        
                                            let eventStart = new Date(eventDate);
                                            let eventEnd = new Date(eventDate);
                        
                                            // Parse hours and minutes properly
                                            let [startHour, startMinute] = startTime.split(":").map(Number);
                                            let [endHour, endMinute] = endTime.split(":").map(Number);
                        
                                            eventStart.setHours(startHour, startMinute, 0);
                                            eventEnd.setHours(endHour, endMinute, 0);
                        
                                            events.push({
                                                title: details || "Scheduled Event",
                                                start: eventStart.toISOString(),
                                                end: eventEnd.toISOString(),
                                                description: `Scheduled Time: ${startTime} - ${endTime}`,
                                                backgroundColor: "#007bff", // Default blue
                                                textColor: "#ffffff",
                                                borderColor: "#0056b3"
                                            });
                                        });
                                    }
                                    currentDate.setDate(currentDate.getDate() + 1);
                                }
                        
                                console.log("Generated Events:", events);
                        
                                // Initialize FullCalendar
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
                                        info.el.style.padding = "5px"; // Better spacing
                                        info.el.style.borderRadius = "5px"; // Rounded edges for better UI
                                    },
                                    eventClick: function (info) {
                                        alert(`Event: ${info.event.title}\nDetails: ${info.event.extendedProps.description}`);
                                    }
                                });
                        
                                calendar.render();
                        
                                // Show Calendar Modal
                                let modalInstance = new bootstrap.Modal(document.getElementById("myCalendar"));
                                modalInstance.show();
                            } else {
                                alert("No work days available.");
                            }
                        }
                               
                        else if (field.field.toLowerCase() === "remark") {
                            console.log(3)
                            if (page_load_conf.tab === "Resource") {
                                let content = rowData[field.field] ? JSON.stringify(JSON.parse(rowData[field.field]), null, 2) : "No data available";
                                document.getElementById("remark_content").innerText = content;
                            }
                            if (page_load_conf.tab === "Entity") {
                                let remarks = rowData[field.field]
                                    ? rowData[field.field].split("|").map((item) => `<li>${item.trim()}</li>`).join("")
                                    : "<li>No remarks available</li>";
                                document.getElementById("remark_content").innerHTML = `<ul>${remarks}</ul>`;
                            }
                    
                            let modalInstance = new bootstrap.Modal(document.getElementById("remark_modal"));
                            modalInstance.show();
                        }
                        else if (field.field.toLowerCase() === "venue") {
                            console.log(4)
                            console.log(rowData[field.field]);
                            if (rowData[field.field]) {
                                let jsonData = JSON.parse(rowData[field.field]);
                                
                                // Convert JSON object to a formatted string without {}, "" using map()
                                let formattedContent = Object.entries(jsonData)
                                    .map(([key, value]) => `${key}: ${value}`)
                                    .join("\n");
                        
                                // Use <pre> for better display
                                document.getElementById("remark_content").innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${formattedContent}</pre>`;
                            } else {
                                document.getElementById("remark_content").innerText = "No data available";
                            }
                            let modalInstance = new bootstrap.Modal(document.getElementById("remark_modal"));
                            modalInstance.show();
                        }
                        console.log(5)
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
            input.setAttribute("value", element.filter_value);
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
    let requestData = { requestor_id:"", request_token:"", type:"",qry:{"where_data":{}}};
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
   /* const apiConfig = {
        "Entity": { api: "entity/list_details", key: "entity_id" },
        "Resource": { api: "resource/list_details", key: "resource_id" },
        "Event": { api: "event/list_details", key: "event_id" },
        "Alert": { api: "alert/list_details", key: "alert_id" },
        "Messages": { api: "message/list_details", key: "message_id" },
        "Subscriber": { api: "subscriber/list_details", key: "subscriber_id" },
        "Appointment": { api: "appointment/list_details", key: "appointment_id" },
        "Log": { api: "log/list_details", key: "log_id" },
        "Roles": { api: "config/list_details", key: "role_id" },
        "Event Categories": { api: "config/list_details", key: "event_type_id" },
        "Resource Categories": { api: "config/list_details", key: "resource_type_id" },
        "Messages": { api: "config/list_details", key: "message_id" }
    };

    // Check if the tab exists in the configuration
    if (!apiConfig[page_load_conf.tab]) {
        console.log("Could not locate the tab",selectedItemFromDropdown);
        if (!apiConfig[selectedItemFromDropdown]) {return;}
        else{apiConfigKey=selectedItemFromDropdown; modal_body.type=selectedItemFromDropdown}
    }
    else{apiConfigKey=page_load_conf.tab}

    // Extract API details dynamically
    const { api, key } = apiConfig[apiConfigKey];*/
    var key_val =MainConfig[page_load_conf.tab][selectedItemFromDropdown].key
    var api = MainConfig[page_load_conf.tab][selectedItemFromDropdown].getDataApi
    modal_body = {
        "requestor_id": "",
        "request_token": "",
        "type": selectedItemFromDropdown,
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

   /* if (page_load_conf.tab === "Entity") {
        if (role == "Admin") { data = entity_config.update.data[0]; }
        if (role == "Approver") { data = entity_config.approver.data[0]; }
    }
    else if (page_load_conf.tab === "Resource") {
        if (role == "Admin") { data = resource_config.update.data[0]; }
        if (role == "Approver") { data = resource_config.approver.data[0]; }
    }
    else if (page_load_conf.tab === "Event") {
        if (role == "Admin") { data = event_config.update.data[0]; }
        if (role == "Approver") { data = event_config.approver.data[0]; }
    }
    else if (page_load_conf.tab === "Alert") {
        if (role == "Admin") { data = alert_config.update.data[0]; }
        if (role == "Approver") { data = alert_config.approver.data[0]; }
    }
    else if (page_load_conf.tab === "Messages") {
        if (role == "Admin") { data = message_config.update.data[0]; }
        if (role == "Approver") { data = message_config.approver.data[0]; }
    }
    else if (page_load_conf.tab === "Subscriber") {
        if (role == "Admin") { data = subscriber_config.update.data[0]; }
        if (role == "Approver") { data = subscriber_config.approver.data[0]; }
    }
    else if (page_load_conf.tab === "Log") {
        if (role == "Admin") { data = log_config.update.data[0]; }
        if (role == "Approver") { data = log_config.approver.data[0]; }
    }
    else {console.log("Could not locate the tab")}
    console.log(data);*/

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
        
                   /* // Extract and format dates
                    if (workDaysData.start) {
                        let startDateTime = new Date(workDaysData.start);
                        document.getElementById('eventStartDate').value = startDateTime.toISOString().split("T")[0]; 
                    }
        
                    if (workDaysData.end) {
                        let endDateTime = new Date(workDaysData.end);
                        document.getElementById('eventEndDate').value = endDateTime.toISOString().split("T")[0];
                    }*/
        
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

    // Handle event modal form submission
    /*document.getElementById("eventForm").onsubmit = function (e) {
        e.preventDefault();

        // Construct JSON in required format
        let startDateTime = new Date(document.getElementById('eventStartDate').value + "T" + document.getElementById('eventStartTime').value + ":00.000Z");
        let endDateTime = new Date(document.getElementById('eventEndDate').value + "T" + document.getElementById('eventEndTime').value + ":00.000Z");

        let updatedWorkDays = {
            title: document.getElementById('eventName').value,
            description: document.getElementById('eventDescription').value,
            start: startDateTime.toISOString(),
            end: endDateTime.toISOString(),
            days: Array.from(document.querySelectorAll('.day-checkbox:checked')).map(cb => parseInt(cb.value)),
            textColor: "#ffffff", 
            backgroundColor: "#007bff"
        };

        console.log("Updated Work Days JSON:", updatedWorkDays);

        document.getElementById('work_days').value = JSON.stringify(updatedWorkDays);
        bootstrap.Modal.getInstance(document.getElementById('addEventModal')).hide();
    };*/

    // Handle venue modal form submission
    /*document.getElementById("venueForm").onsubmit = function (e) {
        e.preventDefault();
    
        // Construct JSON in the required format
        let venueData = {
            building: document.getElementById('building').value,
            street: document.getElementById('street').value,
            area: document.getElementById('area').value,
            city: document.getElementById('city').value,
            state: document.getElementById('state').value,
            country: document.getElementById('country').value,
            url: document.getElementById('url_address').value,
            lat: document.getElementById('latitude').value,
            long: document.getElementById('longitude').value
        };
    
        console.log("Updated Venue JSON:", venueData);
    
        // Store JSON as a string in the hidden input field
        document.getElementById('venue').value = JSON.stringify(venueData);
    
        // Hide the modal after submission
        bootstrap.Modal.getInstance(document.getElementById('venueModal')).hide();
    };*/
    
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

    document.getElementById('saveChanges').onclick = function () {
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
        /*if (page_load_conf.tab == "Entity") { updateEntry(rowData.entity_id, updatedData);}
        else if (page_load_conf.tab == "Resource") { updateEntry(rowData.resource_id, updatedData);}
        else if (page_load_conf.tab == "Event") { updateEntry(rowData.event_id, updatedData);}
        else if (page_load_conf.tab == "Alert") { updateEntry(rowData.alert_id, updatedData);}
        else { console.log("Invalid tab selection"); }*/

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
        
       /* if (field.field === "work_days") {
            input = document.createElement('input');
            input.className = 'form-control';
            input.name = field.field;
            input.id = 'work_days';
            input.readOnly = true;
            formGroup.appendChild(input);
        
            let eventButton = document.createElement('button');
            eventButton.type = 'button';
            eventButton.textContent = "View";
            eventButton.className = 'btn btn-primary mt-2';
        
            eventButton.onclick = function () {
                console.log("Opening work_days modal...");
        
                // Clear previous schedule entries
                let scheduleContainer = document.getElementById('scheduleContainer');
                scheduleContainer.innerHTML = "";
        
                // Show modal
                let addEventModal = new bootstrap.Modal(document.getElementById('addEventModal'));
                addEventModal.show();
            };
        
            formGroup.appendChild(eventButton);
            //debugger;
        }*/

            

        /** Function to validate and store schedule temporarily **/
       /* document.getElementById("eventForm").onsubmit = function (event) {
            event.preventDefault(); // Prevent actual form submission

            let scheduleRows = document.querySelectorAll('.schedule-row');
            let scheduleData = [];

            scheduleRows.forEach(row => {
                let day = row.querySelector('.day-select').value;
                let startTime = row.querySelector('.start-time').value;
                let endTime = row.querySelector('.end-time').value;

                if (!startTime || !endTime) {
                    alert("Start and End time are required!");
                    return;
                }

                // Check for overlapping times on the same day
                let existing = scheduleData.filter(e => e.day === day);
                for (let slot of existing) {
                    if (
                        (startTime >= slot.startTime && startTime < slot.endTime) ||
                        (endTime > slot.startTime && endTime <= slot.endTime) ||
                        (startTime <= slot.startTime && endTime >= slot.endTime)
                    ) {
                        alert(`Time conflict detected for ${["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][day]}. Adjust the schedule.`);
                        return;
                    }
                }

                scheduleData.push({ day, startTime, endTime });
            });
            alert(scheduleData)
            console.log("Saved Schedule:", scheduleData);
            alert("Schedule saved successfully!");

            // Close modal after saving
            let addEventModal = bootstrap.Modal.getInstance(document.getElementById('addEventModal'));
            addEventModal.hide();
        };*/

              
        /*if (field.field === "venue") {
            input = document.createElement('input');
            input.className = 'form-control';
            input.name = field.field;
            input.id = 'venue';
            input.readOnly = true;
            formGroup.appendChild(input);
            
            let eventButton = document.createElement('button');
            eventButton.type = 'button';
            eventButton.textContent = "Add venue";
            eventButton.className = 'btn btn-primary mt-2';
            eventButton.onclick = function () {
                let venueModal = document.getElementById('venueModal');
                
                // Reset all input fields in the modal
                document.getElementById('building').value = ""; document.getElementById('street').value = "";   document.getElementById('area').value = "";
                document.getElementById('city').value = ""; document.getElementById('state').value = "";    document.getElementById('country').value = "";
                document.getElementById('url_address').value = "";  document.getElementById('latitude').value = ""; document.getElementById('longitude').value = "";
            
                // Show the modal
                let addEventModal = new bootstrap.Modal(venueModal);
                addEventModal.show();
            };
            
            formGroup.appendChild(eventButton);
        }*/

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

    /*document.getElementById('register').onclick = function () {
        let newData = {};
        let isValid = true;
        let firstInvalidField = null;

        fields.forEach(field => {
            console.log(field)
            if (!field.show) return;
            let input = form.elements[field.field];

            if (field.mandatory && input.value.trim() === "") {
                isValid = false;
                input.classList.add('is-invalid');
                if (!firstInvalidField) firstInvalidField = input;
            } else {
                input.classList.remove('is-invalid');
            }

            if (field.control === 'checkbox') {
                newData[field.field] = input.checked ? 1 : 0;
            } else {
                newData[field.field] = input.value;
            }
        });

        if (!isValid) {
            alert("Please fill in all required fields before saving.");
            firstInvalidField?.focus();
            return;
        }

        if (document.getElementById('schedule')) {
            console.log(scheduleElement.value);
            //document.getElementById('work_days').value = JSON.stringify(newData);
        }
        if (selectedItemFromDropdown=="Resource Registry")
        {
            
            // Remove `entityname`
            delete newData.entityname;
            
            // Parse `work_days` JSON string
            let workDaysData = JSON.parse(newData.work_days);
            
            // Extract start_date, end_date, and day-wise schedules
            ["start_date", "end_date"].forEach(key => {
                if (workDaysData[key]) {
                    newData[key] = workDaysData[key];
                }
            });
            
            // Extract day-wise schedules and add them to the main object

            Object.keys(workDaysData).forEach(key => {
                if (!["title", "description", "start_date", "end_date"].includes(key)) {
                    newData[key] = JSON.stringify({ timings: workDaysData[key] });    // Wrap the value inside an object


                }
            });
            newData.details=JSON.stringify({"description":workDaysData.description})
            
            
            console.log(">>> ********",newData);
            
        }

        console.log("New Data:", newData);
        createEntry(newData);
        editModal.hide();
    };*/

    /*document.getElementById('register').onclick = function () {
        let newData = {};
        let isValid = true;
        let firstInvalidField = null;
    
        fields.forEach(field => {
            if (!field.show) return;
    
            let input = form.elements[field.field];
    
            if (!input && field.control !== 'schedule-control') {
                console.warn(`Field ${field.field} is missing in the form.`);
                return; // Skip this field if not found
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
                    delete newData.entity_id
                } else {
                    console.warn(`Schedule control element not found.`);
                }
            } else if (input) {
                newData[field.field] = input.value;
            }
        });
    
        if (!isValid) {
            alert("Please fill in all required fields before saving.");
            firstInvalidField?.focus();
            return;
        }
    
        console.log("New Data:", newData);
        createEntry(newData);
        editModal.hide();
    };*/
    

    // **Handle Save on External Button Click**
    document.getElementById('register').onclick = function () {
        let newData = {};
        let isValid = true;
        let firstInvalidField = null;

        fields.forEach(field => {
            if (!field.show) return;
            let input = form.elements[field.field];

            if (!input && field.control !== 'schedule-control' && field.control !== 'venue-control') {
                console.warn(`Field ${field.field} is missing in the form.`);
                return;
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
            } else if (input) {
                newData[field.field] = input.value;
            }
        });

        if (!isValid) {
            alert("Please fill in all required fields before saving.");
            firstInvalidField?.focus();
            return;
        }

        console.log("New Data:", newData);
        createEntry(newData);
        editModal.hide();
    };

  
    

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

function refreshTable(){
    /*if(page_load_conf.tab=="Entity"){ tab_status[page_load_conf.tab]=0; get_entity_list();}   
    if(page_load_conf.tab=="Resource"){ tab_status[page_load_conf.tab]=0; get_resource_list();}
    if(page_load_conf.tab=="Event"){ tab_status[page_load_conf.tab]=0; get_event_list();}
    if(page_load_conf.tab=="Alert"){ tab_status[page_load_conf.tab]=0; get_alert_list();}*/
}



/*
for log_category in log tab
1. administrative log
2. performance log
3. event log
4. error log
5. transaction log [system logging automatted task]

*/ 

/**
 * Appointment slot must be vallidated for exclusivitybefore fixing appointment
 * if the target slot is booked already ?
 *      if the target slot non exclusive
 *          if request is also non exclusive
 *              then book the slot
 *          else
 *              return exclusive slot not available 
 *      else
 *          return slot is reserved exclusive for other party
 * else
 *     return booked the slot
 */



/*
    Entity Config
    - Role Registry
    - Resource Category
    - Resource Registry
    - Event Category 
    - entity log 
    "Role Registry","Resource Category","Resource Registry","Event Category","Entity log" 
    
    
    Network Config
    - entity category
    - entity registry
    - network log 

    "Entity Category,"Entity Registry","Network Log"

    System Config
    - Doc_status_type
    - message_settings
    - system log 

     "Doc_status_type","message_settings","system log" 
    
    Event Config
    - event schedule
    - alert schedule
    - appointment schedule
    - event log
    - subscriber registry
    - subscriber log

    "Event Schedule","Alert Schedule","Appointment Schedule","Event Log,"Subscriber Registry","Subscriber Log"

    Subscriber Config
    - subscriber registry
    - subscriber log

    "Subscriber Registry","Subscriber Log"


*/


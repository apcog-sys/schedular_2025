var page_load_conf={
    rows_PP:null,
    sort_col:null,
    page_count:0,
    tab:"",
    role:"",
    event:"",
    user_name:"",
    sessionId:""
}

var tab_status={}
page_load_conf.user_name="Sahique";
page_load_conf.sessionId="458523shgjs";
page_load_conf.role="Admin";
page_load_conf.qry={};

console.log(page_load_conf);
load_tabs()
var domain="http://127.0.0.1:5000/"

function load_tabs(){
    var ul = document.getElementById("tab_list");
    var tab_pg_content = document.getElementById("tab_page_content");
    var send_data=JSON.stringify(page_load_conf);
    var end_point = "http://127.0.0.1:5000/get_user_tabs";
    const getData = async(url=end_point,api_method="POST",api_body=send_data) => {     
    console.log(api_body);
    var response;
    response = await fetch(url,{
        method: api_method,
        body: api_body, // string or object
        headers : { 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    });
    if (response.ok) {const raps = await response.json(); myresult = raps;}
    return (myresult);
    }
    getData().then(data => {
    console.log((data.tab_list))
    tab_list=data.tab_list
    console.log(tab_list[0])
    for (var i = 0; i < tab_list.length; i++)
    {
        var li = document.createElement("li");  
        var a = document.createElement("a");
        
        a.setAttribute('data-toggle','tab');
        console.log(tab_list[i].function)
        a.setAttribute('onclick',tab_list[i].function)
        a.innerHTML = tab_list[i].Name;
        a.setAttribute('href',"#"+tab_list[i].Name);

        tab_href_div = document.createElement('div');
        tab_href_div.setAttribute('id',tab_list[i].Name);
        tab_href_div.setAttribute('class',"tab-pane fade");
        tab_href_div.innerHTML="this is tab page "+ tab_list[i].Name;
        
        tab_pg_content.append(tab_href_div);
        li.appendChild(a);
        ul.appendChild(li);
        //name=tab_list[i].Name;
        tab_status[tab_list[i].Name] = 0;
        //tab_status.push(tab_st_data)
    }
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
            const raps = await response.json(); myresult = raps;
        }
        return (myresult);
    }
    getData().then(data => {
        console.log(data)
        init_tab_prepartion(data[0],data[1],data[2])   
    });
    tab_status[page_load_conf.tab]=1;
    console.log(tab_status);
}

function get_entity_list(conf){
    // console.log(conf);
    page_load_conf.tab="Entity";
    page_load_conf.event="entity_list";
    console.log(">>>>>",  page_load_conf);
    if(tab_status[page_load_conf.tab]==0){
    //var send_data=JSON.stringify(page_load_conf);
    //var end_point = "http://127.0.0.1:5000/entity/list_details";
        API_call(domain,"entity/list_details","","GET") 
    }
}

function get_resource_list(conf){
    // console.log(conf);
    //hardcode all data fetches for this function
    // this will result in final dataset
    //use the js file to only describe ui parameters for each field (editable/showable/type of)
    page_load_conf.tab="Resource";
    page_load_conf.event="resource_list";
    console.log(">>>>>",  page_load_conf);
    resource_body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"resource/list_details",resource_body,"POST") 
    } 
}

function get_affiliation_list(conf){
    // console.log(conf);
    page_load_conf.tab="Affiliation";
    page_load_conf.event="affiliation_list";
    console.log(">>>>>",  page_load_conf);
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"affiliation/list_details","","GET") 
    } 
}

function get_allocation_list(conf){
    // console.log(conf);
    page_load_conf.tab="Allocation";
    page_load_conf.event="allocation_list";
    console.log(">>>>>",  page_load_conf);
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"allocation/list_details","","GET") 
    } 
}

function get_event_list(conf){
    // console.log(conf);
    page_load_conf.tab="Event";
    page_load_conf.event="eventn_list";
    console.log(">>>>>",  page_load_conf);
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"event/list_details","","GET") 
    } 
}



function init_tab_prepartion(result,per_config,controls){    
    console.log(result,per_config);
    //console.log(">>>>>",controls)
    // console.log(result,per_config.create);
    var count=2;
    var reg_view_col_names=[""];
    if (page_load_conf.tab!="Staff"){
    for ( var property in result[0] ) { 
        if( per_config['show'].includes(property) ){reg_view_col_names.push(property);}
    }
    console.log(reg_view_col_names)
    
    var n_col=per_config['show'].length;
    try {
        var table = document.getElementById("user_list");
        for(var i = table.rows.length - 1; i > 0; i--){ table.deleteRow(i); }
        table.deleteTHead();
        var th=table.tHead.remove();
    } catch (error) {
        //console.log(error);
    }
    }
    createTable(reg_view_col_names,result,per_config,page_load_conf.tab,controls);
}

function createTable_old(headerList, dataList, permission_config, tab_name, pg_controls) {
    console.log(headerList);
    console.log(dataList);

    // Get the specific tab div
    var main = document.getElementById(tab_name);
    main.setAttribute('tab', 'show');
    main.innerHTML = ""; // Clear previous content

    // Create a container div for controls
    var div_1 = document.createElement('div');
    div_1.setAttribute('id', 'div1');
    div_1.setAttribute('class', 'mb-3'); // Bootstrap margin for spacing

    // Create and append buttons
    for (var y = 0; y < pg_controls.length; y++) {
        var btn = document.createElement(pg_controls[y].type);
        btn.setAttribute('id', 'btn_' + pg_controls[y].name);
        btn.setAttribute('onclick', pg_controls[y].function);
        btn.setAttribute('class', pg_controls[y].class);
        btn.innerHTML = pg_controls[y].name;
        div_1.appendChild(btn);
    }
    main.appendChild(div_1);

    // Create a responsive wrapper for the table
    var tableWrapper = document.createElement('div');
    tableWrapper.setAttribute('class', 'table-responsive');

    // Create the table
    var table = document.createElement('table');
    table.setAttribute('class', 'table table-bordered table-striped table-hover');

    // Create table header
    var MyHeader = table.createTHead();
    var MyRow = MyHeader.insertRow(0);

    // Add an empty header cell for action buttons
    var actionHeader = MyRow.insertCell(0);
    actionHeader.innerHTML = "<strong>Actions</strong>";

    // Add headers for the rest of the columns
    headerList.forEach((header) => {
        var MyCell = MyRow.insertCell();
        MyCell.innerHTML = `<strong onclick='sortTable(${headerList.indexOf(header)})'>${header}</strong>`;
    });

    // Create table body
    var tableBody = table.createTBody();
    if (permission_config.open === true) {
        dataList.forEach((dataRow, rowIndex) => {
            var tr = tableBody.insertRow(rowIndex);

            // Add a cell for action buttons
            var actionCell = tr.insertCell(0);
            var button = document.createElement('button');
            button.setAttribute('class', 'btn btn-primary btn-xs my-xs-btn');
            button.setAttribute('type', 'button');
            button.setAttribute('style', 'margin-right:16px');
            if (permission_config.edit === false) {
                button.setAttribute('disabled', 'true');
            } else {
                button.innerHTML = 'Edit';
                if(page_load_conf.tab == 'Entity'){ button.addEventListener('click', () => create_modal(dataRow.entity_id));}
                if(page_load_conf.tab == 'Resource'){button.addEventListener('click', () => create_modal(dataRow.resource_id));}
                if(page_load_conf.tab == 'Affiliation'){button.addEventListener('click', () => create_modal(dataRow.affiliation_id));}
                if(page_load_conf.tab == 'Allocation'){button.addEventListener('click', () => create_modal(dataRow.id));}
                if(page_load_conf.tab == 'Event'){button.addEventListener('click', () => create_modal(dataRow.id));}
            }
            actionCell.appendChild(button);

            // Add cells for the rest of the data
            headerList.forEach((header) => {
                var td = tr.insertCell();
                td.textContent = dataRow[header] || ""; // Fill with data or empty string
            });
        });
    }

    // Append the table to the responsive wrapper
    tableWrapper.appendChild(table);

    // Append the table wrapper to the main tab div
    main.appendChild(tableWrapper);
}

function createTable_working(headerList, dataList, permission_config, tab_name, pg_controls) {
    console.log(headerList);
    console.log(dataList);

    // Get the specific tab div
    var main = document.getElementById(tab_name);
    main.setAttribute('tab', 'show');
    main.innerHTML = ""; // Clear previous content

    // Create a container div for controls
    var div_1 = document.createElement('div');
    div_1.setAttribute('id', 'div1');
    div_1.setAttribute('class', 'mb-3'); // Bootstrap margin for spacing

    // Create and append buttons
    for (var y = 0; y < pg_controls.length; y++) {
        var btn = document.createElement(pg_controls[y].type);
        btn.setAttribute('id', 'btn_' + pg_controls[y].name);
        btn.setAttribute('onclick', pg_controls[y].function);
        btn.setAttribute('class', pg_controls[y].class);
        btn.innerHTML = pg_controls[y].name;
        div_1.appendChild(btn);
    }
    main.appendChild(div_1);

    // Identify columns with data to ensure alignment
    let validHeaders = headerList.filter(header => dataList.some(row => row[header] !== undefined && row[header] !== ""));

    // Create a responsive wrapper for the table
    var tableWrapper = document.createElement('div');
    tableWrapper.setAttribute('class', 'table-responsive');

    // Create the table
    var table = document.createElement('table');
    table.setAttribute('class', 'table table-bordered table-striped table-hover');

    // Create table header
    var MyHeader = table.createTHead();
    var MyRow = MyHeader.insertRow(0);

    // Add an empty header cell for action buttons
    var actionHeader = MyRow.insertCell(0);
    actionHeader.innerHTML = "<strong>Actions</strong>";

    // Add headers for valid columns only
    validHeaders.forEach((header) => {
        var MyCell = MyRow.insertCell();
        MyCell.innerHTML = `<strong onclick='sortTable(${headerList.indexOf(header)})'>${header}</strong>`;
    });

    // Add a header for the delete button column
    var deleteHeader = MyRow.insertCell();
    deleteHeader.innerHTML = "<strong>Delete</strong>";

    // Create table body
    var tableBody = table.createTBody();
    if (permission_config.open === true) {
        dataList.forEach((dataRow, rowIndex) => {
            var tr = tableBody.insertRow(rowIndex);

            // Add a cell for action buttons
            var actionCell = tr.insertCell(0);
            var button = document.createElement('button');
            button.setAttribute('class', 'btn btn-primary btn-xs my-xs-btn');
            button.setAttribute('type', 'button');
            button.setAttribute('style', 'margin-right:16px');
            if (permission_config.edit === false) {
                button.setAttribute('disabled', 'true');
            } else {
                button.innerHTML = 'Edit';
                if (page_load_conf.tab == 'Entity') { button.addEventListener('click', () => create_modal(dataRow.entity_id)); }
                if (page_load_conf.tab == 'Resource') { button.addEventListener('click', () => create_modal(dataRow.resource_id)); }
                if (page_load_conf.tab == 'Affiliation') { button.addEventListener('click', () => create_modal(dataRow.affiliation_id)); }
                if (page_load_conf.tab == 'Allocation') { button.addEventListener('click', () => create_modal(dataRow.id)); }
                if (page_load_conf.tab == 'Event') { button.addEventListener('click', () => create_modal(dataRow.id)); }
            }
            actionCell.appendChild(button);

            // Add cells for valid columns
            validHeaders.forEach((header) => {
                var td = tr.insertCell();
                td.textContent = dataRow[header] || ""; // Fill with data or empty string
            });

            // Add a cell for the delete button
            var deleteCell = tr.insertCell();
            var deleteButton = document.createElement('button');
            deleteButton.setAttribute('class', 'btn btn-danger btn-xs my-xs-btn');
            deleteButton.setAttribute('type', 'button');
            deleteButton.innerHTML = 'Delete';
            deleteButton.addEventListener('click', () => {
                tr.remove(); // Remove the row from the table
            });
            deleteCell.appendChild(deleteButton);
        });
    }

    // Append the table to the responsive wrapper
    tableWrapper.appendChild(table);

    // Append the table wrapper to the main tab div
    main.appendChild(tableWrapper);
}

function createTable_2(headerList, dataList, permission_config, tab_name, pg_controls) {
    console.log(headerList);
    console.log(dataList);

    // Get the specific tab div
    var main = document.getElementById(tab_name);
    main.setAttribute('tab', 'show');
    main.innerHTML = ""; // Clear previous content

    // Create a container div for controls
    var div_1 = document.createElement('div');
    div_1.setAttribute('id', 'div1');
    div_1.setAttribute('class', 'mb-3'); // Bootstrap margin for spacing

    // Create and append buttons
    for (var y = 0; y < pg_controls.length; y++) {
        var btn = document.createElement(pg_controls[y].type);
        btn.setAttribute('id', 'btn_' + pg_controls[y].name);
        btn.setAttribute('onclick', pg_controls[y].function);
        btn.setAttribute('class', pg_controls[y].class);
        btn.innerHTML = `<i class='fa fa-icon'></i> ${pg_controls[y].name}`;
        div_1.appendChild(btn);
    }
    main.appendChild(div_1);

    // Identify columns with data to ensure alignment
    let validHeaders = headerList.filter(header => dataList.some(row => row[header] !== undefined && row[header] !== ""));

    // Create a responsive wrapper for the table
    var tableWrapper = document.createElement('div');
    tableWrapper.setAttribute('class', 'table-responsive');

    // Create the table
    var table = document.createElement('table');
    table.setAttribute('class', 'table table-bordered table-striped table-hover');

    // Create table header
    var MyHeader = table.createTHead();
    var MyRow = MyHeader.insertRow(0);

    // Add an empty header cell for action buttons
    var actionHeader = MyRow.insertCell(0);
    actionHeader.innerHTML = "<strong>Actions</strong>";

    // Add headers for valid columns only
    validHeaders.forEach((header) => {
        var MyCell = MyRow.insertCell();
        MyCell.innerHTML = `<strong onclick='sortTable(${headerList.indexOf(header)})'>${header}</strong>`;
    });

    // Add a header for the delete button column
    var deleteHeader = MyRow.insertCell();
    deleteHeader.innerHTML = "<strong>Delete</strong>";

    // Create table body
    var tableBody = table.createTBody();
    if (permission_config.open === true) {
        dataList.forEach((dataRow, rowIndex) => {
            var tr = tableBody.insertRow(rowIndex);

            // Add a cell for action buttons
            var actionCell = tr.insertCell(0);
            var button = document.createElement('button');
            button.setAttribute('class', 'btn btn-primary btn-xs my-xs-btn');
            button.setAttribute('type', 'button');
            button.setAttribute('style', 'margin-right:16px');
            button.innerHTML = "<i class='fa fa-edit'></i> Edit";
            if (permission_config.edit === false) {
                button.setAttribute('disabled', 'true');
            } else {
                if (page_load_conf.tab == 'Entity') { button.addEventListener('click', () => create_modal(dataRow.entity_id)); }
                if (page_load_conf.tab == 'Resource') { button.addEventListener('click', () => create_modal(dataRow.resource_id)); }
                if (page_load_conf.tab == 'Affiliation') { button.addEventListener('click', () => create_modal(dataRow.affiliation_id)); }
                if (page_load_conf.tab == 'Allocation') { button.addEventListener('click', () => create_modal(dataRow.id)); }
                if (page_load_conf.tab == 'Event') { button.addEventListener('click', () => create_modal(dataRow.id)); }
            }
            actionCell.appendChild(button);

            // Add cells for valid columns
            validHeaders.forEach((header) => {
                var td = tr.insertCell();
                td.textContent = dataRow[header] || ""; // Fill with data or empty string
            });

            // Add a cell for the delete button
            var deleteCell = tr.insertCell();
            var deleteButton = document.createElement('button');
            deleteButton.setAttribute('class', 'btn btn-danger btn-xs my-xs-btn');
            deleteButton.setAttribute('type', 'button');
            deleteButton.innerHTML = "<i class='fa fa-trash'></i> ";
            deleteButton.addEventListener('click', () => {
                tr.remove(); // Remove the row from the table
            });
            deleteCell.appendChild(deleteButton);
        });
    }

    // Append the table to the responsive wrapper
    tableWrapper.appendChild(table);

    // Append the table wrapper to the main tab div
    main.appendChild(tableWrapper);
    console.log("hoooraayyyyyy")
}

function createTable_3(headerList, dataList, permission_config, tab_name, pg_controls) {
    console.log(headerList);
    console.log(dataList);

    // Get the specific tab div
    var main = document.getElementById(tab_name);
    main.setAttribute('tab', 'show');
    main.innerHTML = ""; // Clear previous content

    // Create a container div for controls
    var div_1 = document.createElement('div');
    div_1.setAttribute('id', 'div1');
    div_1.setAttribute('class', 'mb-3'); // Bootstrap margin for spacing

    // Create and append buttons
    for (var y = 0; y < pg_controls.length; y++) {
        var btn = document.createElement(pg_controls[y].type);
        btn.setAttribute('id', 'btn_' + pg_controls[y].name);
        btn.setAttribute('onclick', pg_controls[y].function);
        btn.setAttribute('class', pg_controls[y].class);
        btn.innerHTML = `<i class='fa fa-icon'></i> ${pg_controls[y].name}`;
        div_1.appendChild(btn);
    }
    main.appendChild(div_1);

    // Ensure column order follows database order
    let orderedHeaders = headerList.filter(header => dataList.some(row => row.hasOwnProperty(header)));

    // Create a responsive wrapper for the table
    var tableWrapper = document.createElement('div');
    tableWrapper.setAttribute('class', 'table-responsive');

    // Create the table
    var table = document.createElement('table');
    table.setAttribute('class', 'table table-bordered table-striped table-hover');

    // Create table header
    var MyHeader = table.createTHead();
    var MyRow = MyHeader.insertRow(0);

    // Add an empty header cell for action buttons
    var actionHeader = MyRow.insertCell(0);
    actionHeader.innerHTML = "<strong>Actions</strong>";

    // Add headers in the correct order
    orderedHeaders.forEach((header) => {
        var MyCell = MyRow.insertCell();
        MyCell.innerHTML = `<strong onclick='sortTable(${headerList.indexOf(header)})'>${header}</strong>`;
    });

    // Add a header for the delete button column
    var deleteHeader = MyRow.insertCell();
    deleteHeader.innerHTML = "<strong>Delete</strong>";

    // Create table body
    var tableBody = table.createTBody();
    if (permission_config.open === true) {
        dataList.forEach((dataRow, rowIndex) => {
            var tr = tableBody.insertRow(rowIndex);

            // Add a cell for action buttons
            var actionCell = tr.insertCell(0);
            var button = document.createElement('button');
            button.setAttribute('class', 'btn btn-primary btn-xs my-xs-btn');
            button.setAttribute('type', 'button');
            button.setAttribute('style', 'margin-right:16px');
            button.innerHTML = "<i class='fa fa-edit'></i> Edit";
            if (permission_config.edit === false) {
                button.setAttribute('disabled', 'true');
            } else {
                if (page_load_conf.tab == 'Entity') { button.addEventListener('click', () => create_modal(dataRow.entity_id)); }
                if (page_load_conf.tab == 'Resource') { button.addEventListener('click', () => create_modal(dataRow.resource_id)); }
                if (page_load_conf.tab == 'Affiliation') { button.addEventListener('click', () => create_modal(dataRow.affiliation_id)); }
                if (page_load_conf.tab == 'Allocation') { button.addEventListener('click', () => create_modal(dataRow.id)); }
                if (page_load_conf.tab == 'Event') { button.addEventListener('click', () => create_modal(dataRow.id)); }
            }
            actionCell.appendChild(button);

            // Add cells for ordered columns
            orderedHeaders.forEach((header) => {
                var td = tr.insertCell();
                td.textContent = dataRow[header] || ""; // Fill with data or empty string
            });

            // Add a cell for the delete button
            var deleteCell = tr.insertCell();
            var deleteButton = document.createElement('button');
            deleteButton.setAttribute('class', 'btn btn-danger btn-xs my-xs-btn');
            deleteButton.setAttribute('type', 'button');
            deleteButton.innerHTML = "<i class='fa fa-trash'></i> Delete";
            deleteButton.addEventListener('click', () => {
                tr.remove(); // Remove the row from the table
            });
            deleteCell.appendChild(deleteButton);
        });
    }

    // Append the table to the responsive wrapper
    tableWrapper.appendChild(table);

    // Append the table wrapper to the main tab div
    main.appendChild(tableWrapper);
}

function createTable(headerList, dataList, permission_config, tab_name, pg_controls) {
    console.log(headerList);
    console.log(dataList);

    // Define exact column order per tab
    const columnOrder = {
        'Entity': [ "entity_name", "entity_type", "created_at", "updated_at", "entry_status", "archive"],
        'Resource': [ "name", "category", "phone", "email", "alert_url", "alert_preference", "status_poll_url"],
        'Affiliation': [ "affilation_id","entity_id","entity_name", "resource_id", "resource_name","resource_category"],
        'Allocation': ["id", "affiliation_id", "from_datime", "to_datime", "week_days"],
        'Event': [ "id", "description", "name", "category", "host_entity_id", "subscriber_limit", "terms", "event_ids", "from_datime", "to_datime", "venue_id"]
    };

    // Get the specific tab div
    var main = document.getElementById(tab_name);
    main.setAttribute('tab', 'show');
    main.innerHTML = ""; // Clear previous content

    // Create a container div for controls
    var div_1 = document.createElement('div');
    div_1.setAttribute('id', 'div1');
    div_1.setAttribute('class', 'mb-3'); // Bootstrap margin for spacing

    // Create and append buttons
    for (var y = 0; y < pg_controls.length; y++) {
        var btn = document.createElement(pg_controls[y].type);
        btn.setAttribute('id', 'btn_' + pg_controls[y].name);
        btn.setAttribute('onclick', pg_controls[y].function);
        btn.setAttribute('class', pg_controls[y].class);
        btn.innerHTML = `<i class='fa fa-icon'></i> ${pg_controls[y].name}`;
        div_1.appendChild(btn);
    }
    main.appendChild(div_1);

    // Use predefined column order based on tab
    let validHeaders = columnOrder[tab_name] || [];

    // Create a responsive wrapper for the table
    var tableWrapper = document.createElement('div');
    tableWrapper.setAttribute('class', 'table-responsive');

    // Create the table
    var table = document.createElement('table');
    table.setAttribute('class', 'table table-bordered table-striped table-hover');

    // Create table header
    var MyHeader = table.createTHead();
    var MyRow = MyHeader.insertRow(0);

    // Add an empty header cell for action buttons
    var actionHeader = MyRow.insertCell(0);
    actionHeader.innerHTML = "<strong>Actions</strong>";

    // Add headers for valid columns only
    validHeaders.forEach((header) => {
        var MyCell = MyRow.insertCell();
        MyCell.innerHTML = `<strong onclick='sortTable(${validHeaders.indexOf(header)})'>${header}</strong>`;
    });

    // Add a header for the delete button column
    var deleteHeader = MyRow.insertCell();
    deleteHeader.innerHTML = "<strong>Delete</strong>";

    // Create table body
    var tableBody = table.createTBody();
    if (permission_config.open === true) {
        dataList.forEach((dataRow, rowIndex) => {
            var tr = tableBody.insertRow(rowIndex);

            // Add a cell for action buttons
            var actionCell = tr.insertCell(0);
            var button = document.createElement('button');
            button.setAttribute('class', 'btn btn-primary btn-xs my-xs-btn');
            button.setAttribute('type', 'button');
            button.setAttribute('style', 'margin-right:16px');
            button.innerHTML = "<i class='fa fa-edit'></i> ";
            if (permission_config.edit === false) {
                button.setAttribute('disabled', 'true');
            } else {
                if (tab_name == 'Entity') { button.addEventListener('click', () => create_modal(dataRow.entity_id)); }
                if (tab_name == 'Resource') { button.addEventListener('click', () => create_modal(dataRow.resource_id)); }
                if (tab_name == 'Affiliation') { button.addEventListener('click', () => create_modal(dataRow.affiliation_id)); }
                if (tab_name == 'Allocation') { button.addEventListener('click', () => create_modal(dataRow.id)); }
                if (tab_name == 'Event') { button.addEventListener('click', () => create_modal(dataRow.id)); }
            }
            actionCell.appendChild(button);

            // Add cells for valid columns in exact order
            validHeaders.forEach((header) => {
                var td = tr.insertCell();
                td.textContent = dataRow[header] || ""; // Fill with data or empty string
            });
            

            // Add a cell for the delete button
            var deleteCell = tr.insertCell();
            var deleteButton = document.createElement('button');
            deleteButton.setAttribute('class', 'btn btn-danger btn-xs my-xs-btn');
            deleteButton.setAttribute('type', 'button');
            deleteButton.innerHTML = "<i class='fa fa-trash'></i> ";
            deleteButton.addEventListener('click', () => {
                tr.remove(); // Remove the row from the table
            });
            deleteCell.appendChild(deleteButton);
        });
    }

    // Append the table to the responsive wrapper
    tableWrapper.appendChild(table);

    // Append the table wrapper to the main tab div
    main.appendChild(tableWrapper);
}





function product_details_iframe(link){
    console.log(link)
    window.open(link);
    
}

function previous_page(){
    if(page_load_conf.page_count == 0){socket.emit('customer_list',page_load_conf);}
    else{var cnt=parseInt(page_load_conf.page_count); cnt=cnt-1;page_load_conf.page_count=cnt;console.log(page_load_conf.page_count); socket.emit('customer_list',page_load_conf);}
}

function next_page(){
// console.log(typeof (page_load_conf.page_count));
    //(page_load_conf.page_count == 0){socket.emit('customer_list',page_load_conf);}
    //else{
    var cnt=parseInt(page_load_conf.page_count); cnt=cnt+1;page_load_conf.page_count=cnt;
    //  console.log(page_load_conf.page_count);
    socket.emit('customer_list',page_load_conf);
    //}
}

function first_page(){  page_load_conf.page_count=0; socket.emit('customer_list',page_load_conf);}

function create_modal(edit_id){
    console.log("edit_id:" +edit_id);
    
    page_load_conf.role=localStorage.getItem("u_role");
    var modal_body={
        event:"",
        role:"Admin",
        sessionId:localStorage.getItem("session_id"),
        qry:{}
    }

    api_name=""; method=""
    console.log(page_load_conf);
    if(page_load_conf.tab=="Entity"){
        modal_body.event="get_entity_details"; 
        api_name="entity/list_details", method="POST"
        modal_body.qry={
            "requestor_id":"",
            "request_token":"",
            "qry":{
                "entity_id":edit_id,
                "category":"",
                "name":"",
                "phone":"",
                "email":"",
                "website":""
            }
            
        }
    }
    if(page_load_conf.tab=="Resource"){
        modal_body.event="get_resource_details"; 
        api_name="resource/list_details", method="POST"
        modal_body.qry={
            "resource_id":edit_id,
            "category":"",
            "name":"",
            "phone":"",
            "email":"",
            "alert_url":"",
            "alert_preference":"",
            "status_poll_url":""
        }
    }
    if(page_load_conf.tab=="Affiliation"){
        modal_body.event="get_affiliation_details"; 
        api_name="affiliation/list_details", method="POST"
        modal_body.qry={
            "affiliation_id":edit_id,
            "entity_id":"",
            "resource_category":"",
            "resource_id":"",
            "work_days":""
        }
    }
    if(page_load_conf.tab=="Event"){
        modal_body.event="get_event_details"; 
        api_name="event/list_details", method="POST"
        modal_body.qry={
            "affiliation_id":edit_id,
            "entity_id":"",
            "resource_category":"",
            "resource_id":"",
            "work_days":""
        }
    }
    if(page_load_conf.tab=="Allocation"){
        modal_body.event="get_allocation_details"; 
        api_name="allocation/list_details", method="POST"
        modal_body.qry={
            "id":edit_id,
            "affiliation_id":"",
            "from_datime":"",
            "to_datime":"",
            "week_days":""
        }
    }
    
    
    var send_data=JSON.stringify(modal_body);
    var end_point = "http://127.0.0.1:5000/"+api_name;
    const getData = async(url=end_point,api_method=method,api_body=send_data) => {     
    console.log(api_body);
    var response;
    response = await fetch(url,{
        method: api_method,
        body: api_body, // string or object
        headers : { 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    });
    
    if (response.ok) {
        const raps = await response.json(); myresult = raps;
    }
    return (myresult);
    }
    getData().then(data => {
    console.log("this is my data",data)
    modal_response(data,edit_id)
    //init_tab_prepartion(data[0],data[1],data[2])   
    });
    console.log("after");
}

function modal_response_latest(data,id_no){
    var result=data[0]; 
    var fields=data[1]; console.log(result, fields);
    //referral_details.camp_id=id_no; //populating campaign id in object
    //referral_details.ref_by=page_load_conf.user_name
    //console.log("ressss:",result);//console.log("fieldsss:",fields);//console.log("idssss",id_no);
    field_val=[]
    let modalBtn = document.getElementById("modal-btn")
    let modal = document.querySelector(".modal")
    let closeBtn = document.querySelector(".close-btn")
    var main= document.getElementById('modal_content')
    var modaldiv=document.createElement('div');
    console.log(page_load_conf)
    refer_data=data
    try {main.innerHTML="";}
    catch (error) { }
    if (page_load_conf.tab=="Advertisements"){
        console.log("Advertisments tabs")
        modaldiv.setAttribute('class','modal-body');
        var bodydiv=document.createElement('div');
        bodydiv.setAttribute('class','mb-3 mt-3');
        console.log(data)

        var init_div=document.createElement('div');
        init_div.setAttribute('class','mb-3 mt-3');
        var name_text=document.createElement('INPUT');
        name_text.setAttribute("type", "text");
        name_text.setAttribute("id", "name_t");
        name_text.setAttribute("placeholder", "Enter Name");
        var number_text=document.createElement('INPUT');
        number_text.setAttribute("type", "text");
        number_text.setAttribute("id", "number_t");
        number_text.setAttribute("placeholder","Enter Contact");
        var add_contact=document.createElement('button');
        add_contact.setAttribute("onclick","register_user()"); 
        add_contact.setAttribute('class','btn btn-success');
        //add_contact.setAttribute('style',"float: left;");
        add_contact.setAttribute("id","add_contact");
        
        add_contact.innerHTML=" + Add "

        init_div.appendChild(name_text); init_div.appendChild(number_text);
        init_div.appendChild(add_contact);modaldiv.appendChild(init_div);

        for(var x=0;x<data.length;x++){
        var check_box=document.createElement('INPUT');
        check_box.setAttribute("type", "checkbox");
        check_box.setAttribute("id", "ck_"+x);
        //check_box.setAttribute("label", data[x][2]+data[x][3]);
        //check_box.setAttribute('onclick','test_fun('+data+')')
        bodydiv.appendChild(check_box);

        var label=document.createElement('lable');
        label.setAttribute('class','form-label')
        label.style.color='white';
        //console.log(data[x][0]+' ('+data[x][1]+')')
        label.innerHTML=' '+data[x][0]+'  ('+data[x][1]+')'
        bodydiv.appendChild(label);
        var next_line=document.createElement('br');
        bodydiv.appendChild(next_line);
        modaldiv.appendChild(bodydiv)
        console.log("added")
        }
        var button=['Refer']
        footer_div= document.createElement('div')
        for(var x=0;x<button.length;x++){
        
        btn=document.createElement('button');
        btn.setAttribute('class','btn btn-success');
        btn.setAttribute('style',"float: left;");
        btn.setAttribute("id",button[x]);
        btn.addEventListener("click", function() {
                get_referal_input(data);
        });
        //btn.setAttribute('onClick', 'test_fun('+refer_data[0]+')');
        btn.innerHTML=button[x];
        footer_div.appendChild(btn)
        }
        
        modaldiv.appendChild(footer_div)
        main.appendChild(modaldiv);
        modal.style.display = "block"
    }
    else{
        for (var z=0;z<fields.length;z++){
            console.log(fields[0][z]);
            var keys2=Object.keys(fields[z]);
            console.log(keys2)
            field_val.push(keys2[0])  
        }
        console.log(field_val);
        var modaldiv=document.createElement('div');
        modaldiv.setAttribute('class','modal-body');
        try {main.innerHTML="";} 
        catch (error) {}
        for(var x=0;x<field_val.length;x++){
        console.log(field_val[x])
        console.log(fields[x])
        if(fields[x][field_val[x]]['show']==true ){
            var d=document.createElement('div');
            d.setAttribute('class','mb-3 mt-3');
            
            var label=document.createElement('lable');
            label.setAttribute('class','form-label');
            label.style.color='black';

            label.innerHTML=field_val[x]+':'
            d.appendChild(label);
            var value = result[0][field_val[x]]; // Get value from result
            console.log(value);
            try {
                var jsonValue = JSON.parse(value);
                console.log("JSON IDENTIFIED");
                if (Array.isArray(jsonValue)) {
                    jsonValue.forEach((entry, index) => {
                        console.log(entry, index);
                        var subDiv = document.createElement('div');
    
                        // Create input fields for each JSON key
                        Object.keys(entry).forEach(key => {
                            var subLabel = document.createElement('label');
                            subLabel.innerHTML = key + ": ";
                            subLabel.style.display = 'block';
                            
                            var subInput = document.createElement('input');
                            subInput.setAttribute('type', 'text');
                            subInput.setAttribute('value', entry[key]);
                            subInput.setAttribute('data-json-key', key); // Custom attribute to track key
                            subInput.setAttribute('data-json-index', index); // Track index
    
                            subDiv.appendChild(subLabel);
                            subDiv.appendChild(subInput);
                        });
    
                        d.appendChild(subDiv);
                        modaldiv.appendChild(d);modaldiv.appendChild(next_line);
                    });
                    if(id_no != "0"){
                        u_input.setAttribute('value',result[0][field_val[x]]);
                        document.getElementById('modal_create_btn').style.display = 'none';
                        
                        document.getElementById('modal_save_btn').style.display = 'block';

                    }
                    else{
                        u_input.setAttribute('value',"");
                        document.getElementById('modal_create_btn').style.display = 'block';
                        
                        document.getElementById('modal_save_btn').style.display = 'none';
                    }
                }
            } catch (e) {
                // If not JSON, create a normal input field
                console.log("NOT JSON ");
                var u_input=document.createElement('input');
                u_input.setAttribute("id",field_val[x]);
                u_input.required;
                //u_input.setAttribute("type","text");
                u_input.setAttribute("type",fields[x][field_val[x]]['datatype']);
                u_input.setAttribute('class','form-control');
                
                if(fields[x][field_val[x]]['edit']==false ){u_input.setAttribute('readOnly','true');}
                if(fields[x][field_val[x]]['create']==true ){u_input.setAttribute('value',"");}
                else{
                    console.log(result[0][field_val[x]])
                    try{
                        if(result[0][field_val[x]]==null){u_input.setAttribute('value',"");}
                        else{
                        console.log(field_val[x],result[0][field_val[x]]);
                        if(id_no != "0"){
                            u_input.setAttribute('value',result[0][field_val[x]]);
                            document.getElementById('modal_create_btn').style.display = 'none';
                           
                            document.getElementById('modal_save_btn').style.display = 'block';

                        }
                        else{
                            u_input.setAttribute('value',"");
                            document.getElementById('modal_create_btn').style.display = 'block';
                           
                            document.getElementById('modal_save_btn').style.display = 'none';
                        }
                        }
                    }
                    catch{
                        u_input.setAttribute('value',"");
                    }
                }
                var next_line=document.createElement('br');
                d.appendChild(u_input);
                modaldiv.appendChild(d);modaldiv.appendChild(next_line);
            }

        }

        }
        // adding status
        /*try{
            if(result[0]['status']!=""){
                var status_div=document.createElement('div');
                var st_label=document.createElement('lable');
                st_label.setAttribute('class','form-label')
                st_label.innerHTML="Status:"
                st_label.style.color='white';
                status_div.appendChild(st_label);

                var st_select=document.createElement('select');
                st_select.setAttribute('id','user_status')
                var options=['enable','disable']
                for(var x=0;x<options.length;x++){
                var st_option=document.createElement('option');
                st_option.innerHTML=options[x];
                st_select.appendChild(st_option)
                status_div.appendChild(st_select)
                }
            }
        modaldiv.appendChild(status_div)
        }catch(error){console.log(error)}*/
        
        /*var button=['Save']
        for(var x=0;x<button.length;x++){
            footer_div= document.createElement('div')
            btn=document.createElement('button');
            btn.setAttribute('class','btn btn-success');
            btn.setAttribute('style',"float: left;");
            btn.setAttribute("id",button[x]);
            
            btn.setAttribute("onclick","get_input()");
            btn.innerHTML=button[x];
            footer_div.appendChild(btn)
        }
        
        modaldiv.appendChild(footer_div)*/
        main.appendChild(modaldiv);
        modal.style.display = "block"
    }
    
    closeBtn.onclick = function(){
        modal.style.display = "none"
    }
    window.onclick = function(e){
        if(e.target == modal){
        modal.style.display = "none"
        }
    }

    //create_form(result);
}

function get_input(mode){
    console.log(field_val);
    input_data=[];
    var send_data="";
    var end_point = "";
    var exe=0;
    var total_commision_val=0
    var fail_stauts=0
    
    for (var z=0;z<field_val.length;z++){
            console.log(field_val[z]);
        if(field_val[z] != 'user_name'){ 
        const inpObj = document.getElementById(field_val[z]);
        console.log(field_val[z],":::",inpObj.value);
        if(field_val[z]=="total_commision"){total_commision_val=inpObj.value}
        if(field_val[z]=="success_comission"){
            success_comission_val=inpObj.value
            if(parseInt(success_comission_val)>parseInt(total_commision_val)){alert("success comission more than total comission")}
            else{referal_comission=parseInt(total_commision_val)-parseInt(success_comission_val)}
        }
        //if(field_val[z]=="referal_comission"){ data.field_val[z]=referal_comission}
        if(field_val[z]=="comission_pattern"){
            var com_pat=inpObj.value.split(",");
            var final_com_pat=0
            com_pat.forEach(element => {
            final_com_pat=final_com_pat+parseInt(element)
            });
            if(final_com_pat==total_commision_val){}
            else{alert("total comission and comission pattern does not match");fail_stauts=1; break;}
        }

        if(inpObj.value != ""|| fail_stauts==0){

            if (!inpObj.checkValidity()) {
            alert(inpObj.validationMessage); break;
            //console.log(inpObj.validationMessage);
            } else {
            console.log("Input OK");input_data.push(inpObj.value)
            //document.getElementById("demo").innerHTML = "Input OK";
            }
            
        }
        else{alert("please enter data in all the fields"); break;} 
        
        }
    }
        //input_data.push(document.getElementById('user_status').value)
        //console.log(input_data);

    //console.log (f_name, l_name,email,phone,status, address1,address2,city,state,postcode,country,u_status);
    console.log(mode)
    // modification and deletion
    if (page_load_conf.tab=="Entity"){
        if(mode=="update"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    entity_id: input_data[0],
                    entity_name: input_data[1],
                    entity_type: input_data[2],
                    created_at: input_data[3],
                    updated_at: input_data[4],
                    entry_status: input_data[5],
                    archive: input_data[6]
                },
                where_data: {
                    entity_id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "entity/modifications";
            method="PUT"
        }
        else if(mode=="create"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    entity_id: input_data[0],
                    entity_name: input_data[1],
                    entity_type: input_data[2],
                    created_at: input_data[3],
                    updated_at: input_data[4],
                    entry_status: input_data[5],
                    archive: input_data[6]
                },
                where_data: {
                    entity_id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "entity/new";
            method="POST"

        }
        else{
            const confirmDelete = () => {
                const userConfirmed = confirm("Are you sure you want to delete this entry?");
                if (userConfirmed) {
                    console.log("User clicked Yes");
                    exe=1;
                    // Proceed with the delete action
                    cutm_data = {
                        where_data: {
                            entity_id: input_data[0]
                        }  
                    };
        
                    console.log(cutm_data);
                    send_data=JSON.stringify(cutm_data);
                    api_name = "entity";
                    method="DELETE"
                } else {
                    console.log("User clicked No");
                    // Cancel the delete action
                }
            };
            confirmDelete()
            
            
        }
        end_point = "http://127.0.0.1:5000/"+api_name;
        if (exe==1){
            const getData = async(url=end_point,api_method=method,api_body=send_data) => {     
                console.log(api_body);
                var response;
                response = await fetch(url,{
                    method: api_method,
                    body: api_body, // string or object
                    headers : { 
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const raps = await response.json(); myresult = raps;
                }
                return (myresult);
            }
            getData().then(data => {
                console.log(data)
                alert(data.message)
                data="";
                // Close the modal
            // $('#myModal').modal('hide'); // Assuming Bootstrap modal
        
                document.getElementById('myModal').modal='block';
                
                location.reload;
                get_entity_list();

            });
            exe=0;
        }
    }

    if (page_load_conf.tab=="Resource"){
        if(mode=="update"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    resource_id: input_data[0],
                    name: input_data[1],
                    category: input_data[2],
                    phone: input_data[3],
                    email: input_data[4],
                    alert_url: input_data[5],
                    alert_preference: input_data[6],
                    status_poll_url: input_data[7]
                },
                where_data: {
                    resource_id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "resource/modifications";
            method="PUT"
        }
        else if(mode=="create"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    resource_id: input_data[0],
                    name: input_data[1],
                    category: input_data[2],
                    phone: input_data[3],
                    email: input_data[4],
                    alert_url: input_data[5],
                    alert_preference: input_data[6],
                    status_poll_url: input_data[7]
                },
                where_data: {
                    resource_id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "resource/modifications";
            method="PUT"
        }
        else{
            const confirmDelete = () => {
                const userConfirmed = confirm("Are you sure you want to delete this entry?");
                if (userConfirmed) {
                    console.log("User clicked Yes");
                    exe=1;
                    // Proceed with the delete action
                    cutm_data = {
                        where_data: {
                            resource_id: input_data[0]
                        }  
                    };
        
                    console.log(cutm_data);
                    send_data=JSON.stringify(cutm_data);
                    api_name = "resource";
                    method="DELETE"
                } else {
                    console.log("User clicked No");
                    // Cancel the delete action
                }
            };
            confirmDelete()
            
            
        }
        end_point = "http://127.0.0.1:5000/"+api_name;
        if (exe==1){
            const getData = async(url=end_point,api_method=method,api_body=send_data) => {     
                console.log(api_body);
                var response;
                response = await fetch(url,{
                    method: api_method,
                    body: api_body, // string or object
                    headers : { 
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const raps = await response.json(); myresult = raps;
                }
                return (myresult);
            }
            getData().then(data => {
                console.log(data)
                alert(data.message)
                data="";
                // Close the modal
            // $('#myModal').modal('hide'); // Assuming Bootstrap modal
        
                document.getElementById('myModal').modal='block';
                
                location.reload;
                get_entity_list();

            });
            exe=0;
        }
    }

    if (page_load_conf.tab=="Affiliation"){
        if(mode=="update"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    affiliation_id: input_data[0],
                    resource_id: input_data[1],
                    entity_id: input_data[2],
                    resource_category: input_data[3],
                    work_days:[{"end_time": input_data[4], "start_time": input_data[5], "day_of_week": input_data[6]}] ,
                },
                where_data: {
                    affiliation_id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "affiliation/modifications";
            method="PUT"
        }
        else if(mode=="create"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    affiliation_id: input_data[0],
                    resource_id: input_data[1],
                    entity_id: input_data[2],
                    resource_category: input_data[3],
                    work_days:[{"end_time": input_data[4], "start_time": input_data[5], "day_of_week": input_data[6]}] ,
                },
                where_data: {
                    affiliation_id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "affiliation/new";
            method="POST"
        }
        else{
            const confirmDelete = () => {
                const userConfirmed = confirm("Are you sure you want to delete this entry?");
                if (userConfirmed) {
                    console.log("User clicked Yes");
                    exe=1;
                    // Proceed with the delete action
                    cutm_data = {
                        where_data: {
                            affiliation_id: input_data[0]
                        }  
                    };
        
                    console.log(cutm_data);
                    send_data=JSON.stringify(cutm_data);
                    api_name = "affiliation";
                    method="DELETE"
                } else {
                    console.log("User clicked No");
                    // Cancel the delete action
                }
            };
            confirmDelete()
            
            
        }
        end_point = "http://127.0.0.1:5000/"+api_name;
        if (exe==1){
            const getData = async(url=end_point,api_method=method,api_body=send_data) => {     
                console.log(api_body);
                var response;
                response = await fetch(url,{
                    method: api_method,
                    body: api_body, // string or object
                    headers : { 
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const raps = await response.json(); myresult = raps;
                }
                return (myresult);
            }
            getData().then(data => {
                console.log(data)
                alert(data.message)
                data="";
                // Close the modal
            // $('#myModal').modal('hide'); // Assuming Bootstrap modal
        
                document.getElementById('myModal').modal='block';
                
                location.reload;
                get_entity_list();

            });
            exe=0;
        }
    }

    if (page_load_conf.tab=="Event"){
        if(mode=="update"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    id: input_data[0],
                    description: input_data[1],
                    name: input_data[2],
                    category: input_data[3],

                    host_entity_id: input_data[4],
                    subscriber_limit: input_data[5],
                    trems: input_data[6],
                    event_ids: input_data[7],

                    from_datime: input_data[8],
                    to_datime: input_data[9],
                    venue_id: input_data[10]
                },
                where_data: {
                    id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "event/modifications";
            method="PUT"
        }
        else if(mode=="create"){
            exe=1;
            console.log("The opened tab is : ",page_load_conf.tab);
            console.log("collected data: ",input_data);
            cutm_data = {
                update_data:{
                    id: input_data[0],
                    description: input_data[1],
                    name: input_data[2],
                    category: input_data[3],

                    host_entity_id: input_data[4],
                    subscriber_limit: input_data[5],
                    trems: input_data[6],
                    event_ids: input_data[7],

                    from_datime: input_data[8],
                    to_datime: input_data[9],
                    venue_id: input_data[10]
                },
                where_data: {
                    id: input_data[0]
                }
                
            };

            console.log(cutm_data);
            send_data=JSON.stringify(cutm_data);
            api_name = "event/new";
            method="POST"
        }
        else{
            const confirmDelete = () => {
                const userConfirmed = confirm("Are you sure you want to delete this entry?");
                if (userConfirmed) {
                    console.log("User clicked Yes");
                    exe=1;
                    // Proceed with the delete action
                    cutm_data = {
                        where_data: {
                            affiliation_id: input_data[0]
                        }  
                    };
        
                    console.log(cutm_data);
                    send_data=JSON.stringify(cutm_data);
                    api_name = "event";
                    method="DELETE"
                } else {
                    console.log("User clicked No");
                    // Cancel the delete action
                }
            };
            confirmDelete()
            
            
        }
        end_point = "http://127.0.0.1:5000/"+api_name;
        if (exe==1){
            const getData = async(url=end_point,api_method=method,api_body=send_data) => {     
                console.log(api_body);
                var response;
                response = await fetch(url,{
                    method: api_method,
                    body: api_body, // string or object
                    headers : { 
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                });
                
                if (response.ok) {
                    const raps = await response.json(); myresult = raps;
                }
                return (myresult);
            }
            getData().then(data => {
                console.log(data)
                alert(data.message)
                data="";
                // Close the modal
            // $('#myModal').modal('hide'); // Assuming Bootstrap modal
        
                document.getElementById('myModal').modal='block';
                
                location.reload;
                get_entity_list();

            });
            exe=0;
        }
    }


        
}


function processJSONField(value, container, dependencies, parentKey = '') {
    console.log(dependencies);
    
    const idFields = ["entity_id", "affiliation_id", "resource_id"];
    if (idFields.includes(parentKey)) {
        return false;
    }

    try {
        var jsonValue = JSON.parse(value);
        console.log("JSON IDENTIFIED for key:", parentKey);

        if (Array.isArray(jsonValue)) {
            jsonValue.forEach((entry, index) => {
                console.log("Processing array entry:", entry, "Index:", index);
                var subDiv = document.createElement('div');
                subDiv.style.marginLeft = '20px';

                Object.keys(entry).forEach(key => {
                    let config = dependencies[key] || { show: true, edit: true, datatype: "text" };

                    if (!config.show) {
                        return;
                    }

                    var subLabel = document.createElement('label');
                    subLabel.innerHTML = `${key}: `;
                    subLabel.style.display = 'block';

                    var inputElement;

                    // Check if the datatype is "dropdown"
                    if (config.datatype === "dropdown") {
                        inputElement = document.createElement('select');

                        let options = config.options || []; // Get predefined options
                        options.forEach(option => {
                            let optionElement = document.createElement('option');
                            optionElement.value = option;
                            optionElement.textContent = option;
                            if (entry[key] === option) optionElement.selected = true;
                            inputElement.appendChild(optionElement);
                        });

                    } else {
                        // Default to input field
                        inputElement = document.createElement('input');
                        inputElement.setAttribute('type', config.datatype || "text");
                        inputElement.setAttribute('value', entry[key]);
                    }

                    inputElement.setAttribute('data-json-key', key);
                    inputElement.setAttribute('data-json-index', index);

                    if (!config.edit) {
                        inputElement.setAttribute('readonly', true);
                    }

                    subDiv.appendChild(subLabel);
                    subDiv.appendChild(inputElement);

                    if (typeof entry[key] === 'object' && entry[key] !== null) {
                        processJSONField(JSON.stringify(entry[key]), subDiv, dependencies, key);
                    }
                });

                container.appendChild(subDiv);
            });
        } else if (typeof jsonValue === 'object' && jsonValue !== null) {
            Object.keys(jsonValue).forEach(key => {
                let config = dependencies[key] || { show: true, edit: true, datatype: "text" };

                if (!config.show) {
                    return;
                }

                var subDiv = document.createElement('div');
                subDiv.style.marginLeft = '20px';

                var subLabel = document.createElement('label');
                subLabel.innerHTML = `${key}: `;
                subLabel.style.display = 'block';

                var inputElement;

                // Check if the datatype is "dropdown"
                if (config.datatype === "dropdown") {
                    inputElement = document.createElement('select');

                    let options = config.options || [];
                    options.forEach(option => {
                        let optionElement = document.createElement('option');
                        optionElement.value = option;
                        optionElement.textContent = option;
                        if (jsonValue[key] === option) optionElement.selected = true;
                        inputElement.appendChild(optionElement);
                    });

                } else {
                    inputElement = document.createElement('input');
                    inputElement.setAttribute('type', config.datatype || "text");
                    inputElement.setAttribute('value', jsonValue[key]);
                }

                inputElement.setAttribute('data-json-key', key);

                if (!config.edit) {
                    inputElement.setAttribute('readonly', true);
                }

                subDiv.appendChild(subLabel);
                subDiv.appendChild(inputElement);
                container.appendChild(subDiv);

                if (typeof jsonValue[key] === 'object' && jsonValue[key] !== null) {
                    processJSONField(JSON.stringify(jsonValue[key]), subDiv, dependencies, key);
                }
            });
        }
    } catch (e) {
        console.log("NOT JSON for key:", parentKey);
        return false;
    }
    return true;
}

async function modal_response(data, id_no) {
    var result = data[0];
    var fields = data[1];
    var dependencies = data[2];
    console.log("Modal response data:", result, fields, dependencies);
    field_val = [];
    let modal = document.querySelector(".modal");
    var main = document.getElementById('modal_content');
    var modaldiv = document.createElement('div');
    modaldiv.setAttribute('class', 'modal-body');

    try { main.innerHTML = ""; } 
    catch (error) {}

    for (var z = 0; z < fields.length; z++) {
        var keys2 = Object.keys(fields[z]);
        field_val.push(keys2[0]);
    }

    for (var x = 0; x < field_val.length; x++) {
        var d = document.createElement('div');
        d.setAttribute('class', 'mb-3 mt-3');
        if(fields[x][field_val[x]]['show']==true ){
            var label = document.createElement('label');
            label.setAttribute('class', 'form-label');
            label.style.color = 'black';
            label.innerHTML = field_val[x] + ':';
            d.appendChild(label);

            var value = result[0][field_val[x]];
            console.log("Processing field:", field_val[x], "Value:", value);

            // Process only if it's a valid JSON field, excluding IDs
            if (!processJSONField(value, d, dependencies, field_val[x])) { 
                var u_input = document.createElement('input');
                u_input.setAttribute("id", field_val[x]);
                u_input.setAttribute("type", fields[x][field_val[x]]['datatype']);
                u_input.setAttribute('class', 'form-control');
                console.log(1);
                if (fields[x][field_val[x]]['edit'] == false) {
                    u_input.setAttribute('readOnly', 'true'); console.log(2);
                }
                
                if (fields[x][field_val[x]]['create'] == true) {
                    // check for default value or data has to be source from database and put here.
                    u_input.setAttribute('value', ""); console.log(3);
                } else {
                    try {
                        console.log(4);
                        if (result[0][field_val[x]] == null) {
                            console.log(11,result[0].default.document_query);
                            if (result[0].default.document_query) {
                                try {
                                    
                                    result[0].default.document_query.where_data.entity_id=result.entity_id
                                    retrive_data(result[0].default.document_query)
                                    console.log(5);
                                    const query = fieldConfig.default.document_query;
                                    const params = [id_no];  // Assuming entityId is available
                                    console.log(fetchDataFromBackend)
                                    const data = await fetchDataFromBackend(query, params);
                        
                                    if (data && data.length > 0) {
                                        inputElement.value = data[0].entity_name; // Set first result
                                    }
                                } catch (error) {
                                    console.error(`Error fetching data for ${fieldKey}:`, error);
                                }
                            }
                            u_input.setAttribute('value', ""); console.log(3);
                        } else {
                            console.log(5);
                            if (id_no != "0") {
                                console.log(4,fields[x].default?.document_query);
                                if (fields[x].default?.document_query) {
                                    try {
                                        console.log(5);
                                        const query = fieldConfig.default.document_query;
                                        const params = [id_no];  // Assuming entityId is available
                                        console.log(fetchDataFromBackend)
                                        const data = await fetchDataFromBackend(query, params);
                            
                                        if (data && data.length > 0) {
                                            inputElement.value = data[0].entity_name; // Set first result
                                        }
                                    } catch (error) {
                                        console.error(`Error fetching data for ${fieldKey}:`, error);
                                    }
                                }
                            
                                u_input.setAttribute('value', result[0][field_val[x]]);
                                document.getElementById('modal_create_btn').style.display = 'none';
                                document.getElementById('modal_save_btn').style.display = 'block';
                            } else {
                                u_input.setAttribute('value', "");
                                document.getElementById('modal_create_btn').style.display = 'block';
                                document.getElementById('modal_save_btn').style.display = 'none';
                            }
                        }
                    } catch {
                        u_input.setAttribute('value', "");
                    }
                }
                d.appendChild(u_input);
            }
        }
        modaldiv.appendChild(d);
    }

    main.appendChild(modaldiv);
    modal.style.display = "block";

    let closeBtn = document.querySelector(".close-btn");
    closeBtn.onclick = function () {
        modal.style.display = "none";
    };

    window.onclick = function (e) {
        if (e.target == modal) {
            modal.style.display = "none";
        }
    };
}


async function processField(fieldKey, fieldConfig, entityId) {
    // If document_query exists, fetch data dynamically
    if (fieldConfig.default?.document_query) {
        try {
            const query = fieldConfig.default.document_query;
            const params = [entityId];  // Assuming entityId is available

            const data = await fetchDataFromBackend(query, params);

            if (data && data.length > 0) {
                inputElement.value = data[0].entity_name; // Set first result
            }
        } catch (error) {
            console.error(`Error fetching data for ${fieldKey}:`, error);
        }
    }

    return inputElement;
}



async function fetchDataFromBackend(query, params = []) {
    try {
        const response = await fetch('http://127.0.0.1:5000/fetch-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query, params })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        return data.result; // Expecting a JSON response like { "result": [...] }
    } catch (error) {
        console.error("Error fetching data:", error);
        return null;
    }
}


field.vlaue= get_data("entity_name","entity_id","entity/list")
get_data("entity", ['entity_name','entry_status'],"event_scheduler2025",{'entity_id': 1,'entity_type': 'Type C'})

function retrive_data(qry_data){
    //{"api":"/entity/list_details","select_fields":["entity_name"],"where_data":{"entity_id": 0}}
    send_data
    var end_point = "http://127.0.0.1:5000/"+qry_data.api;
    const getData = async(url=end_point,api_method="POST",api_body=send_data) => {     
    console.log(api_body);
    var response;
    response = await fetch(url,{
        method: api_method,
        body: api_body, // string or object
        headers : { 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    });
    
    if (response.ok) {
        const raps = await response.json(); myresult = raps;
    }
    return (myresult);
    }
    getData().then(data => {
    console.log("this is my data",data)
    modal_response(data,edit_id)
    //init_tab_prepartion(data[0],data[1],data[2])   
    });
}




// **Function to Save Edited JSON Fields**
function saveEditedData() {
    document.querySelectorAll("[data-field-name]").forEach(jsonContainer => {
        var fieldName = jsonContainer.getAttribute("data-field-name");
        var jsonData = JSON.parse(jsonContainer.getAttribute("data-json"));

        jsonContainer.querySelectorAll("input, select").forEach(input => {
            var key = input.getAttribute("data-json-key");
            var index = input.getAttribute("data-index");
            jsonData[index][key] = input.value;
        });

        console.log("Updated JSON for", fieldName, ":", JSON.stringify(jsonData));
    });
}


[{"end_time": "17:00:00", "start_time": "09:00:00", "day_of_week": "monday", "more details":{"time": "17:00:00", "day": "tuesday"}}]
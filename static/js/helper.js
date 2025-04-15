

async function getEntityTypes(data) {
    var end_point = domain +"options";
    var body={
        "requestor_id":"",
        "request_token":"",
        "event":"getentitytypes",
        "qry":{
            "select_fields":["entity_type"],
            "where_data":{}
        }
    }
    console.log("Fetching:", end_point, body);
    var options =  API_helper_call(end_point, body);
    return options
}
   
async function getResourceCateory(entity_id) {
    console.log("helper called")
    var end_point = domain +"options";
    var body={
        "requestor_id":"",
        "request_token":"",
        "type":"Resource Category",
        "tab":"Entity Config",
        "qry":{
            "select_fields":["resource_type_name"],
            "where_data":{}
        }
    }
    console.log("Fetching:", end_point, body);
    var options =  API_helper_call(end_point, body);
    return options
}

async function getRole(){
    console.log("helper called")
    var end_point = domain +"options";
    var body={
        "requestor_id":"",
        "request_token":"",
        "type":"Role Registry",
        "tab":"Entity Config",
        "qry":{
            "select_fields":["role_name"],
            "where_data":{}
        }
    }
    console.log("Fetching:", end_point, body);
    var options =  API_helper_call(end_point, body);
    return options

}

async function getEventType(){
    console.log("helper called")
    var end_point = domain +"options";
    var body={
        "requestor_id":"",
        "request_token":"",
        "type":"Event Category",
        "tab":"Entity Config",
        "qry":{
            "select_fields":["event_type_name"],
            "where_data":{}
        }
    }
    console.log("Fetching:", end_point, body);
    var options =  API_helper_call(end_point, body);
    return options 
}

async function getStatus(){
    console.log("helper called")
    var end_point = domain +"options";
    var body={
        "requestor_id":"",
        "request_token":"",
        "type":"Doc_status_type",
        "tab":"System Config",
        "qry":{
            "select_fields":["doc_status_type"],
            "where_data":{}
        }
    }
    console.log("Fetching:", end_point, body);
    var options =  API_helper_call(end_point, body);
    return options 
}

async function API_helper_call(end_point, body){
    try {
        let response = await fetch(end_point, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            let data = await response.json();
            console.log("Received Data:", data);
            console.log(data);
            let myArray = data.map(element => Object.values(element)).flat();    
            console.log(myArray)    
            return myArray;
        } else {
            console.error("Failed to fetch entity types.");
            return [];
        }
    } catch (error) {
        console.error("Error fetching entity types:", error);
        return [];
    }
}

async function fetchHelperData(helper) {
    if (typeof window[helper] === "function") {
        return await window[helper](helper);
    } else {
        console.error(`Helper function '${helper}' not found!`);
        return [];
    }
}



/*
async function fetchEntityName1(entity_id){ 
    var end_point = domain +"entity/list_details";
    var body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["entity_name"],
            "where_data":{"entity_id":entity_id}
        }
    }
    console.log("Fetching:", end_point, body);

    try {
        let response = await fetch(end_point, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            let data = await response.json();
            console.log("Received Data:", data);
            return data[0].entity_name;
        } else {
            console.error("Failed to fetch entity name.");
            return "";
        }
    } catch (error) {
        console.error("Error fetching entity name:", error);
        return "";
    }
}

async function getEventList1(data) {
    var end_point = domain +"event/list_details";
    var body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    console.log("Fetching:", end_point, body);

    try {
        let response = await fetch(end_point, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            let data = await response.json();
            console.log("Received Data:", data);
            const myArray =[];
            console.log(data);
            data.forEach(element => {
                var entityname=fetchEntityName(element.host_entity_id)
                myArray.push(element.name+" ["+entityname+"]")
            });        
            console.log(myArray)    
            return myArray;
        } else {
            console.error("Failed to fetch entity types.");
            return [];
        }
    } catch (error) {
        console.error("Error fetching entity types:", error);
        return [];
    }
}

async function fetchEntityName(entity_id) { 
    var end_point = domain + "entity/list_details";
    var body = {
        "requestor_id": "",
        "request_token": "",
        "qry": {
            "select_fields": ["entity_name"],
            "where_data": { "entity_id": entity_id }
        }
    };
    console.log("Fetching:", end_point, body);

    try {
        let response = await fetch(end_point, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            let data = await response.json();
            console.log("Received Data:", data);
            return data[0]?.entity_name || "Unknown";
        } else {
            console.error("Failed to fetch entity name.");
            return "Unknown";
        }
    } catch (error) {
        console.error("Error fetching entity name:", error);
        return "Unknown";
    }
}

async function getEventList() {
    var end_point = domain + "event/list_details";
    var body = {
        "requestor_id": "",
        "request_token": "",
        "qry": {
            "select_fields": ["*"],
            "where_data": {}
        }
    };
    console.log("Fetching:", end_point, body);

    try {
        let response = await fetch(end_point, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            let data = await response.json();
            console.log("Received Data:", data);

            // Use map() and await fetchEntityName() inside Promise.all()
            const eventList = await Promise.all(data.map(async (element) => {
                let entityName = await fetchEntityName(element.host_entity_id);
                return `${element.name} | ${entityName} | ${element.host_entity_id}`;
            }));

            console.log(eventList);
            return eventList;
        } else {
            console.error("Failed to fetch event list.");
            return [];
        }
    } catch (error) {
        console.error("Error fetching event list:", error);
        return [];
    }
}

async function fetchResources(entity_id) {
    let end_point = domain + "resource/list_details";
    let body = {
        "requestor_id": "",
        "request_token": "",
        "qry": {
            "select_fields": ["resource_id", "resource_name"],
            "where_data": { "entity_id": entity_id }
        }
    };

    try {
        let response = await fetch(end_point, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            let data = await response.json();

            let resourceSelect = document.getElementById("resource");
            resourceSelect.innerHTML = '<option value="">-- Select Resource --</option>';

            for (let resource of data) {
                let option = document.createElement("option");
                option.value = resource.resource_id;
                option.textContent = resource.resource_name;
                resourceSelect.appendChild(option);
            }
        } else {
            console.error("Failed to fetch resources.");
        }
    } catch (error) {
        console.error("Error fetching resources:", error);
    }
}

function handleEventSelection() {
    console.log("Event selected");

    let eventSelect = document.getElementById("events");
    if (!eventSelect) {
        console.error("Dropdown with id 'events' not found!");
        return;
    }

    let selectedOption = eventSelect.options[eventSelect.selectedIndex];

    console.log(selectedOption.value, selectedOption.dataset.entityId);

    if (selectedOption.value) {
        let parts = selectedOption.value.split(" | ");
        let entity_id = parts[parts.length - 1].trim(); console.log(entity_id); 
        fetchResources(entity_id);
    } else {
        document.getElementById("resource").innerHTML = '<option value="">-- Select Resource --</option>';
    }
}


 */



/*
TO DO 
    fields required to be inserted in change_log column for every table and api endpoint in backend
    change_log ={ actor, action, datetime, ipaddress, fields}
    {"logs":[{"actor":"","action":"CREATE","datetime":"2025-02-06T12:00:00Z","ipaddress":"192.168.1.1","fields":{"field1":"","field2":""}}]}


    include remarks column for all tables :  LongTEXT 
    [capture text with limited characters (100 letters) and append to remarks.] 

    On approval clear all remarks. 


*/

/*function get_data_list(selected_item){
    console.log(selected_item);
    console.log(selectedItemFromDropdown);
    //selectedItemFromDropdown=null
    page_load_conf.event="data_list";
    console.log(">>>>>",  page_load_conf);
    data_list_body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    
    //if(tab_status[page_load_conf.tab]==0){
        console.log(page_load_conf.tab, tab_status[page_load_conf.tab])
        console.log(MainConfig[page_load_conf.tab+"_config"].getDataApi)
        if (MainConfig[page_load_conf.tab+"_config"].getDataApi===undefined){
            if(selected_item) {
                data_list_body.type=selected_item;
                console.log(MainConfig[page_load_conf.tab+"_config"][selected_item].getDataApi)
                API_call(domain,MainConfig[page_load_conf.tab+"_config"][selected_item].getDataApi,data_list_body,"POST")
            
            }
            else{present_Data({})}
        }

        else{API_call(domain,MainConfig[page_load_conf.tab+"_config"].getDataApi,data_list_body,"POST")}
   // }

}*/

function present_Data(data,item) {
    console.log(data, item);
    console.log(selectedItemFromDropdown)
    var display_data;
    var field_data = {}; // Ensure it's initialized properly
    var config_path;
    if (item==null){display_data=data;  config_path=MainConfig[page_load_conf.tab+"_config"]; selectedItemFromDropdown=null;  console.log(1)}
    else{display_data=data[0];  config_path=MainConfig[page_load_conf.tab+"_config"][item]; selectedItemFromDropdown=item;  console.log(2)}
    console.log(MainConfig[page_load_conf.tab+"_config"])
    console.log(config_path)
    if (config_path.job.list.roles.includes(role)) {
        field_data = config_path.job.list;
        console.log(field_data);
    }
    else if (role === "Approver") {
        field_data = config_path.approve;
    }
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


/*
function get_entity_list(conf){
    console.log(page_load_conf.tab);
    //page_load_conf.tab="Entity";
    page_load_conf.event="entity_list";
    console.log(">>>>>",  page_load_conf);
    entity_list_body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"entity/list_details",entity_list_body,"POST") 
    }
}

function presentEntityData1(data) {
    console.log(data);
    var field_data={}
    if (role=="Admin"){field_data=entity_config.list.create}
    if (role=="Approver"){field_data=entity_config.list.approve}
    var entity_list={
        tab_name: "Entity",
        controls: entity_config.controls,
        data: data ,
        fields:field_data
    };
   
  
    console.log(entity_list)
    createTable(entity_list);    
}*/




// Function to update entity via API
/*function updateEntry(Id, updatedData) {
    let apiEndpoint =""
    var update_body={
        "requestor_id":"",
        "request_token":"",
        "qry":updatedData
    }
    //if (page_load_conf.tab == "Entity") {   apiEndpoint = domain + "entity/modifications"; update_body.entity_id=Id;}
    //if (page_load_conf.tab == "Resource") { apiEndpoint = domain + "resource/modifications";update_body.resource_id=Id;}
    //if (page_load_conf.tab == "Event") { apiEndpoint = domain + "event/modifications";update_body.event_id=Id;}
    //if (page_load_conf.tab == "Alert") { apiEndpoint = domain + "alert/modifications";update_body.alert_id=Id;}
    
    console.log(selectedItemFromDropdown)
    try{
       
        if(selectedItemFromDropdown!=null) {
            apiEndpoint=MainConfig[page_load_conf.tab+"_config"][selectedItemFromDropdown].job.create.api;
            update_body=MainConfig[page_load_conf.tab+"_config"][selectedItemFromDropdown].key;
        
        }
        else{
            apiEndpoint=MainConfig[page_load_conf.tab+"_config"].job.create.api;
            update_body=MainConfig[page_load_conf.tab+"_config"].key;
        }
    }catch(err){console.log("Error in data extraction",err)}

    
    console.log(update_body)
    fetch(apiEndpoint, {
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
            //tab_status[page_load_conf.tab]=0; get_entity_list();
            refreshTable();
            } else {
            alert("Update failed: " + (data.message || "Unknown error"));
        }
    })
    .catch(error => {
        console.error("Update request failed:", error);
        alert("An error occurred while updating the entity.");
    });
}*/

// ✅ Function to create a new entity (you should replace this with actual API logic)
function createEntry1(newEntry) {
    let apiEndpoint =""
    var creation_body={
        "requestor_id":"",
        "request_token":"",
        "type":"",
        "qry":newEntry
    }
    /*if (page_load_conf.tab == "Entity") {   apiEndpoint = domain + "entity/new"; update_body.entity_id=Id;}
    if (page_load_conf.tab == "Resource") { apiEndpoint = domain + "resource/new";update_body.resource_id=Id;}
    if (page_load_conf.tab == "Event") { apiEndpoint = domain + "event/new";update_body.event_id=Id;}
    if (page_load_conf.tab == "Alert") { apiEndpoint = domain + "alert/new";update_body.alert_id=Id;}*/


    console.log(selectedItemFromDropdown)
    try{
       
        if(selectedItemFromDropdown!=null) {
            apiEndpoint=MainConfig[page_load_conf.tab+"_config"][selectedItemFromDropdown].job.create.api; 
            creation_body.type=selectedItemFromDropdown;
        }
        else{apiEndpoint=MainConfig[page_load_conf.tab+"_config"].job.create.api}
    }catch(err){console.log("Error in data extraction",err)}


    console.log(creation_body)
    fetch(apiEndpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(creation_body)
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert("Entry Created Successfully!");
            tab_status[page_load_conf.tab]=0; get_data_list();
            } else {
            alert("creation failed: " + (data.message || "Unknown error"));
        }
    })
    .catch(error => {
        console.error("creation request failed:", error);
        alert("An error occurred while creating the entity.");
    });
}
 



//{"days": ["Monday", "Tuesday"], "eventName": "Doctor availibility", "eventEndDate": "2025-03-03", "eventEndTime": "12:00", "eventStartDate": "2025-02-03", "eventStartTime": "10:00", "eventDescription": "Doctor is available for consultation"}

//{"days": [1,2],"title": "Doctor availibility", "start": "2025-02-25T04:30:00.000Z", "end": "2025-03-25T06:30:00.000Z", "description": "aaaaa", "backgroundColor": "#007bff","textColor":"#ffffff"}

// {"end": "2025-03-25T06:30:00.000Z", "days": [1, 2], "start": "2025-02-25T04:30:00.000Z", "title": "Doctor availibility", "textColor": "#ffffff", "description": "aaaaa", "backgroundColor": "#007bff"}
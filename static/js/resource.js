function get_resource_list(conf){
    console.log(page_load_conf.tab)
    //page_load_conf.tab="Resource";
    page_load_conf.event="resource_list";
    console.log(">>>>>",  page_load_conf);
    resource_list_body={
        "requestor_id":"",
        "request_token":"",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"resource/list_details",resource_list_body,"POST") 
    } 
}

function presentResourceData(data) {
    console.log(data);
    
    var field_data = {}; // Ensure it's initialized properly

    if (role === "Admin" ) {
        field_data = resource_config.list; console.log(field_data)
    } 
    else if (role === "Approver") {
        field_data = resource_config.approver;
    }

    var resource_list = {
        tab_name: "Resource",
        controls: resource_config.controls,
        data: data,
        fields: field_data
    };

    console.log(resource_list);
    createTable(resource_list);
}

function takeWorkDays() {
    var work_days = document.getElementById("work_days").value;
    console.log(work_days);
    return work_days;
}

// Function to update entity via API
function updateResource(resourceId, updatedData) {
    
    let apiEndpoint = domain + "resource/modifications"; // Adjust API endpoint accordingly
    var update_body={
        "requestor_id":"",
        "request_token":"",
        "entity_id":resourceId,
        "qry":updatedData
    }
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
            alert("Entity updated successfully!");
            tab_status[page_load_conf.tab]=0; get_entity_list();
            } else {
            alert("Update failed: " + (data.message || "Unknown error"));
        }
    })
    .catch(error => {
        console.error("Update request failed:", error);
        alert("An error occurred while updating the entity.");
    });
}

/*
f=open('config/new/get_entity_list.json');  json_data = json.load(f)
    print("db name: ",json_data)
    data = json.loads(request.data); print(data)
    
    try:
        myresult=get_data(json_data['db_name'],json_data['table_name'], data['qry']['select_fields'],data['qry']['where_data']) 
        print(myresult)
        if(data['qry']['where_data']=={}):
            return jsonify(myresult, json_data['list']['data'],json_data['controls'])
        else:
            return jsonify(myresult, json_data['update']['data'])
     
    except Exception as e:
        print(">>8")
        print("Error:", e)
        return jsonify({"error": str(e)}), 500
*/
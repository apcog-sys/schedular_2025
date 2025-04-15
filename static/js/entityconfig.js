

function get_EntityConfig_list(conf) {
    page_load_conf.tab = "EntityConfig";
    page_load_conf.event = "entity_types";
    let responseData = entityConfig_config.controls;
    const container = document.getElementById("tab_page_content");

    if (!container) {
        console.error(`Element with id 'tab_page_content' not found.`);
        return;
    }

    container.innerHTML = ""; // Clear previous content

    let divControls = document.createElement('div');
    divControls.className = 'mb-3 d-flex gap-2';

    responseData.forEach(control => {
        if (control.roles && control.roles.includes(role)) {
            let input = null;

            if (control.type === "select") {
                input = document.createElement('select');
                input.className = 'form-control';
                input.name = control.tag || control.name;
                input.setAttribute('id', control.tag); // Unique ID for each dropdown

                // Add a default "Select Config" option
                let defaultOption = document.createElement('option');
                defaultOption.value = "";
                defaultOption.textContent = "Items";
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
                    get_list(this.value);
                    selectedItem=this.value;
                    /*if (this.value== "Roles") { get_roles_list();}
                    else if (this.value== "Event Categories") {get_eventCategories_list();}
                    else if (this.value== "Resource Categories") {get_resourceCategories_list();}*/
                });

                let selectContainer = document.createElement('div');
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

function presentConfigData(data) {
    console.log(data);
    var field_data = {}; // Ensure it's initialized properly
    var config_type = ""
    config_type=entityConfig_config[data[1]]
    console.log(config_type)
    console.log(config_type.job.list.roles)
    if (config_type.job.list.roles.includes(role)) {
        field_data = config_type.job.list;
        console.log(field_data);
    }
    
    var entityConfig_list = {
        tab_name: "EntityConfig",
        data: data[0],
        controls: entityConfig_config.controls,
        fields: field_data
    };

    console.log(entityConfig_list);
    createTable(entityConfig_list);
}

function get_list(list_name){
    console.log(document.getElementById('items').value)
    console.log( list_name)
    page_load_conf.tab="EntityConfig";
    page_load_conf.event="EntityConfig";
    console.log(">>>>>",  page_load_conf);
    message_list_body={
        "requestor_id":"",
        "request_token":"",
        "type":list_name,
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    API_call(domain,"config/list_details",message_list_body,"POST") 
}


function get_roles_list() {
    // console.log(conf);
    page_load_conf.tab="EntityConfig";
    page_load_conf.event="EntityConfig";
    console.log(">>>>>",  page_load_conf);
    role_list_body={
        "requestor_id":"",
        "request_token":"",
        "type":"roles",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    API_call(domain,"entityConfig/list_details",role_list_body,"POST") 
    
}

function get_eventCategories_list() {
    page_load_conf.tab="EntityConfig";
    page_load_conf.event="EntityConfig";
    console.log(">>>>>",  page_load_conf);
    eventCategories_list_body={
        "requestor_id":"",
        "request_token":"",
        "type":"event_categories",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    API_call(domain,"entityConfig/list_details",eventCategories_list_body,"POST") 
}

function get_resourceCategories_list() {
    page_load_conf.tab="EntityConfig";
    page_load_conf.event="EntityConfig";
    console.log(">>>>>",  page_load_conf);
    eventCategories_list_body={
        "requestor_id":"",
        "request_token":"",
        "type":"resource_categories",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    API_call(domain,"entityConfig/list_details",eventCategories_list_body,"POST") 
}

function get_message_list(conf){
    console.log("inside get message list ")
    page_load_conf.tab="EntityConfig";
    page_load_conf.event="EntityConfig";
    console.log(">>>>>",  page_load_conf);
    message_list_body={
        "requestor_id":"",
        "request_token":"",
        "type":"message",
        "qry":{
            "select_fields":["*"],
            "where_data":{}
        }
    }
    if(tab_status[page_load_conf.tab]==0){
        API_call(domain,"entityConfig/list_details",message_list_body,"POST") 
    } 
    //API_call(domain,"message/list_details",message_list_body,"POST") 
}




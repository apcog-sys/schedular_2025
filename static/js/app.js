let token = "";
let role = "";

// LOGIN FUNCTION
function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    console.log(username,  password)
    fetch("http://127.0.0.1:5000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        console.log(data)
        if (data.token) {
            token = data.token;
            role = data.role;
            document.getElementById("userRole").innerText = "Role: " + role;

            if (role === "admin") {
                document.getElementById("createBtn").style.display = "block";
            }
            document.getElementById("listBtn").style.display = "block";
        } else {
            alert("Login failed!");
        }
    });
}

// CREATE ENTITY (Admin Only)
function createEntity22() {
    if (!token) {
        alert("Token is missing or invalid.");
        return;
    }

    console.log("Token: ", token);

    fetch("http://127.0.0.1:5000/new_test", {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            "Authorization": "Bearer " + token
        },
        body: JSON.stringify({
            "entity_name": "New Task",
            "entity_type": "Meeting",
            "Subject": "Some subject here"
          }
          )
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert(data.message);
        } else {
            alert(data.error || "An unknown error occurred.");
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Error creating entity.");
    });
}


async function createEntity() {
   
    console.log("fetching", token)
    try {
        let response = await fetch("http://127.0.0.1:5000/new_test", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({
                "entity_name": "New Task",
                "entity_type": "Meeting",
                "subject": "Some subject here"
              }
            )
        });

        if (response.ok) {
            let data = await response.json();
            console.log("Received Data:", data);
        } else {
            console.error("Failed to fetch entity types.");
            return [];
        }
    } catch (error) {
        console.error("Error fetching entity types:", error);
        return [];
    }
}

// LIST ENTITIES (Admin & Approver)
function listEntities() {
    fetch("http://127.0.0.1:5000/entity/list", {
        method: "GET",
        headers: { "Authorization": "Bearer " + token }
    })
    .then(response => response.json())
    .then(data => {
        let list = document.getElementById("entityList");
        list.innerHTML = "";
        data.forEach(entity => {
            list.innerHTML += `<li>${entity.entity_name} (${entity.entry_status})</li>`;
        });
    });
}

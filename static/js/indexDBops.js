<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IndexedDB Example</title>
</head>
<body>

    <h2>IndexedDB Example</h2>
    
    <input type="text" id="nameInput" placeholder="Enter Name">
    <button onclick="addData()">Add Data</button>
    <button onclick="getData()">Get Data</button>
    <button onclick="deleteData()">Delete Data</button>

    <h3>Stored Data:</h3>
    <ul id="dataList"></ul>

    <script>
        // Open or create the IndexedDB database
        let db;
        const dbName = "MyDatabase";

        let request = indexedDB.open(dbName, 1);

        request.onupgradeneeded = function(event) {
            let db = event.target.result;
            if (!db.objectStoreNames.contains("users")) {
                db.createObjectStore("users", { keyPath: "id", autoIncrement: true });
            }
        };

        request.onsuccess = function(event) {
            db = event.target.result;
            console.log("Database opened successfully!");
        };

        request.onerror = function(event) {
            console.log("Error opening database:", event.target.error);
        };

        // Function to add data
        function addData() {
            let name = document.getElementById("nameInput").value;
            if (!name) {
                alert("Enter a name first!");
                return;
            }

            let transaction = db.transaction(["users"], "readwrite");
            let store = transaction.objectStore("users");
            let request = store.add({ name: name });

            request.onsuccess = function() {
                console.log("Data added successfully!");
                document.getElementById("nameInput").value = "";
            };

            request.onerror = function(event) {
                console.log("Error adding data:", event.target.error);
            };
        }

        // Function to get all data
        function getData() {
            let transaction = db.transaction(["users"], "readonly");
            let store = transaction.objectStore("users");
            let request = store.openCursor();

            let dataList = document.getElementById("dataList");
            dataList.innerHTML = ""; // Clear previous data

            request.onsuccess = function(event) {
                let cursor = event.target.result;
                if (cursor) {
                    let listItem = document.createElement("li");
                    listItem.textContent = `ID: ${cursor.key}, Name: ${cursor.value.name}`;
                    dataList.appendChild(listItem);
                    cursor.continue();
                } else {
                    console.log("All data displayed.");
                }
            };

            request.onerror = function(event) {
                console.log("Error fetching data:", event.target.error);
            };
        }

        // Function to delete all data
        function deleteData() {
            let transaction = db.transaction(["users"], "readwrite");
            let store = transaction.objectStore("users");
            let request = store.clear();

            request.onsuccess = function() {
                console.log("All data deleted successfully!");
                document.getElementById("dataList").innerHTML = "";
            };

            request.onerror = function(event) {
                console.log("Error deleting data:", event.target.error);
            };
        }
    </script>

</body>
</html>

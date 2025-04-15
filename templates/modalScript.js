document.addEventListener("DOMContentLoaded", function () {
    function createModalContent() {
        const modalBody = document.getElementById("createForm");

        // Clear any existing content
        modalBody.innerHTML = "";

        // Create form
        const form = document.createElement("form");
        form.id = "eventForm";

        // Create input fields
        form.appendChild(createInputField("Event Name", "text", "eventName"));
        form.appendChild(createTextareaField("Description", "eventDescription"));
        form.appendChild(createInputField("Start Date", "date", "eventStartDate"));
        form.appendChild(createInputField("End Date", "date", "eventEndDate"));

        // Add Schedule Control
        const scheduleLabel = document.createElement("label");
        scheduleLabel.innerText = "Work Days & Timings:";
        form.appendChild(scheduleLabel);

        const scheduleControl = document.createElement("schedule-control");
        scheduleControl.id = "scheduleField";
        form.appendChild(scheduleControl);

        // Create Submit Button
        const submitButton = document.createElement("button");
        submitButton.type = "submit";
        submitButton.className = "btn btn-primary mt-3";
        submitButton.innerText = "Save Schedule";

        form.appendChild(submitButton);
        modalBody.appendChild(form);

        // Form submit event
        form.addEventListener("submit", function (event) {
            event.preventDefault();

            // Extract data from schedule-control
            const scheduleData = document.getElementById("scheduleField").value;

            console.log("Event Name:", document.getElementById("eventName").value);
            console.log("Start Date:", document.getElementById("eventStartDate").value);
            console.log("End Date:", document.getElementById("eventEndDate").value);
            console.log("Schedule Data:", scheduleData);

            alert("Schedule saved successfully!");
        });
    }

    // Helper function to create input fields
    function createInputField(labelText, type, id) {
        const div = document.createElement("div");
        div.className = "mb-3";

        const label = document.createElement("label");
        label.className = "form-label";
        label.innerText = labelText;
        label.setAttribute("for", id);

        const input = document.createElement("input");
        input.type = type;
        input.className = "form-control";
        input.id = id;
        input.required = true;

        div.appendChild(label);
        div.appendChild(input);
        return div;
    }

    // Helper function to create textarea fields
    function createTextareaField(labelText, id) {
        const div = document.createElement("div");
        div.className = "mb-3";

        const label = document.createElement("label");
        label.className = "form-label";
        label.innerText = labelText;
        label.setAttribute("for", id);

        const textarea = document.createElement("textarea");
        textarea.className = "form-control";
        textarea.id = id;

        div.appendChild(label);
        div.appendChild(textarea);
        return div;
    }

    // Run when the modal is shown
    document.getElementById("addEventModal").addEventListener("show.bs.modal", function () {
        createModalContent();
    });
});

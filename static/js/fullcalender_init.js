document.addEventListener('DOMContentLoaded', function () {
    var calendarEl = document.getElementById('calendar');
    var calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek,timeGridDay'
        },
        events: [],
        eventClick: function(info) {
            alert('Event: ' + info.event.title + '\nDescription: ' + (info.event.extendedProps.description || 'No details'));
        }
    });
    
    calendar.render();

    function isOverlapping(start, end) {
        var events = calendar.getEvents();
        for (var i = 0; i < events.length; i++) {
            var event = events[i];
            var eventStart = event.start;
            var eventEnd = event.end || event.start;
            if ((start >= eventStart && start < eventEnd) || (end > eventStart && end <= eventEnd) || (start <= eventStart && end >= eventEnd)) {
                return true;
            }
        }
        return false;
    }

    // Add Event Modal Form Submission
    /*document.getElementById('eventForm').addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent form submission

        var title = document.getElementById('eventName').value;
        var description = document.getElementById('eventDescription').value;
        var startDate = document.getElementById('eventStartDate').value;
        var endDate = document.getElementById('eventEndDate').value || startDate;
        var startTime = document.getElementById('eventStartTime').value;
        var endTime = document.getElementById('eventEndTime').value;

        if (!title || !startDate || !startTime) {
            alert("Event Name, Start Date, and Start Time are required!");
            return;
        }

        var selectedDays = Array.from(document.querySelectorAll('.day-checkbox:checked')).map(cb => parseInt(cb.value));

        var currentDate = new Date(startDate);
        var lastDate = new Date(endDate);

        while (currentDate <= lastDate) {
            var dayOfWeek = currentDate.getDay();
            
            if (selectedDays.length === 0 || selectedDays.includes(dayOfWeek)) {
                var formattedDate = currentDate.toISOString().split("T")[0];
                var eventStart = new Date(formattedDate + 'T' + startTime + ':00');
                var eventEnd = new Date(formattedDate + 'T' + endTime + ':00');
                
                if (isOverlapping(eventStart, eventEnd)) {
                    alert("Event overlaps with an existing event. Please choose a different time.");
                    return;
                }

                calendar.addEvent({
                    title: title,
                    start: eventStart,
                    end: eventEnd,
                    description: description,
                    backgroundColor: '#007bff',
                    textColor: '#ffffff'
                });
            }
            currentDate.setDate(currentDate.getDate() + 1);
        }

        // Close Modal
        var addEventModal = bootstrap.Modal.getInstance(document.getElementById('addEventModal'));
        addEventModal.hide();

        // Reset Form
        document.getElementById('eventForm').reset();
    });*/

    // Open Add Event Modal
    document.getElementById('openEventModalBtn').addEventListener('click', function () {
        var addEventModal = new bootstrap.Modal(document.getElementById('addEventModal'));
        addEventModal.show();
    });
});

function fullCalendar() {
    console.log("fullCalendar() function triggered");

    if (!caldata || !caldata.data || caldata.data.length === 0) {
        console.error("No data found in caldata");
        return;
    }

    let events = [];
    let resourceColors = {};
    let colorPalette = ["#FF5733", "#33FF57", "#3357FF", "#FF33A5", "#FFA533", "#A533FF", "#33FFFF", "#FF3333"];
    let textColorPalette = ["#ffffff", "#000000", "#eeeeee", "#222222"]; // Ensure readable contrast
    let colorIndex = 0;

    console.log(`Processing ${caldata.data.length} entries`);

    caldata.data.forEach(entry => {
        let resourceName = entry.resource_name;
        let workDaysData = entry.work_days;

        console.log(`Processing resource: ${resourceName}`);

        if (workDaysData) {
            try {
                let parsedData = JSON.parse(workDaysData);
                let workDays = parsedData.days || [];
                let startDate = new Date(parsedData.start);
                let endDate = new Date(parsedData.end);

                // Assign a unique color for each resource
                if (!resourceColors[resourceName]) {
                    resourceColors[resourceName] = {
                        background: colorPalette[colorIndex % colorPalette.length],
                        border: colorPalette[colorIndex % colorPalette.length],
                        text: textColorPalette[colorIndex % textColorPalette.length]
                    };
                    colorIndex++;
                }

                // Generate events for each specified day
                let currentDate = new Date(startDate);
                while (currentDate <= endDate) {
                    if (workDays.includes(currentDate.getDay())) {
                        events.push({
                            title: parsedData.title || resourceName,
                            start: new Date(currentDate).toISOString().split("T")[0] + "T" + startDate.toISOString().split("T")[1], // Maintain same time
                            end: new Date(currentDate).toISOString().split("T")[0] + "T" + endDate.toISOString().split("T")[1],
                            description: parsedData.description || "No Description",
                            backgroundColor: resourceColors[resourceName].background,
                            borderColor: resourceColors[resourceName].border,
                            textColor: resourceColors[resourceName].text
                        });
                        console.log("Event added:", events[events.length - 1]);
                    }
                    currentDate.setDate(currentDate.getDate() + 1);
                }
            } catch (error) {
                console.error("Error parsing workDays JSON for", resourceName, error);
            }
        }
    });

    console.log("Final Events Array:", events);

    // Ensure modal exists for displaying event details
    let eventDetailsModal = document.getElementById("eventDetailsModal");
    /*if (!eventDetailsModal) {
        console.log("Creating event details modal");
        eventDetailsModal = document.createElement("div");
        eventDetailsModal.id = "eventDetailsModal";
        eventDetailsModal.className = "modal";
        eventDetailsModal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Event Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <p><strong>Title:</strong> <span id="eventTitle"></span></p>
                        <p><strong>Description:</strong> <span id="eventDescription"></span></p>
                        <p><strong>Start:</strong> <span id="eventStart"></span></p>
                        <p><strong>End:</strong> <span id="eventEnd"></span></p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(eventDetailsModal);
    }*/

    // Show Bootstrap modal
    let calendarModal = document.getElementById("myCalendar");

    let modalInstance = new bootstrap.Modal(calendarModal);
    modalInstance.show();

    setTimeout(() => {
        console.log("Initializing FullCalendar");

        let calendarEl = document.getElementById('calendar');
        if (!calendarEl) {
            console.error("Calendar element not found!");
            return;
        }

        let calendar = new FullCalendar.Calendar(calendarEl, {
            initialView: 'dayGridMonth',
            headerToolbar: {
                left: 'prev,next today',
                center: 'title',
                right: 'dayGridMonth,timeGridWeek,timeGridDay'
            },
            events: events,
            eventDidMount: function(info) {
                info.el.style.backgroundColor = info.event.extendedProps.backgroundColor;
                info.el.style.borderColor = info.event.extendedProps.borderColor;
                info.el.style.color = info.event.extendedProps.textColor;
            },
            eventClick: function(info) {
                // Populate modal with event details
                document.getElementById("eventTitle").innerText = info.event.title;
                document.getElementById("eventDescription").innerText = info.event.extendedProps.description;
                document.getElementById("eventStart").innerText = new Date(info.event.start).toLocaleString();
                document.getElementById("eventEnd").innerText = new Date(info.event.end).toLocaleString();

                // Show modal
                let eventModalInstance = new bootstrap.Modal(document.getElementById("eventDetailsModal"));
                eventModalInstance.show();
            }
        });

        calendar.render();
        console.log("FullCalendar rendered successfully");
    }, 500);
}



// Attach event listener to button
//document.getElementById("showCalendarBtn").addEventListener("click", fullCalendar);








/* WORRKING
document.addEventListener('DOMContentLoaded', function () {
    var calendarEl = document.getElementById('calendar');
    var calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek,timeGridDay'
        },
        events: [],
        eventClick: function(info) {
            alert('Event: ' + info.event.title + '\nDescription: ' + (info.event.extendedProps.description || 'No details'));
        }
    });
    

    calendar.render();

    // Add Event Modal Form Submission
    document.getElementById('eventForm').addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent form submission

        var title = document.getElementById('eventName').value;
        var description = document.getElementById('eventDescription').value;
        var startDate = document.getElementById('eventStartDate').value;
        var endDate = document.getElementById('eventEndDate').value || startDate;
        var startTime = document.getElementById('eventStartTime').value;
        var endTime = document.getElementById('eventEndTime').value;

        if (!title || !startDate || !startTime) {
            alert("Event Name, Start Date, and Start Time are required!");
            return;
        }

        var selectedDays = Array.from(document.querySelectorAll('.day-checkbox:checked')).map(cb => parseInt(cb.value));

        var currentDate = new Date(startDate);
        var lastDate = new Date(endDate);

        while (currentDate <= lastDate) {
            var dayOfWeek = currentDate.getDay();
            
            if (selectedDays.length === 0 || selectedDays.includes(dayOfWeek)) {
                var formattedDate = currentDate.toISOString().split("T")[0];

                calendar.addEvent({
                    title: title,
                    start: formattedDate + 'T' + startTime + ':00',
                    end: formattedDate + 'T' + endTime + ':00',
                    description: description,
                    backgroundColor: '#007bff',
                    textColor: '#ffffff'
                });
            }
            currentDate.setDate(currentDate.getDate() + 1);
        }

        // Close Modal
        var addEventModal = bootstrap.Modal.getInstance(document.getElementById('addEventModal'));
        addEventModal.hide();

        // Reset Form
        document.getElementById('eventForm').reset();
    });

    // Open Add Event Modal
    document.getElementById('openEventModalBtn').addEventListener('click', function () {
        var addEventModal = new bootstrap.Modal(document.getElementById('addEventModal'));
        addEventModal.show();
    });
});
*/








/* WORKING
document.addEventListener('DOMContentLoaded', function () {
    var calendarEl = document.getElementById('calendar');
    var calendar;

    function getMondays(year, month) {
        let mondays = [];
        let date = new Date(year, month, 1); // First day of the month

        while (date.getMonth() === month) {
            if (date.getDay() === 1) { // 1 = Monday
                let start = new Date(date);
                start.setHours(14, 0, 0); // 2:00 PM
                let end = new Date(date);
                end.setHours(19, 0, 0); // 7:00 PM
                
                mondays.push({
                    id: `doctor-availability-${start.toISOString()}`,
                    title: 'Doctor Available',
                    description: 'Dr. Smith is available for consultations',
                    start: start.toISOString(),
                    end: end.toISOString(),
                    backgroundColor: '#28a745', // Green color for availability
                    textColor: '#ffffff' // White text
                });
            }
            date.setDate(date.getDate() + 1); // Move to the next day
        }
        return mondays;
    }

    document.getElementById('myCalendar').addEventListener('shown.bs.modal', function () {
        if (!calendar) {
            calendar = new FullCalendar.Calendar(calendarEl, {
                initialView: 'dayGridMonth',
                headerToolbar: {
                    left: 'prev,next today',
                    center: 'title',
                    right: 'dayGridMonth,timeGridWeek,timeGridDay'
                },
                events: [
                    {
                        id: '1',
                        title: 'Doctor Appointment',
                        description: 'Check-up with Dr. Smith at City Hospital',
                        start: '2025-02-15T10:00:00',
                        end: '2025-02-15T11:00:00'
                    },
                    {
                        id: '2',
                        title: 'Team Meeting',
                        description: 'Discuss project updates in Conference Room 3',
                        start: '2025-02-12T14:00:00'
                    },
                    ...getMondays(2025, 1) // February 2025 (month is zero-based)
                ],
                eventClick: function(info) {
                    document.getElementById('eventTitle').innerText = info.event.title;
                    document.getElementById('eventStart').innerText = info.event.start.toLocaleString();
                    document.getElementById('eventEnd').innerText = info.event.end ? info.event.end.toLocaleString() : 'N/A';
                    document.getElementById('eventDescription').innerText = info.event.extendedProps.description || 'No details provided.';

                    var eventModal = new bootstrap.Modal(document.getElementById('eventModal'));
                    eventModal.show();
                }
            });
        }
        setTimeout(() => calendar.render(), 300);
    });
});*/







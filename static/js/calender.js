
    $(document).ready(function () {
      const socket = io(); // Initialize Socket.IO
      const calendarEl = document.getElementById('calendar');
      let calendar = null;

      // Initialize the calendar when the modal is shown
      $('#calendarModal').on('shown.bs.modal', function () {
        if (!calendar) {
          calendar = new FullCalendar.Calendar(calendarEl, {
            initialView: 'dayGridMonth',
            events: [], // Start with no events
            eventClick: function (info) {
              alert(`Title: ${info.event.title}\nDescription: ${info.event.extendedProps.description}\nStart: ${info.event.start}\nEnd: ${info.event.end}`);
            },
          });
          calendar.render();
        }
      });

      // Function to dynamically update events
      function updateCalendarEvents(eventList) {
        if (calendar) {
          calendar.removeAllEvents(); // Remove all existing events
          eventList.forEach(event => {
            calendar.addEvent({
              id: event.id,
              title: event.title,
              start: event.start,
              end: event.end,
              description: event.description,
            });
          });
        }
      }

      // Example event list
      const newEventList = [
        {
          id: '1',
          title: 'Medical Camp - Doctor Consultation',
          description: 'description1',
          start: '2025-02-15T11:00:00',
          end: '2025-02-15T11:30:00',
        },
        {
          id: '2',
          title: 'Health Checkup',
          description: 'description2',
          start: '2025-02-16T10:00:00',
          end: '2025-02-16T11:00:00',
        },
      ];

      // Simulating receiving events from a server using Socket.IO
      socket.on('new-events', function (data) {
        console.log('Received new events:', data);
        updateCalendarEvents(data);
      });

      // Simulating event broadcast after a delay
      setTimeout(() => {
        socket.emit('broadcast-events', newEventList); // Emit event to simulate server update
        socket.on('new-events', newEventList); // Update the calendar with new events
      }, 2000);
    });
  
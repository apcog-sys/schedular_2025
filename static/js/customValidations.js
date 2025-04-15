/*
    <form class="needs-validation" novalidate>
    <div class="mb-3">
        <label for="dob" class="form-label">Date of Birth</label>
        <input type="date" class="form-control" id="dob" required>
        <div class="invalid-feedback">Please enter a valid date.</div>
    </div>
    <button class="btn btn-primary" type="submit">Submit</button>
    </form>
*/
<script>
document.addEventListener("DOMContentLoaded", function () {
  let form = document.querySelector(".needs-validation");
  
  form.addEventListener("submit", function (event) {
    let dobInput = document.getElementById("dob");

    if (!dobInput.value) {
      dobInput.classList.add("is-invalid");
    } else {
      dobInput.classList.remove("is-invalid");
      dobInput.classList.add("is-valid");
    }

    if (!form.checkValidity()) {
      event.preventDefault();
      event.stopPropagation();
    }

    form.classList.add("was-validated");
  });
});
</script>


/*
<form class="needs-validation" novalidate>
  <div class="mb-3">
    <label for="dob" class="form-label">Date of Birth</label>
    <input type="date" class="form-control" id="dob" required>
    <div class="invalid-feedback">Date of Birth cannot be in the future.</div>
  </div>
  <button class="btn btn-primary" type="submit">Submit</button>
</form>*/

<script>
document.addEventListener("DOMContentLoaded", function () {
  let form = document.querySelector(".needs-validation");
  let dobInput = document.getElementById("dob");

  form.addEventListener("submit", function (event) {
    let today = new Date().toISOString().split("T")[0];

    if (dobInput.value > today) {
      dobInput.classList.add("is-invalid");
      event.preventDefault();
      event.stopPropagation();
    } else {
      dobInput.classList.remove("is-invalid");
      dobInput.classList.add("is-valid");
    }

    form.classList.add("was-validated");
  });
});
</script>


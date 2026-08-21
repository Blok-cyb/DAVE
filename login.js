// ==========================================
// LOGIN AUTHENTICATION
// Malware Detection System
// ==========================================

const loginForm = document.getElementById("loginForm");
const alertBox = document.getElementById("alertBox");
const loginButton = loginForm.querySelector("button[type='submit']");

loginForm.addEventListener("submit", function (e) {

    e.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    // ==========================
    // EMPTY FIELD CHECK
    // ==========================

    if (email === "" || password === "") {

        showAlert("Please fill in all fields");

        return;
    }

    // ==========================
    // EMAIL VALIDATION
    // ==========================

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email)) {

        showAlert("Please enter a valid email address");

        return;
    }

    // ==========================
    // DISABLE BUTTON
    // ==========================

    loginButton.disabled = true;
    loginButton.innerHTML = "Logging in...";

    // ==========================
    // LOGIN USING FLASK BACKEND
    // ==========================

    fetch("http://127.0.0.1:5000/login", {

        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({

            email: email,

            password: password

        })

    })

    .then(async (response) => {

        const data = await response.json();

        if (data.success) {

            // ==========================
// STORE LOGIN SESSION
// ==========================

localStorage.setItem("loggedIn", "true");

localStorage.setItem(
    "user",
    JSON.stringify(data.user)
);

localStorage.setItem(
    "currentUser",
    data.user.fullname
);

            alertBox.style.background = "#16a34a";
            alertBox.style.display = "block";
            alertBox.innerHTML = data.message;

            setTimeout(() => {

                window.location.href = "dashboard.html";

            }, 2000);

        }

        else {

            showAlert(data.message);

        }

    })

    .catch((error) => {

        console.error(error);

        showAlert("Unable to connect to the server.");

    })

    .finally(() => {

        loginButton.disabled = false;
        loginButton.innerHTML = "Login";

    });

});



// ==========================================
// ALERT FUNCTION
// ==========================================

function showAlert(message) {

    alertBox.style.background = "#dc2626";

    alertBox.style.display = "block";

    alertBox.innerHTML = message;

    setTimeout(() => {

        alertBox.style.display = "none";

    }, 3000);

}



// ==========================================
// SHOW / HIDE PASSWORD
// ==========================================

const togglePassword =
document.getElementById("togglePassword");

const passwordInput =
document.getElementById("password");

togglePassword.addEventListener("click", function () {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";

        this.classList.remove("fa-eye");

        this.classList.add("fa-eye-slash");

    }

    else {

        passwordInput.type = "password";

        this.classList.remove("fa-eye-slash");

        this.classList.add("fa-eye");

    }

});
// ==========================================
// SIGNUP AUTHENTICATION
// Malware Detection System
// ==========================================



const signupForm = document.getElementById("signupForm");

const alertBox = document.getElementById("alertBox");





signupForm.addEventListener("submit", function(e){


    e.preventDefault();



    const fullname =
    document.getElementById("fullname").value.trim();



    const email =
    document.getElementById("email").value.trim();



    const password =
    document.getElementById("password").value;



    const confirmPassword =
    document.getElementById("confirmPassword").value;





    // ==========================
    // EMPTY FIELD CHECK
    // ==========================


    if(
        fullname === "" ||
        email === "" ||
        password === "" ||
        confirmPassword === ""
    ){

        showAlert(
            "Please fill in all fields"
        );

        return;

    }







    // ==========================
    // NAME VALIDATION
    // ==========================


    const namePattern =
    /^[A-Za-z ]+$/;



    if(!namePattern.test(fullname)){


        showAlert(
            "Full name should contain only letters"
        );


        return;

    }







    // ==========================
    // EMAIL VALIDATION
    // ==========================


    const emailPattern =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;



    if(!emailPattern.test(email)){


        showAlert(
            "Please enter a valid email address"
        );


        return;

    }







    // ==========================
    // PASSWORD SECURITY CHECK
    // ==========================


    if(password.length < 8){


        showAlert(
            "Password must contain at least 8 characters"
        );


        return;

    }





    if(!/[A-Z]/.test(password)){


        showAlert(
            "Password must contain an uppercase letter"
        );


        return;

    }





    if(!/[a-z]/.test(password)){


        showAlert(
            "Password must contain a lowercase letter"
        );


        return;

    }





    if(!/[0-9]/.test(password)){


        showAlert(
            "Password must contain a number"
        );


        return;

    }





    if(!/[!@#$%^&*(),.?":{}|<>]/.test(password)){


        showAlert(
            "Password must contain a special character"
        );


        return;

    }







    // ==========================
    // PASSWORD MATCH
    // ==========================


    if(password !== confirmPassword){


        showAlert(
            "Passwords do not match"
        );


        return;

    }







    // ==========================
    // CHECK EXISTING USER
    // ==========================

// ==========================
// SEND DATA TO BACKEND
// ==========================

fetch("http://127.0.0.1:5000/signup", {

    method: "POST",

    headers: {
        "Content-Type": "application/json"
    },

    body: JSON.stringify({

        fullname: fullname,

        email: email,

        password: password

    })

})

.then(response => response.json())

.then(data => {

    if(data.success){

        alertBox.style.background = "#16a34a";

        alertBox.style.display = "block";

        alertBox.innerHTML = data.message;

        setTimeout(() => {

            window.location.href = "login.html";

        }, 2000);

    }

    else{

        showAlert(data.message);

    }

})

.catch(error => {

    console.error(error);

    showAlert("Unable to connect to the server.");

});


// ==========================================
// ALERT FUNCTION
// ==========================================


function showAlert(message){



    alertBox.style.background =
    "#dc2626";



    alertBox.style.display =
    "block";



    alertBox.innerHTML =
    message;





    setTimeout(()=>{


        alertBox.style.display =
        "none";



    },3000);



}









// ==========================================
// SHOW / HIDE PASSWORD
// ==========================================



const togglePassword =
document.getElementById("togglePassword");



const passwordInput =
document.getElementById("password");





togglePassword.addEventListener(
"click",
function(){



    if(passwordInput.type === "password"){


        passwordInput.type =
        "text";



        this.classList.remove(
            "fa-eye"
        );


        this.classList.add(
            "fa-eye-slash"
        );


    }

    else{


        passwordInput.type =
        "password";



        this.classList.remove(
            "fa-eye-slash"
        );


        this.classList.add(
            "fa-eye"
        );


    }



});})
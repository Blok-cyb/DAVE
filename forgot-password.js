// ==========================================
// FORGOT PASSWORD AUTHENTICATION
// Malware Detection System
// ==========================================

const forgotPasswordForm =
document.getElementById("forgotPasswordForm");

const alertBox =
document.getElementById("alertBox");

const resetButton =
forgotPasswordForm.querySelector("button[type='submit']");

forgotPasswordForm.addEventListener(
"submit",
function(e){

    e.preventDefault();

    const email =
    document.getElementById("email").value.trim();

    const newPassword =
    document.getElementById("newPassword").value;

    const confirmPassword =
    document.getElementById("confirmPassword").value;

    // ==========================
    // EMPTY FIELD CHECK
    // ==========================

    if(
        email === "" ||
        newPassword === "" ||
        confirmPassword === ""
    ){

        showAlert("Please fill in all fields");

        return;

    }

    // ==========================
    // EMAIL VALIDATION
    // ==========================

    const emailPattern =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if(!emailPattern.test(email)){

        showAlert("Please enter a valid email address");

        return;

    }

    // ==========================
    // PASSWORD SECURITY CHECK
    // ==========================

    if(newPassword.length < 8){

        showAlert(
            "Password must contain at least 8 characters"
        );

        return;

    }

    if(!/[A-Z]/.test(newPassword)){

        showAlert(
            "Password must contain an uppercase letter"
        );

        return;

    }

    if(!/[a-z]/.test(newPassword)){

        showAlert(
            "Password must contain a lowercase letter"
        );

        return;

    }

    if(!/[0-9]/.test(newPassword)){

        showAlert(
            "Password must contain a number"
        );

        return;

    }

    if(!/[!@#$%^&*(),.?":{}|<>]/.test(newPassword)){

        showAlert(
            "Password must contain a special character"
        );

        return;

    }

    // ==========================
    // PASSWORD MATCH
    // ==========================

    if(newPassword !== confirmPassword){

        showAlert("Passwords do not match");

        return;

    }

    // ==========================
    // DISABLE BUTTON
    // ==========================

    resetButton.disabled = true;

    resetButton.innerHTML = "Resetting...";

    // ==========================
    // SEND TO FLASK BACKEND
    // ==========================

    fetch("http://127.0.0.1:5000/forgot-password",{

        method:"POST",

        headers:{

            "Content-Type":"application/json"

        },

        body:JSON.stringify({

            email:email,

            password:newPassword

        })

    })

    .then(async(response)=>{

        const data = await response.json();

        if(data.success){

            alertBox.style.background="#16a34a";

            alertBox.style.display="block";

            alertBox.innerHTML=data.message;

            setTimeout(()=>{

                window.location.href="login.html";

            },2000);

        }

        else{

            showAlert(data.message);

        }

    })

    .catch(error=>{

        console.error(error);

        showAlert("Unable to connect to the server.");

    })

    .finally(()=>{

        resetButton.disabled=false;

        resetButton.innerHTML="Reset Password";

    });

});


// ==========================================
// ALERT FUNCTION
// ==========================================

function showAlert(message){

    alertBox.style.background="#dc2626";

    alertBox.style.display="block";

    alertBox.innerHTML=message;

    setTimeout(()=>{

        alertBox.style.display="none";

    },3000);

}


// ==========================================
// SHOW / HIDE PASSWORD
// ==========================================

const togglePassword =
document.getElementById("togglePassword");

const passwordInput =
document.getElementById("newPassword");

togglePassword.addEventListener(
"click",
function(){

    if(passwordInput.type==="password"){

        passwordInput.type="text";

        this.classList.remove("fa-eye");

        this.classList.add("fa-eye-slash");

    }

    else{

        passwordInput.type="password";

        this.classList.remove("fa-eye-slash");

        this.classList.add("fa-eye");

    }

});
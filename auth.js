// ==========================================
// AUTHENTICATION SECURITY SYSTEM
// Malware Detection System
// ==========================================



// ===============================
// CHECK LOGIN SESSION
// ===============================


function checkAuth(){


    let loggedIn =
    localStorage.getItem("loggedIn");



    if(loggedIn !== "true"){


        window.location.href =
        "login.html";


    }


}






// ===============================
// GET CURRENT USER
// ===============================


function getCurrentUser(){


    let user =
    localStorage.getItem("user");



    if(user){


        return JSON.parse(user);


    }


    return null;


}






// ===============================
// DISPLAY USERNAME
// ===============================


function displayUsername(){


    let user =
    getCurrentUser();



    let username =
    document.getElementById("username");



    if(user && username){


        username.innerHTML =
        user.fullname;


    }


}







// ===============================
// LOGOUT FUNCTION
// ===============================


function logout(){



    localStorage.removeItem(
        "loggedIn"
    );



    localStorage.removeItem(
        "currentUser"
    );



    window.location.href =
    "login.html";



}







// ===============================
// AUTO RUN SECURITY CHECK
// ===============================


// Pages that require authentication


const protectedPages = [


    "dashboard.html",

    "scan.html",

    "activity.html",

    "detection.html",

    "report.html"


];





let currentPage =
window.location.pathname;



protectedPages.forEach(page=>{


    if(currentPage.includes(page)){


        checkAuth();


    }


});







// Load username when page opens


document.addEventListener(
"DOMContentLoaded",
()=>{


    displayUsername();


});
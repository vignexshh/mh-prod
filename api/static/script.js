//ADMIN DASHBOARD PAGE
//----------------------------------------
//accepting requested users
function acceptUser(username) {
    fetch(`/accept_requested_user/${username}`, {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === 'User accepted successfully') {
            document.getElementById(username).remove();
            //alert('User accepted successfully');
            //reloadPage();
            location.reload();
        } else {
            alert('Failed to accept user');
            location.reload();
        }
    });
}
//deleting requested users
function deleteRow(username) {
    fetch(`/reject_requested_user/${username}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === 'User rejected successfully') {
            document.getElementById(username).remove();
            //alert('User Rejected successfully');
            location.reload();
        } else {
            alert('Failed to Reject user');
            location.reload()
        }
    });
}
//searching for requested users
function searchRequestedUser(){
    inputSearch = document.getElementById('requestedSearch').value;

    fetch(`/requested_users_search`,{
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ inputSearch: inputSearch }),
    })
    .then(response => response.json())
    .then(data => {
        if(data.message === 'Search Success'){
            //alert("Users Found");
            updateRequestedTable(data.requested_users);
        }else{
            //alert(data.message)
            alert("Error Occured While Searching");
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while processing the search request');
    });
}
function updateRequestedTable(requested_users){
    var table = document.getElementById('requestedUsersTable');
    table.innerHTML = '<tr><th>Username</th><th>Email</th><th>Password</th><th>TransactionId</th><th>Accept</th><th>Reject</th></tr>';

    //iterate over the requested users and add them to the table
    requested_users.forEach(user => {
        var row = table.insertRow(-1);
        row.id = user.username;
        row.insertCell(0).innerHTML = user.username;
        row.insertCell(1).innerHTML = user.email;
        row.insertCell(2).innerHTML = user.password;
        row.insertCell(3).innerHTML = user.transactionId;
        row.insertCell(4).innerHTML = `
        <button type="button" onclick="acceptUser('{{user.username}}')">Accept</button>`
        row.insertCell(5).innerHTML =`
        <button class="reject" type="button" onclick="deleteRow('{{user.username}}')">Reject</button>`
    });

    var message = document.getElementById('messageRequestedSearch');
    if (requested_users.length == 0) {
        message.innerHTML = 'No user found';
    }else{
        message.innerHTML = '';
    }
}



//ACCEPTED USERS PAGE
//----------------------------------------
//deleting accepted users
function deleteAcceptedUser(username) {
    fetch(`/delete_accepted_user/${username}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === 'User deleted successfully') {
            //alert('User deleted successfully');
            document.getElementById(username).remove();
            location.reload();
        } else {
            alert('Failed to delete user');
            location.reload()
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while processing the request');
    });
}
//searching for accepted users
function searchAcceptedUser() {
    inputSearch = document.getElementById('acceptedSearch').value;

    fetch(`/accepted_users_search`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ inputSearch: inputSearch }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === 'Search Success') {
            // Update the table with the new data
            //alert('User found')
            updateAcceptedTable(data.accepted_users);
        } else {
            //alert(data.message)
            alert('Error Occured While Searching');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while processing the search request');
    });
}

function updateAcceptedTable(accepted_users) {
    // Clear the existing table
    var table = document.getElementById('acceptedUsersTable');
    table.innerHTML = '<tr><th>Username</th><th>Email</th><th>Password</th><th>Transaction ID</th><th>Action</th></tr>';

    // Populate the table with the new data
    accepted_users.forEach(user => {
        var row = table.insertRow(-1);
        row.id = user.username;
        row.insertCell(0).innerHTML = user.username;
        row.insertCell(1).innerHTML = user.email;
        row.insertCell(2).innerHTML = user.password;
        row.insertCell(3).innerHTML = user.transactionId;
        row.insertCell(4).innerHTML = `<button class="delete" type="button" onclick="deleteAcceptedUser('${user.username}')">Delete</button>`;
    });

    var message = document.getElementById('messageAceptedSearch');
    if (accepted_users.length == 0) {
        message.innerHTML = 'No user found';
    }else{
        message.innerHTML = '';
    }
}


//Forgot Password Page
//----------------------------------------
function sendOTP(username){
    //alert(username.value)
    if(username.value == ""){
        alert('Please enter username');
        return;
    }

    fetch(`/send_otp_to_user/${username.value}`, {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        console.log(data);
        if( data.status == 'success'){
            alert('OTP sent successfully');

            //disable button for 30 seconds
            var button = document.getElementById('sendotp');
            button.disabled = true;
            button.innerHTML = 'OTP Sent';
            var timer = document.getElementById('timer');
            var timeleft = 30;
            var downloadTimer = setInterval(function(){
                if(timeleft <= 0){
                    clearInterval(downloadTimer);
                    button.innerHTML = "Resend OTP";
                    button.disabled = false;
                    timer.innerHTML = "";
                } else {
                    timer.innerHTML = timeleft + " for Resend OTP";
                }
                timeleft -= 1;
            }, 1000);

        }
        else if( data.status == 'Not Found'){
            alert('Username not found');
        }
        else {
            alert('Error in sending OTP');
        }
    
    })
}


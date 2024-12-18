function enableButton() {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginButton = document.getElementById('loginbtn');
    if (usernameInput.value.trim() && passwordInput.value.trim()) {
        loginButton.disabled = false;
    } 
    else {
        loginButton.disabled = true;
    }
}

function showpassword() {
    const passwordInput = document.getElementById('password');
    passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
}

function showToast(message, category) {
    const toast = document.createElement('div');
    toast.className = `toast ${category}`;
    toast.innerText = message;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
    }, 100);

    setTimeout(() => {
        toast.classList.remove('show');
        toast.classList.add('fade-out');
        toast.addEventListener('animationend', () => toast.remove());
    }, 3500);
}

window.onload = function() {
    const flashMessages = document.getElementById("flash-messages");
    if (flashMessages) {
        const message = flashMessages.getAttribute('data-message');
        const category = flashMessages.getAttribute('data-category');
        showToast(message, category);
    }
};

function darkmode() {
    const darkButton = document.getElementById('darkbutton');
    const body = document.body;
    if (darkButton.checked) {
        body.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
    } else {
        body.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme');
    const darkButton = document.getElementById('darkbutton');
    
    if (savedTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        darkButton.checked = true;
    } else {
        document.body.removeAttribute('data-theme');
        darkButton.checked = false;
    }
});

function toggleProfileOptions() {
    const profileOptions = document.getElementById('profileOptions');
    if (profileOptions.style.display === "none") {
        profileOptions.style.display = "block";
    } else {
        profileOptions.style.display = "none";
    }
}

function confirmDelete(event, form) {
    event.preventDefault();
    Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, delete it!'
    }).then((result) => {
        if (result.isConfirmed) {
            form.submit(); 
        }
    });
}

$(document).ready(function() {
    $(".scan-form").submit(function(event) {
        event.preventDefault();

        var targetId = $(this).data('target-id');
        var form = $(this);
        var targetStatus = $('#status-' + targetId);
        var statusElement = targetStatus.find("span");

        statusElement.text("Scanning...").removeClass().addClass("status-scanning");

        $.post(form.attr('action'), function(response) {
            checkScanProgress(targetId); // Start checking progress
        }).fail(function() {
            statusElement.text('Scan Error').removeClass().addClass("status-error");
        });
    });
});

function checkScanProgress(targetId) {
    const statusElement = $('#status-' + targetId).find("span");
    const progressBar = $('#progress-bar-' + targetId);

    const progressInterval = setInterval(function() {
        $.get("/scanner/scan_progress/" + targetId, function(progressResponse) {
            const progress = progressResponse.progress;
            const statusText = "Scanning... (" + progress + "%)";
            
            // Update status and progress bar
            statusElement.text(statusText);
            progressBar.css('width', progress + '%').text(progress + '%');
            
            if (progress === 100) {
                clearInterval(progressInterval);
                statusElement.text('Completed').removeClass().addClass("status-completed");
                progressBar.css('width', '100%').text(' 100%');

                window.location.href = '/scanner/view_scan/' + targetId; // Redirect to results page
            }
            
        }).fail(function() {
            clearInterval(progressInterval);
            statusElement.text('Scan Error').removeClass().addClass("status-error");
            progressBar.css('width', '0%').text('0%');
        });
    }, 2000); // Update every 2 seconds
}
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

document.addEventListener('click', function (event) {
    const profileOptions = document.getElementById('profileOptions');
    const userIcon = document.getElementById('userIcon');
    if (!profileOptions.contains(event.target) && !userIcon.contains(event.target)) {
        profileOptions.style.display = 'none';
    }
});

function startScan(targetId) {
    Swal.fire({
        title: 'Initiating Scan',
        html: 'Preparing to scan the target...',
        didOpen: () => {
            Swal.showLoading();
        }
    });

    fetch(`/scan/${targetId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.scan_session_id) {
            trackScanProgress(data.scan_session_id, targetId);
        } else {
            Swal.fire('Error', 'Could not start scan', 'error');
        }
    })
    .catch(error => {
        console.error('Scan initiation error:', error);
        Swal.fire('Error', 'Failed to start scan', 'error');
    });
}

function trackScanProgress(scanSessionId, targetId) {
    let progressInterval = setInterval(() => {
        fetch(`/scan/status/${scanSessionId}`)
        .then(response => response.json())
        .then(data => { if (data.is_complete) {
                clearInterval(progressInterval);
                Swal.fire({
                    title: 'Scan Completed',
                    text: 'The scan has finished successfully.',
                    icon: 'success'
                }).then(() => {
                    window.location.reload();
                });
            } else {
                Swal.getContent().innerHTML = `Scanning... ${data.progress}%<br>Status: ${data.status}`;
            }
        })
        .catch(error => {
            clearInterval(progressInterval);
            console.error('Error fetching scan status:', error);
            Swal.fire('Error', 'Failed to retrieve scan status', 'error');
        });
    }, 2000);
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

document.addEventListener('DOMContentLoaded', () => {
    const scanForms = document.querySelectorAll('.scan-form');

    scanForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            const targetId = this.querySelector('input[name="target_id"]')?.value || 
                             this.getAttribute('data-target-id');
            const statusCell = document.getElementById(`status-${targetId}`);

            statusCell.innerHTML = `
                <span class="status-scanning">Scanning...</span>
                <div class="progress-container">
                    <div class="progress-bar" id="progress-${targetId}"></div>
                </div>
            `;

            // Send scan request
            fetch(`/scan/${targetId}`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            })
            .then(response => {
                console.log('Scan initiation response status:', response.status);
                
                 if (!response.ok) {
                    return response.json().then(errData => {
                        throw new Error(errData.error || 'Network response was not ok');
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data.scan_session_id) {
                    trackScanProgress(data.scan_session_id, targetId);
                } else {
                    throw new Error('No scan session ID received');
                }
            })
            .catch(error => {
                console.error('Scan initiation error:', error);
                statusCell.innerHTML = `
                    <span class="status-error">Scan Error</span>
                    <span class="ml-2" data-toggle="tooltip" title="${error.message}">
                        <i class="fas fa-exclamation-circle text-danger"></i>
                    </span>
                `;
            });
        });
    });

    function trackScanProgress(scanSessionId, targetId) {
        const progressBar = document.getElementById(`progress-${targetId}`);
        const statusCell = document.getElementById(`status-${targetId}`);

        function updateProgress() {
            fetch(`/scan_status/${scanSessionId}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to fetch scan status');
                    }
                    return response.json();
                })
                .then(data => {
                    if (progressBar) {
                        progressBar.style.width = `${data.progress}%`;
                    }

                    if (data.is_complete) {
                        if (data.status.toLowerCase().includes('error')) {
                            statusCell.innerHTML = `
                                <span class="status-error">Scan Error</span>
                                <span class="ml-2" data-toggle="tooltip" title="${data.status}">
                                    <i class="fas fa-exclamation-circle text-danger"></i>
                                </span>
                            `;
                        } else {
                            statusCell.innerHTML = `
                                <span class="status-completed">Completed</span>
                            `;
                        }
                        setTimeout(() => {
                            window.location.reload();
                        }, 1000);
                    } else {
                        setTimeout(updateProgress, 500);
                    }
                })
                .catch(error => {
                    console.error('Progress tracking error:', error);
                    statusCell.innerHTML = `
                        <span class="status-error">Scan Error</span>
                        <span class="ml-2" data-toggle="tooltip" title="${error.message}">
                            <i class="fas fa-exclamation-circle text-danger"></i>
                        </span>
                    `;
                });
        }
        updateProgress();
    }
});
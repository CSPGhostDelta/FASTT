function startScan(event, form) {
    event.preventDefault();
    const targetId = form.getAttribute('data-target-id');
    
    fetch(form.action, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
    })
    .then(response => {
        if (response.ok) {
            showToast(`Scan started for target: ${targetId}`, 'success');
            setTimeout(() => {
                location.reload();
            }, 1000);
        } else {
            showToast('Failed to start scan. Please try again.', 'error');
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showToast('Failed to start scan. Please try again.', 'error');
    });
}

function pollScanStatus(targetId) {
    const statusElement = document.getElementById(`status-${targetId}`);
    const progressElement = document.getElementById(`progress-${targetId}`);
    let progress = 0;

    const intervalId = setInterval(() => {
        fetch(`/scanner/scan_status/${targetId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'Completed') {
                    clearInterval(intervalId);
                    setTimeout(() => {
                        location.reload();
                    }, 1000);
                } else if (data.status === 'Failed' || data.status === 'Scan Error') {
                    clearInterval(intervalId);
                    setTimeout(() => {
                    });
                } else if (data.status.startsWith('Scanning')) {
                    statusElement.innerHTML = `<span class="status-scanning">${data.status}</span>`;
                    progressElement.style.display = 'inline';
                }
            })
            .catch(error => {
                console.error('Error fetching scan status:', error);
                setTimeout(() => {
                    location.reload();
                }, 1000);
            });
    }, 1000);

    const progressIntervalId = setInterval(() => {
        if (progress <= 100) {
            progressElement.innerText = `${progress}%`;
            progress++;
        } else {
            clearInterval(progressIntervalId);
        }
    }, 50);
}

window.onload = function() {
    const flashMessages = document.getElementById('flash-messages');
    if (flashMessages && flashMessages.dataset.message) {
        showToast(flashMessages.dataset.message, flashMessages.dataset.category || 'success');
    }

    const targetElements = document.querySelectorAll('[id^="status-"]');
    targetElements.forEach(element => {
        const id = element.id.split('-')[1];
        const currentStatus = element.querySelector('span').textContent.trim();
        
        if (currentStatus.startsWith('Scanning')) {
            pollScanStatus(id);
        }
        
        if (currentStatus === 'Scan Error') {
            pollScanStatus(id);
        }
    });
}
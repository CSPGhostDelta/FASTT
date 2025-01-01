function enableButton() {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginButton = document.getElementById('loginbtn');
    if (usernameInput.value.trim() && passwordInput.value.trim()) {
        loginButton.disabled = false;
    } else {
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
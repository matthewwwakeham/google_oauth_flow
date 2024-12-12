// Helper functions for showing and hiding errors
function showError(id, message) {
    const errorSpan = document.getElementById(id);
    if (errorSpan) {
        errorSpan.textContent = message;
        errorSpan.classList.add('active');
        const inputId = id.replace('Error', '');
        const input = document.getElementById(inputId);
        if (input) input.setAttribute('aria-describedby', id); // Link error to input
    }
}

function hideError(id) {
    const errorSpan = document.getElementById(id);
    if (errorSpan) {
        errorSpan.textContent = '';
        errorSpan.classList.remove('active');
        const inputId = id.replace('Error', '');
        const input = document.getElementById(inputId);
        if (input) input.removeAttribute('aria-describedby'); // Remove link
    }
}

// Validation functions
function validateUsername() {
    const username = document.getElementById('username').value.trim();
    const usernamePattern = /^[a-zA-Z0-9]+$/;
    if (username.length < 3 || username.length > 15 || !usernamePattern.test(username)) {
        showError('usernameError', 'Username must be 3-15 characters long and contain only letters and numbers.');
        return false;
    } else {
        hideError('usernameError');
        return true;
    }
}

function validateEmail() {
    const email = document.getElementById('email').value.trim();
    if (email.length > 254 || !email.includes('@') || !email.includes('.')) {
        showError('emailError', 'Please enter a valid email address with no more than 254 characters.');
        return false;
    } else {
        hideError('emailError');
        return true;
    }
}

function validatePassword() {
    const password = document.getElementById('password').value;
    const passwordPattern = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_\-+={}[\]:;"'|\\<>,.?/~`]).{8,}$/;
    if (password.length < 8 || !passwordPattern.test(password)) {
        showError('passwordError', 'Password must be at least 8 characters long, contain one uppercase letter, one lowercase letter, one number, and one special character.');
        return false;
    } else {
        hideError('passwordError');
        return true;
    }
}

function validateConfirmPassword() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    if (confirmPassword !== password) {
        showError('confirmPasswordError', 'Passwords do not match. Please confirm your password.');
        return false;
    } else {
        hideError('confirmPasswordError');
        return true;
    }
}

// Final form validation
function validateForm() {
    const isUsernameValid = validateUsername();
    const isEmailValid = validateEmail();
    const isPasswordValid = validatePassword();
    const isConfirmPasswordValid = validateConfirmPassword();

    return isUsernameValid && isEmailValid && isPasswordValid && isConfirmPasswordValid;
}

// Set up event listeners on page load
document.addEventListener("DOMContentLoaded", () => {
    // Clear inputs and error messages
    document.querySelectorAll('.input-field').forEach(input => {
        if (input.type !== 'submit') {
            input.value = ''; // Clear only text, email, and password fields
        }
    });
    document.querySelectorAll('.error-message').forEach(error => (error.textContent = ''));

    // Dynamically map validation functions
    const validationMap = {
        username: validateUsername,
        email: validateEmail,
        password: validatePassword,
        'confirm-password': validateConfirmPassword,
    };

    Object.keys(validationMap).forEach(id => {
        document.getElementById(id).addEventListener('input', validationMap[id]);
    });
});

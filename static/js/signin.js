// Function to unhide error messages for the sign-in page
document.addEventListener("DOMContentLoaded", () => {
    const errorMessages = document.querySelectorAll(".error-message");

    // Loop through all error message spans and make them visible if they have content
    errorMessages.forEach((message) => {
        if (message.textContent.trim() !== "") {
            message.classList.add("active");
        }
    });
});
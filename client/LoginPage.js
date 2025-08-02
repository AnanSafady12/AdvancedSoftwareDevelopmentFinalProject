/**
 * File: LoginPage.js
 * Description:
 * This script handles the login form logic for the Pokémon project.
 * Features:
 * - Validates email and password input fields in real-time
 * - Displays error messages with styled feedback
 * - Submits login request via AJAX (no page reload)
 * - Redirects user to /home on successful login
 * - Handles login failures with clear feedback
 */

document.addEventListener("DOMContentLoaded", () => {
    // === 🔗 Get form fields and error display elements ===
    const form = document.getElementById("login-form");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const emailError = document.getElementById("emailError");
    const passwordError = document.getElementById("passwordError");

    // === ❌ Show input as invalid with message ===
    function showError(input, message, errorElem) {
        input.classList.add("invalid");
        input.classList.remove("valid");
        errorElem.textContent = message;
    }

    // === ✅ Show input as valid and clear error ===
    function showSuccess(input, errorElem) {
        input.classList.remove("invalid");
        input.classList.add("valid");
        errorElem.textContent = "";
    }

    // === 📧 Validate email format using regex ===
    function validateEmail() {
        const value = emailInput.value.trim();
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/; // Basic email pattern

        if (!regex.test(value)) {
            showError(emailInput, "Invalid email format", emailError);
            return false;
        }

        showSuccess(emailInput, emailError);
        return true;
    }

    // === 🔒 Validate password length (7–15 chars) ===
    function validatePassword() {
        const value = passwordInput.value;

        if (value.length < 7 || value.length > 15) {
            showError(passwordInput, "Password must be 7–15 characters", passwordError);
            return false;
        }

        showSuccess(passwordInput, passwordError);
        return true;
    }

    // === 🟡 Real-time validation while typing ===
    emailInput.addEventListener("input", validateEmail);
    passwordInput.addEventListener("input", validatePassword);

    // === 📤 Form submission with async POST request ===
    form.addEventListener("submit", async (e) => {
        e.preventDefault(); // Prevent full page reload

        // Validate all fields before sending
        const valid = [
            validateEmail(),
            validatePassword()
        ].every(Boolean);

        if (!valid) return;

        // 📦 Build request body
        const payload = {
            email: emailInput.value.trim(),
            password: passwordInput.value
        };

        try {
            // 🚀 Send POST request to backend /login route
            const response = await fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (result.success) {
                // ✅ Login successful — redirect to home page
                console.log(result); // Debugging: log the full response
                window.location.href = "/home";
            } else {
                // ❌ Handle specific login errors
                if (result.error === "invalid_credentials") {
                    showError(emailInput, "Email or password incorrect", emailError);
                    showError(passwordInput, "", passwordError); // clear style only
                } else {
                    alert("Login failed. Try again later.");
                }
            }
        } catch (err) {
            // 🔥 Network/server error
            console.error("Login error:", err);
            alert("Server error. Please try again later.");
        }
    });
});

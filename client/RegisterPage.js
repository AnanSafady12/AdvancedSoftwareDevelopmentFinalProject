/**
 * File: RegisterPage.js
 * Description:
 * Handles client-side form validation and AJAX-based submission for the registration page.
 * Features:
 * - Live input validation for name, email, password, and confirm password fields
 * - Styled error/success feedback using class toggling
 * - Sends form data to backend via POST /register
 * - Redirects to /login if registration is successful
 */

document.addEventListener("DOMContentLoaded", () => {
    // === 🔗 Get references to form fields and error elements ===
    const form = document.getElementById("register-form");
    const firstName = document.getElementById("firstName");
    const email = document.getElementById("email");
    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("confirmPassword");

    const firstNameError = document.getElementById("firstNameError");
    const emailError = document.getElementById("emailError");
    const passwordError = document.getElementById("passwordError");
    const confirmPasswordError = document.getElementById("confirmPasswordError");

    // === ❌ Utility: Show input as invalid with error message ===
    function showError(input, message, errorElem) {
        input.classList.add("invalid");
        input.classList.remove("valid");
        errorElem.textContent = message;
    }

    // === ✅ Utility: Show input as valid and clear error message ===
    function showSuccess(input, errorElem) {
        input.classList.remove("invalid");
        input.classList.add("valid");
        errorElem.textContent = "";
    }

    // === 👤 Validate full name: only letters and spaces, max 50 characters ===
    function validateName() {
        const value = firstName.value.trim();
        if (value === "" || value.length > 50 || /[^a-zA-Z ]/.test(value)) {
            showError(firstName, "Only letters allowed, max 50 chars", firstNameError);
            return false;
        }
        showSuccess(firstName, firstNameError);
        return true;
    }

    // === 📧 Validate email with standard pattern ===
    function validateEmail() {
        const value = email.value.trim();
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/; // Basic RFC email format
        if (!regex.test(value)) {
            showError(email, "Invalid email format", emailError);
            return false;
        }
        showSuccess(email, emailError);
        return true;
    }

    // === 🔑 Validate password strength:
    // 7–15 characters, at least one uppercase, one lowercase, and one special character ===
    function validatePassword() {
        const value = password.value;
        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z]).{7,15}$/;
        if (!regex.test(value)) {
            showError(password, "7-15 chars, 1 upper, 1 lower, 1 special", passwordError);
            return false;
        }
        showSuccess(password, passwordError);
        return true;
    }

    // === 🔁 Validate confirm password matches the original password ===
    function validateConfirmPassword() {
        if (confirmPassword.value !== password.value) {
            showError(confirmPassword, "Passwords do not match", confirmPasswordError);
            return false;
        }
        showSuccess(confirmPassword, confirmPasswordError);
        return true;
    }

    // === 🖊️ Enable live validation while typing ===
    firstName.addEventListener("input", validateName);
    email.addEventListener("input", validateEmail);
    password.addEventListener("input", validatePassword);
    confirmPassword.addEventListener("input", validateConfirmPassword);

    // === 📤 Form submission handler ===
    form.addEventListener("submit", async (e) => {
        e.preventDefault(); // Prevent default browser submission

        // ✅ Validate all fields before submission
        const valid = [
            validateName(),
            validateEmail(),
            validatePassword(),
            validateConfirmPassword()
        ].every(Boolean); // All must return true

        if (!valid) return; // Block submission if validation fails

        // 📦 Create payload object to send to backend
        const payload = {
            firstName: firstName.value.trim(),
            email: email.value.trim(),
            password: password.value
        };

        try {
            // 🚀 Send registration data to server
            const response = await fetch("/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (result.success) {
                alert("Registration successful! Redirecting to login...");
                window.location.href = "/login"; // ✅ Correct path
            } else {
                // ❌ Show the error message from server
                alert("Registration failed: " + result.message);
            }
        } catch (err) {
            console.error("Request error:", err);
            alert("Server error. Please try again later.");
        }

    });
});

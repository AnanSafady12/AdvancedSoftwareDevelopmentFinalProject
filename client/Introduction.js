/**
 * File: Introduction.js
 * Description:
 * This script runs on the Introduction.html page. It handles:
 * - Session checking: If the user is already logged in, they are redirected to HomePage.html.
 * - Dynamic content loading: Student info and project description are fetched from the server
 *   and injected into the DOM.
 * 
 * This ensures:
 * - Logged-in users don't return to the login/register screen by pressing "Back"
 * - Visitors always see up-to-date information about the students and the project
 */

document.addEventListener("DOMContentLoaded", async () => {
    // 🔒 STEP 1: Check session status (is the user already logged in?)
    try {
        const sessionRes = await fetch("/api/session");

        // If session is valid (user is logged in), redirect to homepage
        if (sessionRes.ok) {
            // This prevents users from navigating back to the Introduction page after logging in
            window.location.href = "/home";
            return; // Stop further execution
        }
    } catch (err) {
        // If there's an error (e.g., no session or network issue), assume not logged in
        // No need to alert or throw; just proceed to show the introduction page
    }

    // 📄 STEP 2: Fetch project info (students + description)
    try {
        const res = await fetch("/api/projectinfo");

        // Check if the response is OK (HTTP status 200–299)
        if (!res.ok) throw new Error("Failed to fetch project info");

        // Parse the JSON body of the response
        const data = await res.json();

        // Get references to the elements where we’ll insert the data
        const studentList = document.getElementById("student-info");
        const projectDesc = document.getElementById("project-description");

        // 👨‍🎓 Inject student list into the DOM (only if the container exists)
        if (studentList) {
            studentList.innerHTML = `
                <h2>Students:</h2>
                <ul>
                    ${data.students.map(s =>
                `<li><span class="dot"></span>${s.name} - ${s.id}</li>`
            ).join("")}
                </ul>
            `;
        }

        // 📘 Inject project description into the DOM (only if the container exists)
        if (projectDesc) {
            projectDesc.innerHTML = `
                <h3>Description:</h3>
                <p>${data.description}</p>
            `;
        }

    } catch (err) {
        // If something went wrong (network error, invalid response, etc.), log to console
        console.error("Error loading intro data:", err);
    }
});

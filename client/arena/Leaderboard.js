/**
 * 🏆 Leaderboard.js
 * This script handles:
 * - Fetching and rendering the leaderboard data from the backend.
 * - Displaying user rank, avatar, name, total score, and success rate.
 * - Handling user sign-out with a session-aware logout.
 */

document.addEventListener("DOMContentLoaded", async () => {

    // ✅ Session check
    const session = await checkSession();
    if (!session) return;

    // ✅ Handle Sign Out button
    document.getElementById("signOutBtn")?.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/logout", { method: "POST" });
            if (res.ok) {
                window.location.replace("/"); // Redirect to home page after logout
            } else {
                alert("Logout failed");
            }
        } catch (err) {
            console.error("Logout error:", err);
            alert("Logout error. Try again.");
        }
    });

    // ✅ Prevent back-navigation after logout
    window.addEventListener("pageshow", async (event) => {
        if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
            const session = await checkSession();
            if (!session) return;
        }
    });

    // 🔧 Session utility
    async function checkSession() {
        try {
            const res = await fetch("/api/session");
            if (!res.ok) throw new Error();
            return await res.json();
        } catch {
            window.location.replace("/");
            return null;
        }
    }

    // 📦 Reference to leaderboard table body
    const tableBody = document.getElementById("leaderboardBody");

    try {
        // 🌐 Fetch leaderboard data from the server
        const res = await fetch("/api/leaderboard");
        if (!res.ok) throw new Error("Leaderboard fetch failed");

        const users = await res.json(); // Array of users with score and successRate

        // 🧱 Insert rows dynamically
        users.forEach((user, index) => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${index + 1}</td>
                <td><img src="${user.avatar}" alt="avatar of ${user.name}" /></td>
                <td>${user.name}</td>
                <td>${user.score}</td>
                <td>${user.successRate}</td>
            `;

            tableBody.appendChild(row);
        });

    } catch (err) {
        console.error("❌ Failed to load leaderboard:", err);
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-danger text-center">
                    Failed to load data
                </td>
            </tr>
        `;
    }
});

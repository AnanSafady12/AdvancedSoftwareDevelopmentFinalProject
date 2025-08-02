/**
 * 🎮 FightsHistory.js
 * This script handles:
 * - Session verification
 * - Sign-out functionality
 * - Fetching and rendering user's fight history into a styled table
 * - Graceful handling of empty history or errors
 * 
 * Used on: /arena/FightsHistory.html
 * Related API:
 *   - GET /api/session → Verify user session
 *   - POST /api/logout → Logout the user
 *   - GET /api/history → Fetch user's battle history (VS Bot or Human)
 */

document.addEventListener("DOMContentLoaded", async () => {
    console.log("✅ FightsHistory.js loaded");

    // ✅ Check if user is logged in
    const session = await checkSession();
    if (!session) return;

    // ✅ Set up logout handler
    document.getElementById("signOutBtn")?.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/logout", { method: "POST" });
            if (res.ok) window.location.replace("/"); // Redirect to home
            else alert("Logout failed");
        } catch (err) {
            console.error("Logout error:", err);
            alert("Logout error. Try again.");
        }
    });

    // ✅ Prevent back navigation after logout (ensures session is still valid)
    window.addEventListener("pageshow", async (event) => {
        if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
            const session = await checkSession();
            if (!session) return;
        }
    });

    // 🔧 Helper: Check session and redirect to home if invalid
    async function checkSession() {
        try {
            const res = await fetch("/api/session");
            if (!res.ok) throw new Error();
            return await res.json(); // Returns: { userId, firstName }
        } catch {
            window.location.replace("/");
            return null;
        }
    }

    // ✅ Fetch and render user's fight history
    try {
        const res = await fetch("/api/history");
        if (!res.ok) throw new Error("Failed to fetch history");

        const history = await res.json(); // Array of fight records
        const tbody = document.getElementById("historyTableBody");

        // Empty state
        if (!Array.isArray(history) || history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5">No battles yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = ""; // Clear previous content

        // Loop through each battle entry and create a table row
        history.forEach(entry => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${entry.date}</td>
                <td>${entry.opponent}</td>
                <td class="text-capitalize">${entry.playerPokemon.name}</td>
                <td class="text-capitalize">${entry.opponentPokemon.name}</td>
                <td class="${entry.result === 'win' ? 'text-success' :
                    entry.result === 'lose' ? 'text-danger' :
                        'text-warning'
                }">
                    ${entry.result.toUpperCase()}
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (err) {
        console.error("❌ Error loading fight history:", err);
        document.getElementById("historyTableBody").innerHTML =
            `<tr><td colspan="5">Failed to load history.</td></tr>`;
    }
});

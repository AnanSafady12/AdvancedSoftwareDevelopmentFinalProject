/**
 * 🔥 Favorites.js — Client-Side Logic for Favorites Page
 *
 * Handles:
 * - Session validation and redirect if not logged in
 * - Loading and rendering the user's favorite Pokémon from backend
 * - Sorting (by ID or name)
 * - Removing Pokémon from favorites
 * - Downloading favorites as CSV
 * - Navigation protection on back/forward
 * - Sign out functionality
 */

/**
 * 🔥 Favorites.js — Client-Side Logic for Favorites Page
 */



document.addEventListener("DOMContentLoaded", async () => {
    // ✅ Session check
    const session = await checkSession();
    if (!session) return;

    const userId = session.userId;
    const container = document.getElementById("favoritesList");
    const sortDropdown = document.getElementById("sortSelect");
    const downloadBtn = document.getElementById("downloadBtn");

    let Favorites = [];

    // ✅ Sign Out Handler
    document.getElementById("signOutBtn")?.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/logout", { method: "POST" });
            if (res.ok) window.location.replace("/");
            else alert("Logout failed");
        } catch (err) {
            console.error("Logout error:", err);
            alert("Logout error. Try again.");
        }
    });

    // 🔁 Handle back/forward browser navigation
    window.addEventListener("pageshow", async (event) => {
        if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
            const session = await checkSession();
            if (!session) return;
        }
    });


    // 🔐 Utility function: check if session is valid
    async function checkSession() {
        try {
            const res = await fetch("/api/session");
            if (!res.ok) throw new Error();
            return await res.json();
        } catch (err) {
            window.location.replace("/");
            return null;
        }
    }


    // 📥 Load user's favorite Pokémon
    async function loadFavorites() {
        try {
            const res = await fetch(`/users/${userId}/favorites?enrich=false`);
            if (!res.ok) throw new Error("Could not load Favorites");
            Favorites = await res.json();
            renderFavorites();
        } catch (err) {
            console.error("❌ Error loading favorites:", err);
            container.innerHTML = "<p class='text-warning'>⚠️ Failed to load Favorites.</p>";
        }
    }

    // 🧱 Render Pokémon cards
    function renderFavorites() {
        container.innerHTML = "";

        if (Favorites.length === 0) {
            container.innerHTML = "<p>No favorite Pokémon yet!</p>";
            return;
        }

        const sortBy = sortDropdown.value;
        Favorites.sort((a, b) =>
            sortBy === "name" ? a.name.localeCompare(b.name) : a.id - b.id
        );

        Favorites.forEach(pokemon => {
            const card = document.createElement("div");
            card.className = "pokemon-card";

            card.innerHTML = `
                <div class="pokemon-info">
                    <img src="${pokemon.image}" alt="${pokemon.name}">
                    <h2>${pokemon.name}</h2>
                    <p><strong>ID:</strong> ${pokemon.id}</p>
                    <p><strong>Type(s):</strong> ${pokemon.types.join(", ")}</p>
                    <p><strong>Abilities:</strong> ${pokemon.abilities.join(", ")}</p>
                </div>
                <button class="remove-btn" data-id="${pokemon.id}">❤️ Remove</button>
            `;

            card.querySelector(".pokemon-info").addEventListener("click", () => {
                window.location.href = `/pokemon/${pokemon.id}`;
            });

            container.appendChild(card);
        });
    }

    // ❌ Remove Pokémon from favorites
    container.addEventListener("click", async (e) => {
        if (e.target.classList.contains("remove-btn")) {
            const pokemonId = e.target.dataset.id;
            try {
                const res = await fetch(`/users/${userId}/favorites/${pokemonId}`, {
                    method: "DELETE"
                });
                if (!res.ok) throw new Error();
                Favorites = Favorites.filter(p => p.id != pokemonId);
                renderFavorites();
            } catch {
                alert("Failed to remove favorite.");
            }
        }
    });

    // 🔁 Sort favorites when dropdown changes
    sortDropdown.addEventListener("change", renderFavorites);

    // ⬇️ Download favorites as CSV
    downloadBtn.addEventListener("click", () => {
        window.location.href = `/users/${userId}/favorites/download`;
    });

    // 🚀 Load favorites on page load
    loadFavorites();
});


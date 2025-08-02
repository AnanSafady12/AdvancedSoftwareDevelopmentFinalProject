/**
 * 📄 popular_pokemons.js — Displays and Manages the Popular Pokémons Page
 *
 * Features:
 * - 🔐 Checks session on page load and prevents unauthorized access
 * - 🚪 Handles user logout and back-navigation protection
 * - 🌟 Loads and displays a list of popular Pokémon from `/api/popular-pokemons`
 * - ❤️ Loads user favorites and highlights them with a heart icon
 * - 🖱️ Clicking a Pokémon card navigates to `/pokemon/:id` (excluding favorite button)
 * - 🔄 Allows adding/removing favorites via heart button (max 10)
 * - 🔁 Automatically refreshes heart icons when returning via browser back button
 *
 * Expected DOM elements:
 * - `#signOutBtn` — Sign out button
 * - `#popularContainer` — Container for Pokémon cards
 *
 * Backend endpoints used:
 * - `GET /api/session` — Verifies session and returns user info
 * - `POST /api/logout` — Logs out the user
 * - `GET /api/popular-pokemons` — Returns popular Pokémon array
 * - `GET /users/:userId/favorites` — Returns user's favorites list
 * - `POST /users/:userId/favorites` — Adds Pokémon to favorites
 * - `DELETE /users/:userId/favorites/:pokemonId` — Removes Pokémon from favorites
 */



document.addEventListener("DOMContentLoaded", async () => {
    // ✅ Session check
    const session = await checkSession();
    if (!session) return;

    const { userId, firstName } = session;

    // ✅ Sign Out
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

    // ✅ Prevent back-navigation after logout
    window.addEventListener("pageshow", async (event) => {
        if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
            const session = await checkSession();
            if (!session) return;
            const res = await fetch(`/users/${session.userId}/favorites`);
            const favorites = await res.json();
            updateHearts(favorites);
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

    // ✅ Fetch popular Pokémon list
    const response = await fetch("/api/popular-pokemons");
    const popularPokemons = await response.json();

    // ✅ Fetch user favorites
    const favRes = await fetch(`/users/${userId}/favorites`);
    const favorites = await favRes.json();
    const favoriteIds = favorites.map(p => p.id);

    // ✅ Render Pokémon cards
    const container = document.getElementById("popularContainer");
    container.innerHTML = "";

    popularPokemons.forEach(pokemon => {
        const isFav = favoriteIds.includes(pokemon.id);
        const heartIcon = isFav ? "❤️" : "♡";

        const card = document.createElement("div");
        card.className = "pokemon-card";

        card.innerHTML = `
            <img src="${pokemon.image}" alt="${pokemon.name}" />
            <h5>${pokemon.name}</h5>
            <p><strong>ID:</strong> ${pokemon.id}</p>
            <p><strong>Types:</strong> ${pokemon.types.join(", ")}</p>
            <p><strong>Abilities:</strong> ${pokemon.abilities.join(", ")}</p>
            <button class="fav-btn" data-id="${pokemon.id}">${heartIcon} Favorite</button>
        `;

        // ✅ Add click listener for entire card (excluding heart button)
        card.addEventListener("click", (e) => {
            if (!e.target.classList.contains("fav-btn")) {
                window.location.href = `/pokemon/${pokemon.id}`;
            }
        });

        container.appendChild(card);
    });

    // ✅ Add favorite toggle logic
    document.querySelectorAll(".fav-btn").forEach(button => {
        button.addEventListener("click", async () => {
            const id = parseInt(button.dataset.id);
            const isFav = button.textContent.includes("❤️");
            const pokemon = popularPokemons.find(p => p.id === id);

            if (isFav) {
                // Remove from favorites
                await fetch(`/users/${userId}/favorites/${id}`, { method: "DELETE" });
                button.innerHTML = "♡ Favorite";
            } else {
                // Add to favorites with full Pokémon object
                const res = await fetch(`/users/${userId}/favorites`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(pokemon)
                });

                const data = await res.json();
                if (data.success) {
                    button.innerHTML = "❤️ Favorite";
                } else if (data.error === "limit") {
                    alert("⚠️ You can only have 10 favorites.");
                }
            }
        });
    });

    // 🔧 Heart refresh function (used for back nav)
    function updateHearts(favorites) {
        const favIds = favorites.map(p => p.id);
        document.querySelectorAll(".fav-btn").forEach(button => {
            const id = parseInt(button.dataset.id);
            button.innerHTML = favIds.includes(id) ? "❤️ Favorite" : "♡ Favorite";
        });
    }
});

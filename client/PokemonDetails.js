/**
 * 📄 pokemon-details.js — Displays Pokémon Detail Page
 *
 * Features:
 * - Extracts Pokémon ID from URL (e.g., /pokemon/25)
 * - Fetches Pokémon data from server-side `/api/pokemon/:id`
 * - Dynamically updates the DOM with:
 *   - Name (uppercase)
 *   - Image and alt text
 *   - Types (comma-separated)
 *   - Abilities (comma-separated)
 *   - Base stats (as a list)
 * - Handles fetch failures with user-friendly error message
 *
 * Expected DOM elements:
 * - #pokemon-name (heading for name)
 * - #pokemon-image (image tag for sprite)
 * - #pokemon-types (span or div for types)
 * - #pokemon-abilities (span or div for abilities)
 * - #pokemon-stats (ul or div for stats list)
 * - .pokemon-details-container (for error fallback)
 */




document.addEventListener("DOMContentLoaded", async () => {
    // 🆔 Extract Pokémon ID from the current URL (e.g., /pokemon/25)
    const id = window.location.pathname.split("/").pop();
    console.log("🟡 Fetching Pokémon ID:", id);

    try {
        // 🌐 Fetch Pokémon data from backend route
        const res = await fetch(`/api/pokemon/${id}`);
        if (!res.ok) throw new Error("Failed to fetch Pokémon");

        // 📦 Parse the JSON response
        const data = await res.json();
        console.log("🟢 Pokémon data:", data);

        // 🏷️ Display the Pokémon name (in uppercase for style)
        document.getElementById("pokemon-name").textContent = data.name.toUpperCase();

        // 🖼️ Set the Pokémon image
        const img = document.getElementById("pokemon-image");
        img.src = data.image;
        img.alt = data.name;

        // 🔠 Set the Pokémon types (comma-separated)
        document.getElementById("pokemon-types").textContent =
            data.types?.join(", ") || "N/A";

        // 💡 Set the Pokémon abilities (comma-separated)
        document.getElementById("pokemon-abilities").textContent =
            data.abilities?.join(", ") || "N/A";

        // 📊 Populate the Pokémon stats
        const statsList = document.getElementById("pokemon-stats");
        statsList.innerHTML = ""; // Clear previous content

        Object.entries(data.stats).forEach(([statName, statValue]) => {
            const li = document.createElement("li");
            li.textContent = `${statName.toUpperCase()}: ${statValue}`;
            statsList.appendChild(li);
        });

    } catch (err) {
        // ❌ Handle fetch or rendering errors
        console.error("🔴 Error loading Pokémon:", err);
        document.querySelector(".pokemon-details-container").innerHTML = `
            <h2>Error</h2>
            <p>Could not load Pokémon details. Please try again later.</p>
        `;
    }
});

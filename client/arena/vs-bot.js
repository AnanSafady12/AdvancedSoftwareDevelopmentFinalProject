/**
 * vs-bot.js
 * Handles the battle arena logic for "VS Bot" mode in the Pokémon app.
 * - Checks session and handles sign out
 * - Loads user's favorite Pokémon and a random bot opponent
 * - Lets user pick a Pokémon to fight
 * - Sends battle request to backend and displays result
 * - Includes popup if user exceeds daily fight limit
 */

document.addEventListener("DOMContentLoaded", async () => {
    // ✅ Session check
    const session = await checkSession();
    if (!session) return;

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

    // 🎮 VS Bot Battle Logic
    const botCard = document.getElementById("botCard");
    const botStats = document.getElementById("botStats");
    const favoritesContainer = document.getElementById("favoritesContainer");
    const playerCard = document.getElementById("playerCard");
    const playerStats = document.getElementById("playerStats");
    const fightButton = document.getElementById("fightButton");
    const resultContainer = document.getElementById("resultContainer");

    let selectedPokemon = null;
    let opponentPokemon = null;
    let isFirstSelection = true;

    const popup = document.getElementById("popup");
    const popupMessage = document.getElementById("popup-message");
    const popupClose = document.getElementById("popup-close");
    popupClose.addEventListener("click", () => popup.classList.add("hidden"));

    // 🔄 Load Random Bot Pokémon
    async function loadBotPokemon() {
        try {
            const res = await fetch("/api/pokemon/random");
            if (!res.ok) throw new Error("Bot not found");

            opponentPokemon = await res.json();
            renderCard(botCard, opponentPokemon);
            renderStats(botStats, opponentPokemon.stats);
        } catch (err) {
            console.error("Failed to load bot:", err);
            botCard.textContent = "⚠️ Failed to load bot";
        }
    }

    // 🧠 Load User Favorites
    async function loadFavorites() {
        try {
            const { userId } = session;
            const res = await fetch(`/users/${userId}/favorites`);
            const favorites = await res.json();

            favoritesContainer.innerHTML = "";
            for (const p of favorites) {
                const card = document.createElement("div");
                card.className = "pokemon-card";
                card.innerHTML = `
                    <img src="${p.image}" alt="${p.name}" />
                    <p><strong>${p.name}</strong></p>
                `;
                card.onclick = async () => {
                    selectedPokemon = await getPokemonById(p.id);
                    renderCard(playerCard, selectedPokemon);
                    renderStats(playerStats, selectedPokemon.stats);
                    resultContainer.textContent = "";
                    if (!isFirstSelection) await loadBotPokemon();
                    isFirstSelection = false;
                };
                favoritesContainer.appendChild(card);
            }
        } catch (err) {
            console.error("Failed to load favorites:", err);
            favoritesContainer.textContent = "⚠️ Failed to load favorites";
        }
    }

    // 📦 Fetch Full Pokémon Info by ID
    async function getPokemonById(id) {
        const res = await fetch(`/api/pokemon/${id}`);
        if (!res.ok) throw new Error("Failed to fetch Pokémon details");
        return await res.json();
    }

    // 🎴 Render Pokémon Card
    function renderCard(container, pokemon) {
        container.innerHTML = `
            <img src="${pokemon.image}" alt="${pokemon.name}" />
            <p><strong>${pokemon.name}</strong></p>
        `;
    }

    // 📊 Render Stats Block
    function renderStats(container, stats) {
        container.innerHTML = `
            <p>HP: ${stats.hp}</p>
            <p>Attack: ${stats.attack}</p>
            <p>Defense: ${stats.defense}</p>
            <p>Speed: ${stats.speed}</p>
        `;
    }

    // ⚔️ Fight Button Handler
    fightButton.addEventListener("click", async () => {
        if (!selectedPokemon || !opponentPokemon) {
            resultContainer.textContent = selectedPokemon
                ? "❗ Bot Pokémon not loaded."
                : "❗ Please select your Pokémon first.";
            return;
        }

        try {
            const res = await fetch("/api/battle/vs", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    playerPokemon: selectedPokemon,
                    opponentPokemon: opponentPokemon,
                    opponentType: "bot"
                })
            });

            const data = await res.json();

            if (!res.ok) {
                if (data.error === "Daily fight limit reached (5/day)") {
                    popupMessage.textContent = "⚠️ You’ve reached your daily limit of 5 fights. Try again tomorrow!";
                    popup.classList.remove("hidden");
                } else {
                    resultContainer.textContent = "❌ " + (data.error || "Battle failed.");
                }
                return;
            }

            // ⏳ Countdown Sequence
            resultContainer.textContent = "3...";
            await new Promise(r => setTimeout(r, 1000));
            resultContainer.textContent = "2...";
            await new Promise(r => setTimeout(r, 1000));
            resultContainer.textContent = "1...";
            await new Promise(r => setTimeout(r, 1000));
            resultContainer.textContent = `Result: You ${data.result.toUpperCase()}!`;

        } catch (err) {
            console.error("Battle failed:", err);
            resultContainer.textContent = "❌ Battle error.";
        }
    });

    // 🚀 Initial Load
    loadBotPokemon();
    loadFavorites();
});

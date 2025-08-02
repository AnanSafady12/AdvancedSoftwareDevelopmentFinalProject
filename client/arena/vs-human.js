/**
 * 🧠 VS Human Battle Script
 * This script handles:
 * - Checking user session
 * - Loading online users
 * - Selecting an opponent
 * - Displaying a battle arena with two random favorite Pokémon
 * - Sending battle request to server
 * - Displaying result with typewriter animation
 */

document.addEventListener("DOMContentLoaded", async () => {
    console.log("✅ DOM fully loaded");

    const session = await checkSession();
    if (!session) return;

    const currentUserId = session.userId;

    let currentUserPokemon = null;
    let otherUserPokemon = null;

    // 🔔 Popup setup
    const popup = document.getElementById("popup");
    const popupMessage = document.getElementById("popup-message");
    const popupOk = document.getElementById("popup-ok");
    popupOk.addEventListener("click", () => popup.classList.add("hidden"));

    const resultContainer = document.getElementById("resultContainer");

    // 🚪 Sign out logic
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

    // 🔁 Handles back/forward navigation session check
    window.addEventListener("pageshow", async (event) => {
        if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
            const session = await checkSession();
            if (!session) return;
        }
    });

    // 🛡️ Verify session
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

    // ⌨️ Typewriter effect
    function typeText(element, html) {
        element.innerHTML = "";
        let i = 0;
        const temp = document.createElement("div");
        temp.innerHTML = html;
        const text = temp.textContent;
        const span = document.createElement("div");
        element.appendChild(span);

        function type() {
            if (i < text.length) {
                span.textContent += text.charAt(i++);
                setTimeout(type, 20);
            }
        }

        type();
    }

    // 🎲 Get random element from array
    function getRandom(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    }

    // 🧱 Stat block creator
    function createStatBlock(label, value) {
        const stat = document.createElement("p");
        stat.className = "stat";
        stat.innerHTML = `<strong>${label}:</strong> ${value}`;
        return stat;
    }

    // 🌐 Load online users from server
    async function loadOnlineUsers() {
        try {
            const res = await fetch("/api/online-users");
            if (!res.ok) throw new Error();
            const data = await res.json();

            const container = document.getElementById("onlineUsersContainer");
            container.innerHTML = "";

            if (!Array.isArray(data.online) || data.online.length === 0) {
                container.innerHTML = "<p class='text-white'>No other users are online.</p>";
                return;
            }

            window.onlineUsersMap = {};

            for (const user of data.online) {
                const card = document.createElement("div");
                card.className = "user-card";
                card.style.cursor = "pointer";

                const avatar = document.createElement("img");
                avatar.src = user.avatar;
                avatar.alt = `${user.firstName}'s avatar`;
                avatar.className = "pokemon-image";

                const name = document.createElement("p");
                name.className = "pokemon-name";
                name.textContent = user.firstName;

                card.appendChild(avatar);
                card.appendChild(name);
                container.appendChild(card);

                window.onlineUsersMap[user.firstName] = user;

                card.addEventListener("click", async () => {
                    console.log(`You clicked on ${user.firstName}`);
                    const opponentId = user.id;
                    await displayTwoPokemons(currentUserId, opponentId);
                });
            }

        } catch (err) {
            console.error("Failed to load online users:", err);
            document.getElementById("onlineUsersContainer").innerHTML =
                "<p class='text-danger'>Error loading online users.</p>";
        }
    }

    // 🎴 Load two random favorite Pokémon and display cards
    async function displayTwoPokemons(currentId, opponentId) {
        try {
            const [currentRes, opponentRes] = await Promise.all([
                fetch(`/users/${currentId}/favorites?enrich=true`),
                fetch(`/users/${opponentId}/favorites?enrich=true`)
            ]);

            if (!currentRes.ok || !opponentRes.ok)
                throw new Error("Failed to fetch favorites");

            const currentUserfavList = await currentRes.json();
            const otherUserfavList = await opponentRes.json();

            if (!currentUserfavList.length || !otherUserfavList.length) {
                alert("❗ One of the users has no favorite Pokémon.");
                return;
            }

            currentUserPokemon = getRandom(currentUserfavList);
            otherUserPokemon = getRandom(otherUserfavList);

            displayPokemons(currentUserPokemon, otherUserPokemon);
        } catch (err) {
            console.error("Error displaying pokémons:", err);
            alert("⚠️ Could not load and display pokémon.");
        }
    }

    // 🎨 Render both Pokémon cards in battle arena
    function displayPokemons(player, opponent) {
        const battleContainer = document.getElementById("battleContainer");
        const playerCard = document.getElementById("playerCard");
        const opponentCard = document.getElementById("opponentCard");
        const resultContainer = document.getElementById("resultContainer");

        playerCard.innerHTML = "";
        opponentCard.innerHTML = "";
        resultContainer.innerHTML = "";

        const buildCard = (pokemon) => {
            const img = document.createElement("img");
            img.src = pokemon.image;
            img.alt = pokemon.name;
            img.className = "pokemon-image";

            const name = document.createElement("p");
            name.textContent = pokemon.name;
            name.className = "pokemon-name";

            const stats = document.createElement("div");
            stats.className = "stats";
            stats.appendChild(createStatBlock("HP", pokemon.stats.hp));
            stats.appendChild(createStatBlock("Attack", pokemon.stats.attack));
            stats.appendChild(createStatBlock("Defense", pokemon.stats.defense));
            stats.appendChild(createStatBlock("Speed", pokemon.stats.speed));

            return [img, name, stats];
        };

        const playerElements = buildCard(player);
        const opponentElements = buildCard(opponent);

        playerCard.append(...playerElements);
        opponentCard.append(...opponentElements);

        battleContainer.style.display = "flex";
    }

    // 🥊 Fight button logic – send battle to server
    document.getElementById("fightButton").addEventListener("click", async () => {
        if (!currentUserPokemon || !otherUserPokemon) {
            alert("❗ Please select an opponent first.");
            return;
        }

        try {
            const res = await fetch("/api/battle/vs", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    playerPokemon: currentUserPokemon,
                    opponentPokemon: otherUserPokemon,
                    opponentType: "human"
                })
            });

            const data = await res.json();

            if (!res.ok) {
                if (data.error === "Daily fight limit reached (5/day)") {
                    popupMessage.textContent = "⚠️ You’ve reached your daily limit of 5 fights. Try again tomorrow!";
                    popup.classList.remove("hidden");
                    return;
                } else {
                    resultContainer.textContent = "❌ " + (data.error || "Battle failed.");
                    return;
                }
            }

            // ✅ Success - show results
            const resultText = `
            <div>Result: <strong>You ${data.result.toUpperCase()}!</strong></div>
            <div>Your Score: ${data.playerScore.toFixed(2)} | Opponent Score: ${data.opponentScore.toFixed(2)}</div>
            `;
            typeText(resultContainer, resultText);

        } catch (err) {
            console.error("VS Human battle failed:", err);
            alert("❌ Battle error. Try again.");
        }
    });

    // 🔃 Load online users initially + auto-refresh every 10s
    await loadOnlineUsers();
    setInterval(loadOnlineUsers, 10000);
});

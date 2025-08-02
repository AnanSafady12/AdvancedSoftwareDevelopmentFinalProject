/**
 * 🏠 HomePage.js — Main Script for Pokémon Home Page
 *
 * Features:
 * - Session validation and redirection
 * - Real-time avatar loading from backend
 * - User greeting and logout functionality
 * - Search Pokémon by name/type/ability (live search)
 * - Toggle favorites (add/remove with server-side limit)
 * - Navigate to Pokémon detail page
 * - Restore heart icons on back navigation
 * - Periodically update list of online users with avatars
 *
 * Elements expected in DOM:
 * - #txtSearch (search box)
 * - #PokémonfoundList (container for results)
 * - #loader (loading indicator)
 * - #signOutBtn (logout button)
 * - #currentUsername (username span)
 * - #currentUserAvatar (avatar <img>)
 * - #onlineUsersList (for online dropdown list)
 */



// Wait for the DOM to be fully loaded
document.addEventListener("DOMContentLoaded", async () => {
    console.log("✅ HomePage.js loaded"); // Log for debugging

    // 🔐 Check if session is valid (redirects to / if not)
    const session = await checkSession(); // Call session check
    if (!session) return; // If no session, exit script
    const { userId, firstName } = session; // Destructure session info

    // 🎭 Get the avatar <img> element from the DOM
    const avatarImg = document.getElementById("currentUserAvatar");

    // 🎨 Fetch avatar URL from backend (not generated on frontend anymore)
    try {
        const avatarRes = await fetch("/api/avatar"); // Request avatar from backend
        if (!avatarRes.ok) throw new Error("Failed to load avatar"); // Handle error
        const { avatarUrl } = await avatarRes.json(); // Extract avatar URL from response
        avatarImg.src = avatarUrl; // Set avatar image source
        avatarImg.alt = "Avatar"; // Set alt text
    } catch (err) {
        console.error("Failed to load avatar:", err); // Log error if failed
        avatarImg.alt = "Avatar"; // Set fallback alt text
    }

    // 🙋‍♂️ Display username in the DOM
    document.getElementById("currentUsername").textContent = firstName;

    // 🚪 Set up Sign Out button listener
    document.getElementById("signOutBtn")?.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/logout", { method: "POST" }); // Send logout request
            if (res.ok) window.location.replace("/"); // Redirect if successful
            else alert("Logout failed"); // Show error alert
        } catch (err) {
            console.error("Logout error:", err); // Log error
            alert("Logout error. Try again."); // Show fallback alert
        }
    });

    // 🔁 Restore hearts after back navigation
    window.addEventListener("pageshow", async (event) => {
        if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
            const session = await checkSession(); // Re-check session
            if (!session) return; // Exit if no session
            const res = await fetch(`/users/${session.userId}/favorites`); // Get favorites again
            const favorites = await res.json(); // Parse favorites list
            updateHearts(favorites); // Restore favorited hearts
        }
    });

    // 🛡️ Function to validate session
    async function checkSession() {
        try {
            const res = await fetch("/api/session"); // Ask backend for session info
            if (!res.ok) throw new Error(); // Handle failure
            return await res.json(); // Return session object
        } catch {
            window.location.replace("/"); // Redirect if invalid
            return null; // Return null
        }
    }

    // 🔍 Set up Pokémon search input listener
    const pokemonListContainer = document.getElementById("PokémonfoundList"); // Container for results
    const searchBox = document.getElementById("txtSearch"); // Input field
    const loader = document.getElementById("loader"); // Loader element

    searchBox.addEventListener("input", async () => {
        const query = searchBox.value.trim(); // Get search input
        if (!query) return (pokemonListContainer.innerHTML = ""); // Clear if empty
        loader.style.display = "block"; // Show loader

        try {
            const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`); // Send search request
            const data = await res.json(); // Parse JSON response
            if (!res.ok || !data || data.length === 0) {
                pokemonListContainer.innerHTML = `<p>No Pokémon found for "${query}".</p>`; // Show no results
                return;
            }
            renderPokemons(Array.isArray(data) ? data : [data]); // Render results
        } catch {
            pokemonListContainer.innerHTML = `<p>Error while searching Pokémon.</p>`; // Handle error
        } finally {
            loader.style.display = "none"; // Hide loader
        }
    });

    // ❤️ Handle clicking the favorite button
    pokemonListContainer.addEventListener("click", async (e) => {
        const heartBtn = e.target.closest(".favorite-btn"); // Get clicked heart button
        if (!heartBtn) return; // Ignore if clicked elsewhere

        const card = heartBtn.closest(".pokemon-card"); // Get parent card
        const pokemonId = card.dataset.id; // Extract Pokémon ID
        const heartIcon = heartBtn.querySelector(".heart-icon"); // Get icon element
        const isFav = heartIcon.classList.contains("favorited"); // Check if already favorited

        try {
            if (isFav) {
                const res = await fetch(`/users/${userId}/favorites/${pokemonId}`, { method: "DELETE" }); // Remove favorite
                if (!res.ok) throw new Error();
                heartIcon.classList.remove("favorited"); // Update icon class
                heartIcon.textContent = "♡"; // Change to empty heart
            } else {
                // Collect Pokémon info from card
                const pokemon = {
                    id: parseInt(pokemonId),
                    name: card.querySelector("h2").textContent,
                    image: card.querySelector("img").src,
                    types: card.querySelector("p:nth-of-type(2)").textContent.replace("Types:", "").trim().split(", "),
                    abilities: card.querySelector("p:nth-of-type(3)").textContent.replace("Abilities:", "").trim().split(", ")
                };

                const res = await fetch(`/users/${userId}/favorites`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(pokemon) // Send to backend
                });

                const result = await res.json(); // Parse response
                if (!res.ok || !result.success) {
                    alert(result.error === "Limit reached" ? "⚠️ Max 10 favorites." :
                        result.error === "Already in favorites" ? "⚠️ Already in favorites." :
                            "⚠️ Could not add to favorites.");
                    return;
                }

                heartIcon.classList.add("favorited"); // Update class
                heartIcon.textContent = "❤️"; // Change to full heart
            }
        } catch (err) {
            console.error("Failed to toggle favorite:", err); // Log error
            alert("Could not update favorite. Please try again."); // Alert user
        }
    });

    // 🧱 Render Pokémon cards to the DOM
    function renderPokemons(pokemons) {
        pokemonListContainer.innerHTML = pokemons.map(p => `
            <div class="pokemon-card" data-id="${p.id}">
                <div class="pokemon-info">
                    <img src="${p.image}" alt="${p.name}">
                    <h2>${p.name}</h2>
                    <p><strong>ID:</strong> ${p.id}</p>
                    <p><strong>Types:</strong> ${p.types?.join(", ") || "Unknown"}</p>
                    <p><strong>Abilities:</strong> ${p.abilities?.join(", ") || "Unknown"}</p>
                </div>
                <button class="favorite-btn">
                    <span class="heart-icon ${p.isFavorite ? "favorited" : ""}">
                        ${p.isFavorite ? "❤️" : "♡"}
                    </span> Favorite
                </button>
            </div>
        `).join(""); // Join HTML blocks and insert

        // Enable click to view Pokémon details
        document.querySelectorAll(".pokemon-info").forEach(card => {
            card.style.cursor = "pointer";
            card.addEventListener("click", () => {
                const id = card.closest(".pokemon-card").dataset.id;
                window.location.href = `/pokemon/${id}`; // Redirect to detail page
            });
        });
    }

    // 💖 Update heart icons based on current favorites
    function updateHearts(favorites) {
        const favoriteIds = favorites.map(p => p.id); // Extract IDs
        document.querySelectorAll(".pokemon-card").forEach(card => {
            const id = Number(card.dataset.id); // Get card ID
            const heart = card.querySelector(".heart-icon"); // Find heart icon
            if (!heart) return;
            heart.classList.toggle("favorited", favoriteIds.includes(id)); // Update class
            heart.textContent = favoriteIds.includes(id) ? "❤️" : "♡"; // Set icon
        });
    }

    // 👥 Load and display online users in dropdown
    async function fetchOnlineUsers() {
        try {
            const res = await fetch("/api/online-users"); // Get online users
            const data = await res.json(); // Parse response
            const list = document.getElementById("onlineUsersList"); // Find dropdown list
            list.innerHTML = ""; // Clear it

            if (!data.online || data.online.length === 0) {
                list.innerHTML = '<li class="dropdown-item text-muted">No users online</li>'; // Empty message
                return;
            }

            // Add each online user to list
            data.online.forEach(user => {
                const avatarUrl = `https://api.dicebear.com/9.x/bottts/png?seed=${user.firstName}`; // Generate avatar
                const li = document.createElement("li"); // Create <li>
                li.className = "dropdown-item d-flex align-items-center gap-2"; // Add Bootstrap classes
                li.innerHTML = `
                    <span class="online-dot"></span>
                    <img src="${avatarUrl}" class="avatar-img-small rounded-circle" alt="Avatar" />
                    <span>${user.firstName}</span>
                `;
                list.appendChild(li); // Append to DOM
            });
        } catch (err) {
            console.error("Failed to fetch online users:", err); // Log error
        }
    }

    // 🔁 Periodically update online user list every 10 seconds
    fetchOnlineUsers(); // Initial load
    setInterval(fetchOnlineUsers, 10000); // Re-fetch every 10 sec
});

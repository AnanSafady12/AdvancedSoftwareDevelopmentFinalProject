import express from 'express';
import fs from 'fs-extra';
import axios from 'axios';
import path from 'path';
import bcrypt from 'bcrypt';
import { Parser } from 'json2csv';
import session from 'express-session';
import { fileURLToPath } from 'url';

// ✅ Correct Firebase Admin Import — Single Line
import { db, authAdmin, admin } from './firebaseAdmin.js';
let popularCache = {
    data: [],
    timestamp: 0
};







// ✅ Predefined list of popular Pokémon IDs (used for Popular Pokémons page)
const POPULAR_IDS = [1, 6, 7, 9, 12, 25, 59, 94, 132, 133, 134, 143, 149, 150, 151, 493];



const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(express.static(path.join(__dirname, '../client')));

// ✅ Session Middleware
app.use(session({
    secret: 'your_secret_key',  // Replace with a secure key in production
    resave: false,
    saveUninitialized: true,
}));

// 🔒 Session-based Route Protection Middleware
function requireLogin(req, res, next) {
    if (req.session && req.session.userId) {
        next(); // ✅ User is logged in — allow access
    } else {
        res.redirect('/login'); // ❌ Not logged in — redirect to login
    }
}


// Example Route — Home Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../client', 'Introduction.html'));
});

// ✅ Register page (public)
app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "../client", "RegisterPage.html"));
});

// ✅ Login page (public)
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "../client", "LogInPage.html"));
});

// ✅ Home page – protected
app.get("/home", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client", "HomePage.html"));
});

// ✅ Favorites page – protected
app.get("/favorites", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client", "Favorites.html"));
});

// ✅ Popular Pokémons page – protected
app.get("/popular_pokemons", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client", "popular_pokemons.html"));
});

// ✅ Individual Pokémon details – protected
app.get("/pokemon/:id", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client", "PokemonDetails.html"));
});

// ✅ Arena: VS Bot – protected
app.get("/arena/vs-bot", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client/arena", "vs-bot.html"));
});

// ✅ Arena: VS Human – protected
app.get("/arena/vs-human", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client/arena", "vs-human.html"));
});

// ✅ Arena: Leaderboard – protected
app.get("/arena/leaderboard", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client/arena", "LeaderBoard.html"));
});

// ✅ Arena: Fights History – protected
app.get("/arena/fight_history", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "../client/arena", "FightsHistory.html"));
});



/**
 * @route   GET /api/projectinfo
 * @access  Public
 * @desc    Fetches the project description and student information.
 * 
 * ✅ This endpoint reads the JSON file `Data/project_info.json`.
 * ✅ It's typically used to populate dynamic content in the Introduction.html page.
 * 
 * 📥 Request: No parameters or body required.
 * 📤 Response Example:
 * {
 *   description: "This is a Pokémon web app project...",
 *   students: [
 *     { name: "Anan Safady", id: "123" },
 *     { name: "Anan Farhat", id: "456" }
 *   ]
 * }
 */

app.get("/api/projectinfo", async (req, res) => {
    try {
        // 📁 Read and parse project_info.json file from Data folder
        const data = await fs.readJson(path.join(__dirname, "../MyData/project_info.json"));

        // ✅ Send the JSON content to the client
        res.json(data);
    } catch (err) {
        // ❌ If the file doesn't exist or reading fails, return error
        console.error("Error loading project info:", err);
        res.status(500).json({ error: "Could not load project info" });
    }
});





/**
 * @route   GET /api/pokemon/random
 * @access  Protected (requires login)
 * @desc    Returns a random Pokémon (ID 1–150) with its basic battle stats.
 * 
 * ✅ This endpoint is used when the bot (AI opponent) needs a random Pokémon for battle.
 * ✅ It fetches data from the external PokéAPI.
 * ✅ The returned data includes: id, name, image, and stats (HP, Attack, Defense, Speed).
 * 
 * 📥 Request: No request body needed.
 * 📤 Response Example:
 * {
 *   "id": 25,
 *   "name": "pikachu",
 *   "image": "https://...",
 *   "stats": {
 *     "hp": 35,
 *     "attack": 55,
 *     "defense": 40,
 *     "speed": 90
 *   }
 * }
 */

app.get("/api/pokemon/random", requireLogin, async (req, res) => {
    try {
        const id = Math.floor(Math.random() * 150) + 1;

        const r = await axios.get(`https://pokeapi.co/api/v2/pokemon/${id}`);
        const p = r.data;

        const getStat = name => p.stats.find(s => s.stat.name === name)?.base_stat || 0;

        res.json({
            id: p.id,
            name: p.name,
            image: p.sprites.front_default,
            stats: {
                hp: getStat("hp"),
                attack: getStat("attack"),
                defense: getStat("defense"),
                speed: getStat("speed")
            }
        });

    } catch (err) {
        console.error("Failed to load random Pokémon:", err.message);
        res.status(404).json({ message: "Bot not found" });
    }
});


/**
 * @route   GET /api/avatar
 * @access  Private (requires user to be logged in)
 * @desc    Returns the current user's avatar URL based on their first name.
 *
 * 🧠 Avatar is generated using DiceBear's "bottts" style with PNG format.
 *
 * 📤 Success Response:
 * { "avatarUrl": "https://api.dicebear.com/9.x/bottts/png?seed=Anan" }
 *
 * ❌ Error Responses:
 * - { message: "Unauthorized" } – if no user session
 * - { message: "User not found" } – if user document not found in Firestore
 * - { message: "Failed to load avatar" } – on server failure
 */

app.get("/api/avatar", async (req, res) => {
    try {
        const userId = req.session.userId;

        // ❌ Reject if user is not logged in
        if (!userId) return res.status(401).json({ message: "Unauthorized" });

        // 🔍 Fetch user document from Firestore
        const userDoc = await db.collection('users').doc(userId).get();

        // ❌ If no user document exists
        if (!userDoc.exists) return res.status(404).json({ message: "User not found" });

        const user = userDoc.data();

        // 🎨 Generate DiceBear avatar URL using user's firstName
        const avatarUrl = `https://api.dicebear.com/9.x/bottts/png?seed=${encodeURIComponent(user.firstName)}`;

        // ✅ Return avatar URL
        res.json({ avatarUrl });

    } catch (err) {
        console.error("Error generating avatar:", err);
        res.status(500).json({ message: "Failed to load avatar" });
    }
});


/**
 * @route   POST /register
 * @access  Public
 * @desc    Registers a new user with Firebase Authentication and stores additional user data in Firestore.
 * 
 * ✅ Validates input fields: firstName, email, password.
 * ✅ Checks for duplicate email in Firebase Auth.
 * ✅ Checks for duplicate username (firstName) in Firestore users collection.
 * ✅ Creates user in Firebase Authentication.
 * ✅ Saves full user object (favorites, score, history, avatar, etc.) in Firestore.
 * ✅ Starts a session for the newly registered user.
 * 
 * 📥 Request Body Example:
 * {
 *   "firstName": "Anan",
 *   "email": "anan@example.com",
 *   "password": "MySecure123!"
 * }
 * 
 * 📤 Success Response:
 * { "success": true }
 * 
 * ❌ Error Responses:
 * - { success: false, errors: { firstName/email/password: "error message" } }  // Input validation errors
 * - { success: false, message: "Email already in use." }                      // Duplicate email
 * - { success: false, message: "Username already exists." }                   // Duplicate username
 * - { success: false, message: "Server error occurred." }                     // Other server-side error
 */

app.post("/register", async (req, res) => {
    const { firstName, email, password } = req.body;
    const errors = {};

    // ✅ Validate first name: only letters & spaces, max 50 chars
    if (!firstName || firstName.length > 50 || /[^a-zA-Z ]/.test(firstName))
        errors.firstName = "Only letters, max 50 chars";

    // ✅ Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email))
        errors.email = "Invalid email";

    // ✅ Validate password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z]).{7,15}$/;
    if (!password || !passwordRegex.test(password))
        errors.password = "Password must be 7-15 chars, include upper/lower/special";

    // ❌ If any validation errors, return them immediately
    if (Object.keys(errors).length)
        return res.json({ success: false, errors });

    try {
        // ❌ Check if email already exists in Firebase Auth
        const existingUsers = await authAdmin.getUserByEmail(email).catch(() => null);
        if (existingUsers)
            return res.json({ success: false, message: "Email already in use." });

        // ❌ Check if username exists (Firestore users collection)
        const nameSnapshot = await db.collection('users')
            .where('firstName', '==', firstName)
            .get();

        if (!nameSnapshot.empty)
            return res.json({ success: false, message: "Username already exists." });

        // ✅ Create user in Firebase Auth
        const userRecord = await authAdmin.createUser({
            email,
            password,
            displayName: firstName
        });

        console.log(`✅ User created in Firebase Auth: ${userRecord.uid}`);

        // ✅ Hash password (optional, if you want to store it hashed)
        const hashedPassword = await bcrypt.hash(password, 10);

        // ✅ Create user object for Firestore
        const newUser = {
            id: userRecord.uid,
            firstName,
            email,
            password: hashedPassword, // storing hashed password if you need (optional)
            avatar: `https://api.dicebear.com/9.x/bottts/png?seed=${firstName}`,
            favorites: [],
            score: { bot: 0, human: 0, total: 0 },
            history: [],
            createdAt: new Date(),
            isOnline: false
        };

        // ✅ Save user data in Firestore
        await db.collection('users').doc(userRecord.uid).set(newUser);

        // ✅ Create session
        req.session.userId = userRecord.uid;
        req.session.firstName = firstName;

        res.json({ success: true });
    } catch (err) {
        console.error("❌ Registration error:", err);
        res.status(500).json({ success: false, message: "Server error occurred." });
    }
});



/**
 * @route   POST /login
 * @access  Public
 * @desc    Authenticates user with email and password using Firebase Authentication.
 *          On successful login, updates the user's online status in Firestore.
 *
 * 🧾 Request Body:
 * {
 *   "email": "user@example.com",
 *   "password": "UserPassword123!"
 * }
 *
 * ✅ On Success:
 * - Starts a session with user ID and first name
 * - Sets `isOnline: true` in Firestore
 * - Returns: { success: true }
 *
 * ❌ On Failure:
 * - { success: false, message: "Missing email or password." }
 * - { success: false, message: "Invalid email or password." }
 * - { success: false, message: "Server error occurred." }
 */

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // ❌ Validate input
    if (!email || !password)
        return res.json({ success: false, message: "Missing email or password." });

    try {
        // 🔍 Find user in Firebase Authentication by email
        let userRecord;
        try {
            userRecord = await authAdmin.getUserByEmail(email);
        } catch {
            return res.json({ success: false, message: "Invalid email or password." });
        }

        // 🔐 Fetch user document from Firestore
        const userDoc = await db.collection('users').doc(userRecord.uid).get();

        if (!userDoc.exists)
            return res.json({ success: false, message: "Invalid email or password." });

        const user = userDoc.data();

        // ✅ Compare provided password with stored hashed password in Firestore
        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.json({ success: false, message: "Invalid email or password." });

        // ✅ Store user info in session
        req.session.userId = user.id;
        req.session.firstName = user.firstName;

        // ✅ Update Firestore to mark user as online
        await db.collection('users').doc(user.id).update({
            isOnline: true
        });

        // ✅ Success response
        res.json({ success: true });

    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ success: false, message: "Server error occurred." });
    }
});


/**
 * @route   POST /api/logout
 * @access  Private (requires existing session)
 * @desc    Logs out the currently logged-in user by:
 *   - Updating isOnline: false in Firestore
 *   - Destroying their session
 *
 * ✅ On Success:
 * - User is marked offline in Firestore
 * - Session is destroyed
 * - Returns: { success: true }
 *
 * ❌ On Failure:
 * - If session destruction fails, returns: { success: false }
 */

app.post("/api/logout", async (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    try {
        // ✅ Mark user as offline in Firestore
        await db.collection('users').doc(userId).update({
            isOnline: false
        });

        // 🔥 Destroy session
        req.session.destroy(err => {
            if (err) {
                console.error("Session destruction failed:", err);
                return res.status(500).json({ success: false });
            }

            // ✅ Successfully logged out
            res.json({ success: true });
        });

    } catch (err) {
        console.error("Logout error:", err);
        res.status(500).json({ success: false });
    }
});


/**
 * @route   GET /api/online-users
 * @access  Private (requires session)
 * @desc    Returns a list of users who are currently online, EXCLUDING the logged-in user.
 *
 * ✅ Fetches users from Firestore where isOnline: true.
 * ✅ Excludes the currently logged-in user from the returned list.
 *
 * 📤 Response Example:
 * {
 *   "online": [
 *     { "firstName": "Ash", "avatar": "https://...", "id": "user123" },
 *     ...
 *   ]
 * }
 *
 * ❌ Errors:
 * - 401 Unauthorized – if no active session
 * - 404 User not found – if current session user doesn't exist in Firestore
 * - 500 Internal Server Error – on server failure
 */

app.get("/api/online-users", async (req, res) => {
    const currentUserId = req.session.userId;

    // ❌ Reject if no active session
    if (!currentUserId) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        // 🔍 Fetch current user from Firestore
        const currentUserDoc = await db.collection('users').doc(currentUserId).get();

        if (!currentUserDoc.exists) {
            return res.status(404).json({ error: "User not found" });
        }

        const currentUser = currentUserDoc.data();

        // 🌐 Query all users where isOnline == true
        const snapshot = await db.collection('users').where('isOnline', '==', true).get();

        // 🚿 Build list excluding the current user
        const online = [];
        snapshot.forEach(doc => {
            const user = doc.data();
            if (user.id !== currentUserId) {
                online.push({
                    firstName: user.firstName,
                    avatar: user.avatar,
                    id: user.id
                });
            }
        });

        // ✅ Return online users list
        res.json({ online });

    } catch (err) {
        console.error("Error in /api/online-users:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * @route   GET /api/session
 * @access  Private (session required)
 * @desc    Validates current user session and returns basic user data (ID, name, avatar).
 *
 * ✅ Response Example:
 * {
 *   userId: "abc123",
 *   firstName: "Ash",
 *   avatar: "https://api.dicebear.com/..."
 * }
 *
 * ❌ Errors:
 * - 401 Unauthorized – if no active session
 * - 404 User not found – if session user doesn't exist in Firestore
 */

app.get("/api/session", async (req, res) => {
    const userId = req.session.userId;

    // ❌ Reject if no active session
    if (!userId) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        // 🔍 Fetch user from Firestore by session ID
        const userDoc = await db.collection('users').doc(userId).get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: "User not found" });
        }

        const user = userDoc.data();

        // ✅ Return basic session user info
        res.json({
            userId: user.id,
            firstName: user.firstName,
            avatar: user.avatar
        });

    } catch (err) {
        console.error("Session validation error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});


/**
 * @route   GET /api/search?q={query}
 * @access  Private (must be logged in)
 * @desc    Searches for Pokémon by:
 *          1. Direct name or ID
 *          2. Type name (e.g., "fire")
 *          3. Ability name (e.g., "overgrow")
 *
 * ✅ Response:
 *   An array of matching Pokémon objects:
 *   [
 *     {
 *       id: 25,
 *       name: "pikachu",
 *       image: "...",
 *       types: ["electric"],
 *       abilities: ["static", "lightning-rod"],
 *       isFavorite: true/false
 *     },
 *     ...
 *   ]
 *
 * ❌ Errors:
 *   - 401: Unauthorized (if no session)
 *   - 400: Missing search query
 *   - []: No Pokémon matched
 */

app.get("/api/search", async (req, res) => {
    const query = req.query.q?.toLowerCase();
    if (!query) return res.status(400).json({ error: "Missing search query" });

    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ error: "Unauthorized" });

    try {
        // 🔍 Fetch user document from Firestore
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) return res.status(404).json({ error: "User not found" });

        const user = userDoc.data();

        // 🟡 Helper to check if a Pokémon is in user's favorites
        const isFavorite = (id) => user.favorites.some(p => p.id === id);

        // 🔍 1. Direct search by name or ID
        try {
            const r = await axios.get(`https://pokeapi.co/api/v2/pokemon/${query}`);
            const p = r.data;

            return res.json([
                {
                    id: p.id,
                    name: p.name,
                    image: p.sprites.front_default,
                    types: p.types.map(t => t.type.name),
                    abilities: p.abilities.map(a => a.ability.name),
                    isFavorite: isFavorite(p.id)
                }
            ]);
        } catch {
            // ❌ If direct match fails, continue with type/ability search
        }

        // 🔄 2. Search by type or ability
        for (const type of ["type", "ability"]) {
            try {
                const r = await axios.get(`https://pokeapi.co/api/v2/${type}/${query}`);
                const results = r.data.pokemon.slice(0, 20); // ⛔ Limit to 20 results for performance

                // 🔁 Fetch full Pokémon data for each match
                const all = await Promise.all(
                    results.map(p => axios.get(p.pokemon.url).then(r => r.data))
                );

                return res.json(
                    all.map(p => ({
                        id: p.id,
                        name: p.name,
                        image: p.sprites.front_default,
                        types: p.types.map(t => t.type.name),
                        abilities: p.abilities.map(a => a.ability.name),
                        isFavorite: isFavorite(p.id)
                    }))
                );
            } catch {
                // ❌ Try next (type/ability)
            }
        }

        // ❌ No match found
        return res.json([]);

    } catch (err) {
        console.error("Search error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});


/**
 * @route   GET /api/pokemon/:id
 * @access  Private (requires login)
 * @desc    Fetches detailed data for a specific Pokémon by its ID from PokéAPI.
 *
 * ✅ Response Example:
 * {
 *   id: 25,
 *   name: "pikachu",
 *   image: "https://...",
 *   stats: { hp: 35, attack: 55, defense: 40, speed: 90 },
 *   types: ["electric"],
 *   abilities: ["static", "lightning-rod"]
 * }
 *
 * ❌ Errors:
 * - 401 Unauthorized – if user not logged in
 * - 404 Not Found – if Pokémon ID is invalid or fetch fails
 */

app.get("/api/pokemon/:id", requireLogin, async (req, res) => {
    try {
        // 🌐 Fetch Pokémon data from PokéAPI by ID
        const r = await axios.get(`https://pokeapi.co/api/v2/pokemon/${req.params.id}`);
        const p = r.data;

        // 🧮 Helper to get stat value by name
        const getStat = (name) => p.stats.find(s => s.stat.name === name)?.base_stat || 0;

        // ✅ Structured Pokémon data response
        res.json({
            id: p.id,
            name: p.name,
            image: p.sprites.front_default,
            stats: {
                hp: getStat("hp"),
                attack: getStat("attack"),
                defense: getStat("defense"),
                speed: getStat("speed")
            },
            types: p.types.map(t => t.type.name),
            abilities: p.abilities.map(a => a.ability.name)
        });

    } catch (err) {
        console.error("Pokémon details fetch failed:", err.message);
        res.status(404).json({ error: "Pokémon not found" });
    }
});


/**
 * ✅ Function: hasReachedDailyFightLimit(userId)
 * ----------------------------------------------
 * @param {string} userId - The UID of the user in Firestore
 * @returns {Promise<boolean>} - true if limit reached, false otherwise
 */
async function hasReachedDailyFightLimit(userId) {
    try {
        // 🔥 Add this log here to check if db is properly initialized
        console.log("DB Object:", db);

        const userDoc = await db.collection('users').doc(userId).get();

        if (!userDoc.exists) {
            console.error(`User with ID ${userId} not found while checking fight limit.`);
            return false;
        }

        const user = userDoc.data();
        const today = new Date().toISOString().split('T')[0];

        const todayFights = user.history?.filter(fight => fight.date === today) || [];

        return todayFights.length >= 5;

    } catch (err) {
        console.error("Error checking daily fight limit:", err);
        return false;
    }
}



/**
 * @route   POST /api/battle/vs
 * @access  Private (requires login)
 * @desc    Handles a battle request between current user and bot/human opponent.
 *          Enforces daily fight limit, updates score/history in Firestore.
 */

app.post("/api/battle/vs", requireLogin, async (req, res) => {
    try {
        // ✅ Destructure battle data from request
        const { playerPokemon, opponentPokemon, opponentType } = req.body;

        // ❌ Validate input
        if (!playerPokemon || !opponentPokemon || !opponentType) {
            return res.status(400).json({ error: "Missing battle data" });
        }

        const userId = req.session.userId;

        // 🔍 Fetch current user from Firestore
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: "User not found" });
        }

        const user = userDoc.data();

        console.log("userId passed to hasReachedDailyFightLimit:", userId);

        // ⛔ Check if user reached daily fight limit
        if (await hasReachedDailyFightLimit(userId)) {
            return res.status(403).json({ error: "Daily fight limit reached (5/day)" });
        }

        // 🧠 Handle battle logic (calculates result & updates Firestore)
        console.log(`⚔️ Starting battle: ${user.firstName} (${playerPokemon.name}) vs ${opponentPokemon.name} (${opponentType})`);
        const resultData = await handleBattle(userId, playerPokemon, opponentPokemon, opponentType);

        // ✅ Return battle result
        res.json(resultData);

    } catch (err) {
        console.error("Battle error:", err);
        res.status(500).json({ error: "Server error during battle" });
    }
});



/**
 * ✅ Function: handleBattle(playerId, playerPokemon, opponentPokemon, opponentType = "bot")
 * -----------------------------------------------------------------------------------------
 * @desc   Simulates a battle between user’s Pokémon and opponent (bot/human),
 *         updates Firestore with result, score, and history.
 *
 * @param  {string} playerId - UID from Firebase Auth (Firestore doc ID)
 * @param  {object} playerPokemon - Player's Pokémon (id, name, stats)
 * @param  {object} opponentPokemon - Opponent's Pokémon (id, name, stats)
 * @param  {string} opponentType - "bot" or "human" (default: "bot")
 *
 * @returns { result, playerScore, opponentScore }
 */

async function handleBattle(playerId, playerPokemon, opponentPokemon, opponentType = "bot") {
    // ✅ Check if player reached daily fight limit
    const limitReached = await hasReachedDailyFightLimit(playerId);
    if (limitReached) {
        throw new Error("Daily fight limit reached. Please try again tomorrow.");
    }

    // 🔍 Fetch user from Firestore
    const userRef = db.collection('users').doc(playerId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
        throw new Error("User not found in Firestore");
    }

    const user = userDoc.data();

    // 🧮 Scoring formula with stat weights + randomness
    const score = (p) =>
        p.stats.hp * 0.3 +
        p.stats.attack * 0.4 +
        p.stats.defense * 0.2 +
        p.stats.speed * 0.1 +
        Math.random() * 10;

    // ⚔️ Calculate scores
    const playerScore = score(playerPokemon);
    const opponentScore = score(opponentPokemon);

    // 🧠 Determine result (tie if difference < 2)
    let result;
    if (Math.abs(playerScore - opponentScore) < 2) result = "tie";
    else result = playerScore > opponentScore ? "win" : "lose";

    console.log(`[BATTLE - ${opponentType.toUpperCase()}] ${playerPokemon.name} vs ${opponentPokemon.name} → ${result}`);

    // 📅 Prepare fight history entry
    const today = new Date().toISOString().split('T')[0];
    const fightRecord = {
        date: today,
        opponent: opponentType,
        playerPokemon: {
            id: playerPokemon.id,
            name: playerPokemon.name
        },
        opponentPokemon: {
            id: opponentPokemon.id,
            name: opponentPokemon.name
        },
        result
    };

    // 🏅 Prepare score updates
    const currentScores = user.score || { bot: 0, human: 0, total: 0 };
    const scoreGain = result === "win" ? 3 : result === "tie" ? 1 : 0;

    // 🏅 Update Firestore user document:
    await userRef.update({
        history: admin.firestore.FieldValue.arrayUnion(fightRecord),
        [`score.${opponentType}`]: currentScores[opponentType] + scoreGain,
        'score.total': currentScores.total + scoreGain
    });

    // ✅ Return result and raw scores
    return { result, playerScore, opponentScore };
}



/**
 * @route   GET /users/:userId/favorites
 * @access  Private (requires login)
 * @desc    Fetches user's favorite Pokémon from Firestore.
 *          Optional enrichment with detailed stats from PokéAPI if `?enrich=true`.
 */

app.get("/users/:userId/favorites", requireLogin, async (req, res) => {
    const userId = req.params.userId;

    try {
        // 🔍 Fetch user from Firestore
        const userDoc = await db.collection('users').doc(userId).get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: "User not found" });
        }

        const user = userDoc.data();
        const favorites = user.favorites || [];

        // ❓ Check if ?enrich=true is requested
        const enrich = req.query.enrich === "true";

        if (!enrich) {
            // 🟢 Return raw favorites list
            return res.json(favorites);
        }

        // 🟡 Enrich each favorite Pokémon with stats from PokéAPI
        const enrichedFavorites = await Promise.all(
            favorites.map(async (pokemon) => {
                try {
                    const { data } = await axios.get(`https://pokeapi.co/api/v2/pokemon/${pokemon.id}`);

                    const stats = {
                        hp: data.stats.find(s => s.stat.name === "hp")?.base_stat || 0,
                        attack: data.stats.find(s => s.stat.name === "attack")?.base_stat || 0,
                        defense: data.stats.find(s => s.stat.name === "defense")?.base_stat || 0,
                        speed: data.stats.find(s => s.stat.name === "speed")?.base_stat || 0
                    };

                    return {
                        id: pokemon.id,
                        name: pokemon.name,
                        image: pokemon.image,
                        stats
                    };
                } catch (err) {
                    console.error(`Failed to fetch stats for Pokémon ID ${pokemon.id}:`, err.message);
                    return null;
                }
            })
        );

        // ✅ Filter out failed fetches and return enriched list
        res.json(enrichedFavorites.filter(Boolean));

    } catch (err) {
        console.error("Error fetching favorites:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});



/**
 * @route   GET /api/popular-pokemons
 * @access  Private (requires login)
 * @desc    Returns a list of hand-picked popular Pokémon fetched from PokéAPI.
 */

app.get("/api/popular-pokemons", requireLogin, async (req, res) => {
    const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours in ms
    const now = Date.now();

    // ✅ If cache is fresh, return cached data
    if (popularCache.data.length > 0 && (now - popularCache.timestamp) < CACHE_TTL) {
        console.log("Serving Popular Pokémons from CACHE ✅");
        return res.json(popularCache.data);
    }

    try {
        console.log("Fetching Popular Pokémons from PokéAPI 🌐");

        const requests = POPULAR_IDS.map(id =>
            axios.get(`https://pokeapi.co/api/v2/pokemon/${id}`)
        );

        const responses = await Promise.all(requests);

        const popular = responses.map(r => ({
            id: r.data.id,
            name: r.data.name,
            image: r.data.sprites.other["official-artwork"].front_default,
            types: r.data.types.map(t => t.type.name),
            abilities: r.data.abilities.map(a => a.ability.name),
        }));

        // 🔥 Save to cache
        popularCache = {
            data: popular,
            timestamp: now
        };

        res.json(popular);

    } catch (err) {
        console.error("Error fetching popular Pokémon:", err.message);
        res.status(500).json({ error: "Failed to fetch popular Pokémon" });
    }
});



/**
 * @route   POST /users/:userId/favorites
 * @access  Private (requires login)
 * @desc    Adds a Pokémon to the user's favorites list in Firestore.
 */

app.post("/users/:userId/favorites", requireLogin, async (req, res) => {
    const userId = req.params.userId;
    const pokemon = req.body; // { id, name, image, types, abilities }

    // ❌ Ensure session user matches requested userId
    if (req.session.userId !== userId) {
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        // 🔍 Fetch user document from Firestore
        const userRef = db.collection('users').doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ success: false, error: "User not found" });
        }

        const user = userDoc.data();
        const favorites = user.favorites || [];

        // 🚫 Enforce limit of 10 favorites
        if (favorites.length >= 10) {
            return res.status(400).json({ success: false, error: "Favorites limit reached (10)" });
        }

        // 🚫 Prevent duplicates
        if (favorites.some(p => p.id === pokemon.id)) {
            return res.status(400).json({ success: false, error: "Pokémon already in favorites" });
        }

        // ✅ Add the Pokémon to the favorites array
        favorites.push({
            id: pokemon.id,
            name: pokemon.name,
            image: pokemon.image,
            types: pokemon.types || [],
            abilities: pokemon.abilities || []
        });

        // 💾 Update Firestore document
        await userRef.update({
            favorites: favorites
        });

        // 🎉 Success
        res.json({ success: true });

    } catch (err) {
        console.error("Error adding favorite:", err);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});







/**
 * @route   DELETE /users/:userId/favorites/:pokemonId
 * @access  Private (requires login)
 * @desc    Removes a specific Pokémon from the user's favorites list in Firestore.
 */

app.delete("/users/:userId/favorites/:pokemonId", requireLogin, async (req, res) => {
    const userId = req.params.userId;
    const pokemonId = parseInt(req.params.pokemonId);

    // ❌ Ensure session user matches requested userId
    if (req.session.userId !== userId) {
        return res.status(403).json({ error: "Forbidden" });
    }

    try {
        // 🔍 Fetch user document from Firestore
        const userRef = db.collection('users').doc(userId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: "User not found" });
        }

        const user = userDoc.data();
        const favorites = user.favorites || [];

        // 🗑️ Filter out the Pokémon with the given ID
        const updatedFavorites = favorites.filter(p => p.id !== pokemonId);

        // 💾 Update Firestore document
        await userRef.update({
            favorites: updatedFavorites
        });

        // ✅ Success
        res.json({ success: true });

    } catch (err) {
        console.error("Error removing favorite:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});






/**
 * @route   GET /api/history
 * @access  Private (requires login)
 * @desc    Fetches the logged-in user's battle history from Firestore.
 */
app.get("/api/history", requireLogin, async (req, res) => {
    const userId = req.session.userId; // 🔐 Get current user's ID from session

    try {
        // 🔍 Fetch user document from Firestore
        const userDoc = await db.collection('users').doc(userId).get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: "User not found" });
        }

        const user = userDoc.data();

        // ✅ Return user's history (or empty array if none exists)
        res.json(user.history || []);

    } catch (err) {
        console.error("Error fetching history:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});




/**
 * ✅ Route: GET /api/leaderboard
 * ------------------------------
 * @desc   Returns a leaderboard of all users, sorted by total score.
 *
 * @access Private (requires session via requireLogin middleware)
 *
 * ✅ What it does:
 *   - Loads all users from Firestore
 *   - Calculates:
 *     - Total number of wins per user
 *     - Total number of battles
 *     - Success rate = (wins / battles) × 100
 *     - Retrieves score and avatar for display
 *   - Sorts users by score in descending order
 *
 * ✅ Returns:
 *   - Array of leaderboard entries:
 *     [
 *       { name, avatar, score, successRate },
 *       ...
 *     ]
 *   - { error: "..." } on failure
 */

app.get("/api/leaderboard", requireLogin, async (req, res) => {
    try {
        // 🔄 Get all users from Firestore 'users' collection
        const usersSnapshot = await db.collection('users').get();

        const leaderboard = [];

        usersSnapshot.forEach(doc => {
            const user = doc.data();

            const wins = user.history?.filter(h => h.result === "win").length || 0; // 🏆 Count wins
            const battles = user.history?.length || 0; // ⚔️ Total battles
            const successRate = battles > 0
                ? ((wins / battles) * 100).toFixed(2)
                : "0.00"; // 📊 Win rate percentage

            leaderboard.push({
                name: user.firstName,
                avatar: user.avatar || `https://api.dicebear.com/9.x/bottts/png?seed=${user.firstName}`,
                score: user.score?.total || 0,
                successRate
            });
        });

        // 🔽 Sort leaderboard by score (descending)
        leaderboard.sort((a, b) => b.score - a.score);

        // ✅ Send leaderboard back to client
        res.json(leaderboard);

    } catch (err) {
        console.error("Leaderboard error:", err);
        res.status(500).json({ error: "Failed to fetch leaderboard" });
    }
});







/**
 * ✅ Route: GET /users/:userId/favorites/download
 * -----------------------------------------------
 * @desc   Generates and downloads the user's favorites list as a CSV file.
 *
 * @access Private (requires login session)
 *
 * ✅ What it does now:
 *   - Fetches the user document from Firestore using userId
 *   - Checks if user exists and has favorites
 *   - Formats favorites list into CSV format:
 *     - Fields: id, name, image, types, abilities
 *   - Sends CSV file as download attachment
 */

app.get("/users/:userId/favorites/download", requireLogin, async (req, res) => {
    const userId = String(req.params.userId);

    // ❌ Ensure the session user matches requested userId
    if (req.session.userId !== userId) {
        return res.status(403).send("Forbidden");
    }

    try {
        // 🔍 Fetch user document from Firestore
        const userDoc = await db.collection('users').doc(userId).get();

        if (!userDoc.exists) {
            return res.status(404).send("User not found.");
        }

        const user = userDoc.data();

        if (!Array.isArray(user.favorites) || user.favorites.length === 0) {
            return res.status(404).send("No favorites to download.");
        }

        // 📝 Prepare CSV data
        const favorites = user.favorites.map(p => ({
            id: p.id,
            name: p.name,
            image: p.image || "",
            types: Array.isArray(p.types) ? p.types.join("/") : "",
            abilities: Array.isArray(p.abilities) ? p.abilities.join("/") : ""
        }));

        const fields = ["id", "name", "image", "types", "abilities"];
        const parser = new Parser({ fields });
        const csv = parser.parse(favorites);

        // 📤 Send CSV file as download
        res.header("Content-Type", "text/csv");
        res.attachment("favorites.csv");
        res.send(csv);

    } catch (err) {
        console.error("❌ CSV download error:", err);
        res.status(500).send("Failed to generate CSV.");
    }
});





// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});

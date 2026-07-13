"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const google_auth_library_1 = require("google-auth-library");
const mongodb_1 = require("mongodb");
dotenv_1.default.config();
const app = (0, express_1.default)();
const port = Number(process.env.PORT) || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const AUTH_COOKIE = "cinema_auth_token";
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in environment variables");
}
// ================= Middleware =================
app.use((0, cors_1.default)({
    origin: [
        "http://localhost:3000",
        process.env.CLIENT_URL,
    ],
    credentials: true,
}));
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
// ================= Google OAuth Client =================
const googleClient = new google_auth_library_1.OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// ================= MongoDB =================
const uri = process.env.MONGODB_URI;
const client = new mongodb_1.MongoClient(uri);
let moviesCollection;
let usersCollection;
async function connectDB() {
    try {
        await client.connect();
        console.log("✅ MongoDB Connected");
        const db = client.db("ReelBox");
        moviesCollection = db.collection("movies");
        usersCollection = db.collection("users");
        console.log("Database:", db.databaseName);
    }
    catch (error) {
        console.log(error);
        process.exit(1);
    }
}
// ================= Auth Helpers =================
function signToken(payload) {
    return jsonwebtoken_1.default.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}
// ⭐ এইটাই মূল জায়গা যেখানে NODE_ENV কাজ করে ⭐
function setAuthCookie(res, token) {
    const isProd = process.env.NODE_ENV === "production";
    res.cookie(AUTH_COOKIE, token, {
        httpOnly: true,
        secure: isProd, // production হলে true, localhost হলে false
        sameSite: isProd ? "none" : "lax", // production হলে "none", localhost হলে "lax"
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
}
function requireAuth(req, res, next) {
    const token = req.cookies?.[AUTH_COOKIE] ||
        req.headers.authorization?.replace("Bearer ", "");
    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}
// =======================
// Routes
// =======================
app.get("/", (req, res) => {
    res.send("ReelBox Server Running 🚀");
});
// ---------- Auth Routes ----------
app.post("/auth/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: "Name, email and password are required" });
        }
        const existing = await usersCollection.findOne({ email });
        if (existing) {
            return res.status(409).json({ message: "Email already registered" });
        }
        const hashedPassword = await bcrypt_1.default.hash(password, 10);
        const result = await usersCollection.insertOne({
            name,
            email,
            password: hashedPassword,
            provider: "manual",
            createdAt: new Date(),
        });
        const token = signToken({ id: result.insertedId.toString(), name, email });
        setAuthCookie(res, token);
        res.status(201).json({ user: { id: result.insertedId, name, email } });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Registration failed" });
    }
});
app.post("/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        if (user.provider === "google" || !user.password) {
            return res.status(400).json({
                message: "This email is registered with Google. Please use 'Continue with Google'.",
            });
        }
        const isMatch = await bcrypt_1.default.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        const token = signToken({ id: user._id.toString(), name: user.name, email: user.email });
        setAuthCookie(res, token);
        res.json({ user: { id: user._id, name: user.name, email: user.email } });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Login failed" });
    }
});
app.post("/auth/google", async (req, res) => {
    try {
        const { credential } = req.body;
        if (!credential) {
            return res.status(400).json({ message: "Missing Google credential" });
        }
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        if (!payload || !payload.email) {
            return res.status(401).json({ message: "Invalid Google token" });
        }
        let user = await usersCollection.findOne({ email: payload.email });
        if (!user) {
            const result = await usersCollection.insertOne({
                name: payload.name || "Google User",
                email: payload.email,
                provider: "google",
                createdAt: new Date(),
            });
            user = await usersCollection.findOne({ _id: result.insertedId });
        }
        if (!user) {
            return res.status(500).json({ message: "Failed to create user" });
        }
        const token = signToken({ id: user._id.toString(), name: user.name, email: user.email });
        setAuthCookie(res, token);
        res.json({ user: { id: user._id, name: user.name, email: user.email } });
    }
    catch (error) {
        console.error(error);
        res.status(401).json({ message: "Google authentication failed" });
    }
});
app.post("/auth/logout", (req, res) => {
    res.clearCookie(AUTH_COOKIE);
    res.json({ message: "Logged out" });
});
app.get("/auth/me", requireAuth, (req, res) => {
    res.json({ user: req.user });
});
// ---------- Movie Routes ----------
app.get("/movies", async (req, res) => {
    try {
        const movies = await moviesCollection.find().toArray();
        res.status(200).json(movies);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Failed to load movies" });
    }
});
app.get("/movies/trending", async (req, res) => {
    try {
        const movies = await moviesCollection.find({ trending: true }).limit(8).toArray();
        res.json(movies);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load trending movies" });
    }
});
app.get("/movies/featured", async (req, res) => {
    try {
        const movies = await moviesCollection.find({ featured: true }).limit(9).toArray();
        res.json(movies);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load featured movies" });
    }
});
app.get("/movies/popular", async (req, res) => {
    try {
        const movies = await moviesCollection.find().sort({ rating: -1 }).limit(9).toArray();
        res.json(movies);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load popular movies" });
    }
});
app.get("/movies/mine", requireAuth, async (req, res) => {
    try {
        const movies = await moviesCollection.find({ addedBy: req.user.id }).toArray();
        res.json(movies);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load your movies" });
    }
});
app.get("/movies/filters", async (req, res) => {
    try {
        const genres = await moviesCollection.distinct("genre");
        const languages = await moviesCollection.distinct("language");
        res.json({ genres, languages });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load filters" });
    }
});
app.get("/movies/explore", async (req, res) => {
    try {
        const { search, genre, language, sort, page = "1", limit = "12" } = req.query;
        const query = {};
        if (search && typeof search === "string") {
            query.title = { $regex: search, $options: "i" };
        }
        if (genre && typeof genre === "string") {
            query.genre = genre;
        }
        if (language && typeof language === "string") {
            query.language = language;
        }
        const pageNum = Math.max(1, parseInt(String(page)) || 1);
        const limitNum = Math.max(1, parseInt(String(limit)) || 12);
        const skip = (pageNum - 1) * limitNum;
        let sortOption = {};
        switch (sort) {
            case "rating_desc":
                sortOption = { rating: -1 };
                break;
            case "rating_asc":
                sortOption = { rating: 1 };
                break;
            case "year_desc":
                sortOption = { releaseYear: -1 };
                break;
            case "year_asc":
                sortOption = { releaseYear: 1 };
                break;
            case "title_asc":
                sortOption = { title: 1 };
                break;
            default: sortOption = { releaseYear: -1 };
        }
        const total = await moviesCollection.countDocuments(query);
        const movies = await moviesCollection.find(query).sort(sortOption).skip(skip).limit(limitNum).toArray();
        res.json({
            movies,
            total,
            page: pageNum,
            totalPages: Math.max(1, Math.ceil(total / limitNum)),
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load movies" });
    }
});
app.get("/movies/:id", async (req, res) => {
    try {
        const id = String(req.params.id);
        if (!mongodb_1.ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid movie id" });
        }
        const movie = await moviesCollection.findOne({ _id: new mongodb_1.ObjectId(id) });
        if (!movie) {
            return res.status(404).json({ message: "Movie not found" });
        }
        res.json(movie);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to load movie" });
    }
});
app.post("/movies", requireAuth, async (req, res) => {
    try {
        const movie = { ...req.body, addedBy: req.user.id };
        const result = await moviesCollection.insertOne(movie);
        res.json(result);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to add movie" });
    }
});
app.delete("/movies/:id", requireAuth, async (req, res) => {
    try {
        const id = String(req.params.id);
        if (!mongodb_1.ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid movie id" });
        }
        const movie = await moviesCollection.findOne({ _id: new mongodb_1.ObjectId(id) });
        if (!movie) {
            return res.status(404).json({ message: "Movie not found" });
        }
        if (movie.addedBy !== req.user.id) {
            return res.status(403).json({ message: "You can only delete your own items" });
        }
        await moviesCollection.deleteOne({ _id: new mongodb_1.ObjectId(id) });
        res.json({ message: "Movie deleted" });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to delete movie" });
    }
});
// =======================
// Start Server
// =======================
async function startServer() {
    await connectDB();
    app.listen(port, () => {
        console.log(`🚀 Server Running on ${port}`);
    });
}
startServer();

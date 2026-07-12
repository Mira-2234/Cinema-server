import express, { Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { MongoClient, ObjectId, Collection } from "mongodb";

dotenv.config();

const app = express();

const port = Number(process.env.PORT) || 5000;
const JWT_SECRET = process.env.JWT_SECRET as string;
const AUTH_COOKIE = "cinema_auth_token";

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined in environment variables");
}

// ================= Middleware =================

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

// ================= Google OAuth Client =================

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================= Interfaces =================

interface Movie {
  title: string;
  shortDescription: string;
  poster: string;
  banner: string;
  genre: string;
  language: string;
  duration: string;
  releaseYear: number;
  rating: number;
  description: string;
  featured: boolean;
  trending: boolean;
  addedBy: string;
}

interface User {
  name: string;
  email: string;
  password?: string;
  provider: "manual" | "google";
  createdAt: Date;
}

interface AuthPayload {
  id: string;
  name: string;
  email: string;
}

interface AuthRequest extends Request {
  user?: AuthPayload;
}

// ================= MongoDB =================

const uri = process.env.MONGODB_URI!;
const client = new MongoClient(uri);

let moviesCollection: Collection<Movie>;
let usersCollection: Collection<User>;

async function connectDB() {
  try {
    await client.connect();

    console.log("✅ MongoDB Connected");

    const db = client.db("ReelBox");

    moviesCollection = db.collection<Movie>("movies");
    usersCollection = db.collection<User>("users");

    console.log("Database:", db.databaseName);
    console.log(
      "Collections:",
      moviesCollection.collectionName,
      usersCollection.collectionName
    );
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
}

// ================= Auth Helpers =================

function signToken(payload: AuthPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function setAuthCookie(res: Response, token: string) {
  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const token =
    req.cookies?.[AUTH_COOKIE] ||
    req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthPayload;
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// =======================
// Routes
// =======================

app.get("/", (req: Request, res: Response) => {
  res.send("ReelBox Server Running 🚀");
});

// ---------- Auth Routes ----------

// Register (manual)
app.post("/auth/register", async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "Name, email and password are required" });
    }

    const existing = await usersCollection.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      provider: "manual",
      createdAt: new Date(),
    });

    const token = signToken({
      id: result.insertedId.toString(),
      name,
      email,
    });

    setAuthCookie(res, token);

    res.status(201).json({
      user: { id: result.insertedId, name, email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Registration failed" });
  }
});

// Login (manual)
app.post("/auth/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (user.provider === "google" || !user.password) {
      return res.status(400).json({
        message:
          "This email is registered with Google. Please use 'Continue with Google'.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = signToken({
      id: user._id.toString(),
      name: user.name,
      email: user.email,
    });

    setAuthCookie(res, token);

    res.json({
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Login failed" });
  }
});

// Google Login
app.post("/auth/google", async (req: Request, res: Response) => {
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

    const token = signToken({
      id: user._id.toString(),
      name: user.name,
      email: user.email,
    });

    setAuthCookie(res, token);

    res.json({
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(401).json({ message: "Google authentication failed" });
  }
});

// Logout
app.post("/auth/logout", (req: Request, res: Response) => {
  res.clearCookie(AUTH_COOKIE);
  res.json({ message: "Logged out" });
});

// Current user
app.get("/auth/me", requireAuth, (req: AuthRequest, res: Response) => {
  res.json({ user: req.user });
});

// ---------- Movie Routes ----------
// IMPORTANT: all specific "/movies/xxx" routes MUST come before "/movies/:id"

// Get All Movies
app.get("/movies", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection.find().toArray();
    res.status(200).json(movies);
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ success: false, message: "Failed to load movies" });
  }
});

// Trending Movies
app.get("/movies/trending", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection
      .find({ trending: true })
      .limit(8)
      .toArray();
    res.json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load trending movies" });
  }
});

// Featured Movies
app.get("/movies/featured", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection
      .find({ featured: true })
      .limit(9)
      .toArray();
    res.json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load featured movies" });
  }
});

// Popular Movies
app.get("/movies/popular", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection
      .find()
      .sort({ rating: -1 })
      .limit(9)
      .toArray();
    res.json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load popular movies" });
  }
});

// My Movies (protected — Manage Items page)
app.get("/movies/mine", requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const movies = await moviesCollection
      .find({ addedBy: req.user!.id })
      .toArray();
    res.json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load your movies" });
  }
});

// Filter options (genres/languages)
app.get("/movies/filters", async (req: Request, res: Response) => {
  try {
    const genres = await moviesCollection.distinct("genre");
    const languages = await moviesCollection.distinct("language");

    res.json({ genres, languages });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load filters" });
  }
});

// Explore — search + filter + sort + pagination
app.get("/movies/explore", async (req: Request, res: Response) => {
  try {
    const {
      search,
      genre,
      language,
      sort,
      page = "1",
      limit = "12",
    } = req.query;

    const query: Record<string, unknown> = {};

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

    let sortOption: Record<string, 1 | -1> = {};
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
      default:
        sortOption = { releaseYear: -1 };
    }

    const total = await moviesCollection.countDocuments(query);

    const movies = await moviesCollection
      .find(query)
      .sort(sortOption)
      .skip(skip)
      .limit(limitNum)
      .toArray();

    res.json({
      movies,
      total,
      page: pageNum,
      totalPages: Math.max(1, Math.ceil(total / limitNum)),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load movies" });
  }
});

// ---------------------------------------------------------
// Single Movie — PUBLIC, generic :id route.
// Must stay LAST among all "/movies/*" GET routes.
// requireAuth removed here per requirement #5: "Details Page
// - Publicly accessible"
// ---------------------------------------------------------
app.get("/movies/:id", async (req: Request, res: Response) => {
  try {
    const id = String(req.params.id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid movie id" });
    }

    const movie = await moviesCollection.findOne({ _id: new ObjectId(id) });

    if (!movie) {
      return res.status(404).json({ message: "Movie not found" });
    }

    res.json(movie);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load movie" });
  }
});

// Add Movie (protected)
app.post("/movies", requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const movie: Movie = {
      ...req.body,
      addedBy: req.user!.id,
    };

    const result = await moviesCollection.insertOne(movie);
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to add movie" });
  }
});

// Delete Movie (protected — owner only)
app.delete("/movies/:id", requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const id = String(req.params.id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid movie id" });
    }

    const movie = await moviesCollection.findOne({ _id: new ObjectId(id) });

    if (!movie) {
      return res.status(404).json({ message: "Movie not found" });
    }

    if (movie.addedBy !== req.user!.id) {
      return res.status(403).json({ message: "You can only delete your own items" });
    }

    await moviesCollection.deleteOne({ _id: new ObjectId(id) });
    res.json({ message: "Movie deleted" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete movie" });
  }
});


async function startServer() {
  await connectDB();

  app.listen(port, () => {
    console.log(`🚀 Server Running on ${port}`);
  });
}

startServer();
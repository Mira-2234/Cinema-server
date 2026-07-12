import express, { Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId, Collection } from "mongodb";

dotenv.config();

const app = express();

const port = Number(process.env.PORT) || 5000;
const JWT_SECRET = process.env.JWT_SECRET as string;
const AUTH_COOKIE = "cinema_auth_token";

// ================= Middleware =================

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

// ================= Interface =================

interface Movie {
  title: string;
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
}

interface User {
  name: string;
  email: string;
  password: string; // hashed
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
    console.log("Collections:", moviesCollection.collectionName, usersCollection.collectionName);
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
}

// ================= Auth Helpers =================

function signToken(payload: AuthPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
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

// Register
app.post("/auth/register", async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email and password are required" });
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
      createdAt: new Date(),
    });

    const token = signToken({
      id: result.insertedId.toString(),
      name,
      email,
    });

    res.cookie(AUTH_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(201).json({
      user: { id: result.insertedId, name, email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Registration failed" });
  }
});

// Login
app.post("/auth/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
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

    res.cookie(AUTH_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Login failed" });
  }
});

// Logout
app.post("/auth/logout", (req: Request, res: Response) => {
  res.clearCookie(AUTH_COOKIE);
  res.json({ message: "Logged out" });
});

// Current user (Next.js middleware/page ei diye check korte parbe)
app.get("/auth/me", requireAuth, (req: AuthRequest, res: Response) => {
  res.json({ user: req.user });
});

// ---------- Movie Routes ----------

// Get All Movies
app.get("/movies", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection.find().toArray();
    res.status(200).json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to load movies" });
  }
});

// Trending Movies
app.get("/movies/trending", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection.find({ trending: true }).limit(8).toArray();
    res.json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load trending movies" });
  }
});

// Featured Movies
app.get("/movies/featured", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection.find({ featured: true }).limit(9).toArray();
    res.json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load featured movies" });
  }
});

// Popular Movies
app.get("/movies/popular", async (req: Request, res: Response) => {
  const movies = await moviesCollection.find().sort({ rating: -1 }).limit(9).toArray();
  res.json(movies);
});

// Single Movie (protected — logged-in user chara dekhte parbe na)
app.get("/movies/:id", requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const id = String(req.params.id);
    const movie = await moviesCollection.findOne({ _id: new ObjectId(id) });

    if (!movie) {
      return res.status(404).json({ message: "Movie not found" });
    }

    res.json(movie);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Movie not found" });
  }
});

// Add Movie (protected — /items/add page-er jonno)
app.post("/movies", requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const movie: Movie = req.body;
    const result = await moviesCollection.insertOne(movie);
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to add movie" });
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
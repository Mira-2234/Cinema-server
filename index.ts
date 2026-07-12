import express, { Request, Response } from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import { MongoClient, ObjectId, Collection } from "mongodb";

dotenv.config();

const app = express();

const port = Number(process.env.PORT) || 5000;

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

// ================= MongoDB =================

const uri = process.env.MONGODB_URI!;

const client = new MongoClient(uri);

let moviesCollection: Collection<Movie>;

async function connectDB() {
  try {
    await client.connect();

    console.log("✅ MongoDB Connected");

    const db = client.db("ReelBox");

    moviesCollection = db.collection<Movie>("movies");

    console.log("Database:", db.databaseName);
    console.log("Collection:", moviesCollection.collectionName);
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
}

// =======================
// Routes
// =======================

app.get("/", (req: Request, res: Response) => {
  res.send("ReelBox Server Running 🚀");
});

// Get All Movies

app.get("/movies", async (req: Request, res: Response) => {
  try {
    const movies = await moviesCollection.find().toArray();

    res.status(200).json(movies);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Failed to load movies",
    });
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

    res.status(500).json({
      message: "Failed to load trending movies",
    });
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

    res.status(500).json({
      message: "Failed to load featured movies",
    });
  }
});

// Single Movie

app.get("/movies/:id", async (req: Request, res: Response) => {
  try {
   const id = String(req.params.id);

  const movie = await moviesCollection.findOne({
  _id: new ObjectId(id),
});

    res.json(movie);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Movie not found",
    });
  }
});

// Add Movie

app.post("/movies", async (req: Request, res: Response) => {
  try {
    const movie: Movie = req.body;

    const result = await moviesCollection.insertOne(movie);

    res.json(result);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Failed to add movie",
    });
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
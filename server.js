const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const User = require("./models/User");

const app = express();

const PORT = 3000;

// JWT Secret
const JWT_SECRET = "my_secret_key_12345";

// ==============================
// MIDDLEWARE
// ==============================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend files
app.use(express.static(path.join(__dirname, "public")));


// ==============================
// MONGODB CONNECTION
// ==============================

// Local MongoDB connection
mongoose
    .connect("mongodb://127.0.0.1:27017/authenticationDB")
    .then(() => {
        console.log("MongoDB connected successfully");
    })
    .catch((error) => {
        console.log("MongoDB connection failed");
        console.log(error.message);
    });


// ==============================
// REGISTER
// ==============================

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.post("/register", async (req, res) => {

    try {

        const { email, password } = req.body;

        // Check input
        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required"
            });
        }

        // Password length validation
        if (password.length < 6) {
            return res.status(400).json({
                error: "Password must contain at least 6 characters"
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            email: email
        });

        if (existingUser) {
            return res.status(409).json({
                error: "User already exists"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(
            password,
            10
        );

        // Create user
        const user = new User({
            email: email,
            password: hashedPassword
        });

        // Save user to MongoDB
        await user.save();

        res.status(201).json({
            message: "User registered successfully"
        });

    } catch (error) {

        console.log(error);

        res.status(500).json({
            error: "Registration failed"
        });
    }
});


// ==============================
// LOGIN
// ==============================

app.post("/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        // Check input
        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required"
            });
        }

        // Find user
        const user = await User.findOne({
            email: email
        });

        if (!user) {
            return res.status(401).json({
                error: "Invalid email or password"
            });
        }

        // Compare password
        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                error: "Invalid email or password"
            });
        }

        // Generate JWT
        const token = jwt.sign(
            {
                id: user._id,
                email: user.email
            },
            JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        res.json({
            message: "Login successful",
            token: token
        });

    } catch (error) {

        console.log(error);

        res.status(500).json({
            error: "Login failed"
        });
    }
});


// ==============================
// AUTHENTICATION MIDDLEWARE
// ==============================

function authenticateToken(req, res, next) {

    const authHeader =
        req.headers.authorization;

    // Check Authorization header
    if (!authHeader) {

        return res.status(401).json({
            error: "Access denied. Token required."
        });
    }

    // Get token
    const token =
        authHeader.split(" ")[1];

    if (!token) {

        return res.status(401).json({
            error: "Invalid token"
        });
    }

    try {

        // Verify JWT
        const decoded =
            jwt.verify(token, JWT_SECRET);

        // Store user information
        req.user = decoded;

        next();

    } catch (error) {

        return res.status(403).json({
            error: "Invalid or expired token"
        });
    }
}


// ==============================
// PROTECTED DASHBOARD
// ==============================

app.get(
    "/dashboard",
    authenticateToken,
    (req, res) => {

        res.json({
            message:
                `Welcome to the dashboard, ${req.user.email}!`
        });

    }
);


// ==============================
// LOGOUT
// ==============================

app.post("/logout", (req, res) => {

    res.json({
        message: "Logout successful"
    });

});


// ==============================
// HOME PAGE
// ==============================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "login.html"
        )
    );

});


// ==============================
// START SERVER
// ==============================

app.listen(PORT, () => {

    console.log(
        `Server running at http://localhost:${PORT}`
    );

});
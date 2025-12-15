import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import mysql from 'mysql2';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = "my_super_secret_key_123";

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "baby_diary",
    port: 3306
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
    } else {
        console.log(' Connected to database');
    }
});

app.get('/', (req, res) => {
    res.send("Hello from server");
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    db.query(`SELECT * FROM users WHERE email = ?`, [email], async (err, results) => {

        if (err) return res.status(500).json({ message: "Database error" });

        if (results.length > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
            [name, email, hashedPassword],
            (err, result) => {
                if (err) {
                    return res.status(500).json({ message: "Error registering user" });
                }

                res.status(201).json({ message: " User registered successfully" });
            }
        );
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query(`SELECT * FROM users WHERE email = ?`, [email], async (err, results) => {

        if (err) return res.status(500).json({ message: "Database error" });

        if (results.length == 0) {
            return res.status(400).json({ message: "User not found" });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Incorrect password" });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        // 4️⃣ Send token + user info
        res.json({
            message: " Login successful",
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    });
});

function auth(req, res, next) {
    const authHeader = req.headers.authorization;


    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;  // { id, email }
        next();
    } catch (error) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

// ✅ PROTECTED TEST ROUTE
app.get('/profile', auth, (req, res) => {
    res.json({
        message: "✅ You are authenticated",
        user: req.user
    });
});

app.post('/diary/add', auth, (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.id;  // from token

    const sql = `INSERT INTO diary (user_id, title, content) VALUES (?, ?, ?)`;

    db.query(sql, [userId, title, content], (err, result) => {
        if (err) return res.status(500).json({ message: "Error adding diary" });
        res.status(201).json({ message: "Diary added successfully" });
    });
});
app.get('/diary/all', auth, (req, res) => {
    const userId = req.user.id;

    const sql = `SELECT * FROM diary WHERE user_id = ? ORDER BY created_at DESC`;

    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).json({ message: "Error fetching diary" });
        res.json(results);
    });
});
app.delete('/diary/:id', auth, (req, res) => {
    const diaryId = req.params.id;
    const userId = req.user.id;

    const sql = `DELETE FROM diary WHERE id = ? AND user_id = ?`;

    db.query(sql, [diaryId, userId], (err, result) => {
        if (err) return res.status(500).json({ message: "Error deleting entry" });

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Diary not found or unauthorized" });
        }

        res.json({ message: "Diary deleted successfully" });
    });
});
app.post('/events/add', auth, (req, res) => {
    const { title, event_date } = req.body;
    const userId = req.user.id;

    const sql = `INSERT INTO events (user_id, title, event_date) VALUES (?, ?, ?)`;

    db.query(sql, [userId, title, event_date], (err, result) => {
        if (err) return res.status(500).json({ message: "Error adding event" });
        res.status(201).json({ message: "Event added successfully" });
    });
});
app.get('/events/all', auth, (req, res) => {
    const userId = req.user.id;

    const sql = `SELECT * FROM events WHERE user_id = ? ORDER BY event_date ASC`;

    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).json({ message: "Error fetching events" });
        res.json(results);
    });
});
app.post('/reminders/add', auth, (req, res) => {
    const { text, reminder_date } = req.body;
    const userId = req.user.id;

    const sql = `INSERT INTO reminders (user_id, text, reminder_date) VALUES (?, ?, ?)`;

    db.query(sql, [userId, text, reminder_date], (err, result) => {
        if (err) return res.status(500).json({ message: "Error adding reminder" });
        res.status(201).json({ message: "Reminder added successfully" });
    });
});
app.get('/reminders/all', auth, (req, res) => {
    const userId = req.user.id;

    const sql = `SELECT * FROM reminders WHERE user_id = ? ORDER BY reminder_date ASC`;

    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).json({ message: "Error fetching reminders" });
        res.json(results);
    });
});

// ✅ Start server
app.listen(3000, () => {
    console.log("✅ Server is running on port 3000");
});
import express, { Request, Response } from 'express';
import mysql, { RowDataPacket, OkPacket } from 'mysql2/promise';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import path from 'path';

//Creating a user object
interface User {
    id: number;
    username: string;
    password: string;
}

interface AuthenticatedRequest extends Request {
    user?: {
        id: number;
    };
}

interface Location {
    id: number;
    name: string;
}

// Init Database
const app = express();
app.use(express.json());

const pool = mysql.createPool({
    host: 'sql.freedb.tech',
    port: 3306,
    user: 'freedb_task_user',
    password: 'r%v37gePfE?S6BZ',
    database: 'freedb_task_school',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('Database connected successfully');
        connection.release();
    })
    .catch(err => {
        console.error('Error connecting to the database:', err);
    });

const JWT_SECRET = 'random_secret';


//Functionality for creating an account
app.post('/api/register', async (req: Request, res: Response) => {
    const { username, password } = req.body;
    const hashedPassword = await argon2.hash(password);

    try {
        await pool.execute(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );
        res.json({ success: true });
    } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error('Error during registration:', errorMessage);
        res.status(500).json({ success: false, error: 'Registration failed', details: errorMessage });
    }
});
// Functionality for logging in
app.post('/api/login', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    try {
        const [rows] = await pool.execute<RowDataPacket[]>(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            return res.status(400).json({ success: false, error: 'User not found' });
        }

        const user = rows[0] as User;
        const isMatch = await argon2.verify(user.password, password);

        if (!isMatch) {
            return res.status(400).json({ success: false, error: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token, user: { id: user.id, username: user.username } });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// Middleware to verify JWT token (For security reasons to prevent any misuse of the API that we created)
const authenticateToken = (req: AuthenticatedRequest, res: Response, next: Function) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};


// Functionality for authenticating the user if he opens the platform again and we have to pull data from the database
app.get('/api/check-auth', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const [rows] = await pool.execute<RowDataPacket[]>(
            'SELECT id, username FROM users WHERE id = ?',
            [req.user?.id]
        );
        if (rows.length > 0) {
            const user = rows[0];
            res.json({ loggedIn: true, user });
        } else {
            res.status(404).json({ loggedIn: false, error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ loggedIn: false, error: 'Failed to fetch user data' });
    }
});

// Functionality for getting the locations that the user entered
app.get('/api/locations', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user?.id;

    try {
        const [rows] = await pool.execute<RowDataPacket[]>(
            'SELECT * FROM locations WHERE user_id = ?',
            [userId]
        );
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch locations' });
    }
});

// Functionality for getting the weather for the selected locations
app.get('/api/locations/weather', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user?.id;

    try {
        const [rows] = await pool.execute<RowDataPacket[]>(
            'SELECT * FROM locations WHERE user_id = ?',
            [userId]
        );

        const locations = rows as Location[];
        const weatherPromises = locations.map(async location => {
            const geocodeResponse = await axios.get(`https://api.openweathermap.org/geo/1.0/direct?q=${location.name}&limit=1&appid=14f4a1b8829d4ca6539a13b0e4c31435`);
            if (geocodeResponse.data.length === 0) {
                throw new Error(`Could not find coordinates for location: ${location.name}`);
            }
            const { lat, lon } = geocodeResponse.data[0];

            const weatherResponse = await axios.get(`https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=14f4a1b8829d4ca6539a13b0e4c31435&units=metric`);

            const { temp } = weatherResponse.data.main;

            const { description } = weatherResponse.data.weather[0];
            const { icon } = weatherResponse.data.weather[0];
            return {
                location: location.name,
                temperature: temp,
                condition: description,
                icon: icon

            };
        });

        const weatherData = await Promise.all(weatherPromises);
        console.log(weatherData);
        res.json(weatherData);
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        res.status(500).json({ error: 'Failed to fetch weather data for locations', details: errorMessage });
    }
});
// Functionality for adding a new location
app.post('/api/locations', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user?.id;
    const { location } = req.body;

    try {
        const [result] = await pool.execute<OkPacket>(
            'INSERT INTO locations (user_id, name) VALUES (?, ?)',
            [userId, location]
        );
        res.json({ success: true, location: { id: result.insertId, name: location } });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add location' });
    }
});
/// Functionality for deleting a location
app.delete('/api/locations/:id', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user?.id;
    const locationId = req.params.id;

    try {
        await pool.execute(
            'DELETE FROM locations WHERE id = ? AND user_id = ?',
            [locationId, userId]
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete location' });
    }
});
// Telling the server to default to the index page
app.get('*', (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Defining the localhost server 
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

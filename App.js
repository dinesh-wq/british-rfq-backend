const express = require('express')
const {Pool} = require('pg')
const {v4} = require('uuid')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const http = require('http')
const { Server } = require('socket.io')
require('dotenv').config()

const app = express()
app.use(express.json())
app.use(cors())

const server = http.createServer(app)
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
})

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://us-west-2.api.thenile.dev/v2/databases/019db60b-50a1-7466-8027-a076f50bc1df'
});

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id)
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id)
    })
})

server.listen(process.env.PORT || 3001, () => {
    console.log(`Server Started at port ${process.env.PORT || 3001}`)
})

// POST login 
app.post('/auth/login', async (request, response) => {
    try {
        const { username, password } = request.body;
        const result = await pool.query(
            `SELECT * FROM users WHERE name = $1`,
            [username]
        );
        if (result.rows.length === 0) {
            return response.status(401).json({ message: 'Invalid Username' });
        }
        const user = result.rows[0];
        const isPasswordCorrect = await bcrypt.compare(
            password,
            user.password_hash
        );
        if (!isPasswordCorrect) {
            return response.status(401).json({ message: 'Invalid Password' });
        }
        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                role: user.role
            },
            process.env.JWT_SECRET || 'britishRFQ'
        );

        response.status(200).json({
            message: 'User Logged In Successfully',
            token
        });

    } catch (e) {
        response.status(500).json({
            message: `Error: ${e.message}`
        });
    }
});

// API 2 POST Signup
app.post('/auth/signup', async (request, response) => {
    try {
        const { name, email, password } = request.body;
        if (!name || !email || !password) {
            return response.status(400).json({
                message: 'All fields (name, email, password) are required'
            });
        }

        // 2. Check if name OR email already exists
        const existingUser = await pool.query(
            `SELECT name, email FROM users WHERE name = $1 OR email = $2`,
            [name, email]
        );

        if (existingUser.rows.length > 0) {
            const user = existingUser.rows[0];

            if (user.name === name && user.email === email) {
                return response.status(409).json({
                    message: 'Username and Email already exist'
                });
            }

            if (user.name === name) {
                return response.status(409).json({
                    message: 'Username already exists'
                });
            }

            if (user.email === email) {
                return response.status(409).json({
                    message: 'Email already exists'
                });
            }
        }

        // 3. Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 4. Insert user
        const newUser = await pool.query(
            `INSERT INTO users (name, email, password_hash, role)
             VALUES ($1, $2, $3, $4)
             RETURNING id, name, email, role`,
            [name, email, hashedPassword, 'supplier']
        );

        const user = newUser.rows[0];

        // 5. Generate token
        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                role: user.role
            },
            process.env.JWT_SECRET || 'britishRFQ'
        );

        response.status(201).json({
            message: 'User registered successfully',
            token,
            user
        });

    } catch (e) {
        response.status(500).json({
            message: `Error: ${e.message}`
        });
    }
});

// API 3 POST CREATE RFQ (REQUEST CREATED WHEN BUYER Wants to create the service)
app.post('/rfq/create', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'britishRFQ');

        if (decoded.role !== 'buyer') {
            return res.status(403).json({ message: 'Only buyers allowed' });
        }

        const { rfq_name, bid_start_time, bid_close_time, extension_time } = req.body;

        if (!rfq_name || !bid_start_time || !bid_close_time || !extension_time) {
            return res.status(400).json({ message: 'Missing fields' });
        }

        // generate reference id
        const reference_id = `RFQ-${Date.now()}`;

        const result = await pool.query(
            `INSERT INTO rfqs 
            (rfq_name, reference_id, buyer_id, bid_start_time, bid_close_time, forced_close_time, status)
            VALUES ($1,$2,$3,$4,$5,$6,'active')
            RETURNING *`,
            [
                rfq_name,
                reference_id,
                decoded.id,
                bid_start_time,
                bid_close_time,
                new Date(new Date(bid_close_time).getTime() + extension_time * 60000)
            ]
        );

        const newRFQ = result.rows[0];
        io.emit('new-rfq', newRFQ);
        res.json(newRFQ);

    } catch (e) {
        res.status(500).json({ message: e.message });
    }
});

// API 4 GET get all RFQ's
app.get('/rfq/all', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                r.id,
                r.rfq_name,
                r.reference_id,
                r.bid_close_time,
                u.name AS buyer_name,
                COALESCE(MIN(b.total_amount), 0) AS lowest_bid
            FROM rfqs r
            JOIN users u ON r.buyer_id = u.id
            LEFT JOIN bids b ON r.id = b.rfq_id
            GROUP BY r.id, u.name
            ORDER BY r.created_at DESC
        `);

        res.json(result.rows);

    } catch (e) {
        res.status(500).json({ message: e.message });
    }
});

// API 5 GET get all buyers details
app.get('/supplier/rfqs', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                r.id,
                r.rfq_name,
                r.reference_id,
                r.bid_close_time,
                COALESCE(MIN(b.total_amount), 0) AS lowest_bid
            FROM rfqs r
            LEFT JOIN bids b ON r.id = b.rfq_id
            WHERE r.status = 'active'
            GROUP BY r.id
            ORDER BY r.created_at DESC
        `);

        res.json(result.rows);

    } catch (e) {
        res.status(500).json({ message: e.message });
    }
});


// API 6 POST place a bid
app.post('/supplier/bid', async (req, res) => {
    const client = await pool.connect();

    try {
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'britishRFQ');

        if (decoded.role !== 'supplier') {
            return res.status(403).json({ message: 'Only suppliers can bid' });
        }

        const { rfq_id, amount } = req.body;

        if (!rfq_id || !amount) {
            return res.status(400).json({ message: 'Missing fields' });
        }

        await client.query('BEGIN');

        // 1. Get RFQ
        const rfqRes = await client.query(
            `SELECT * FROM rfqs WHERE id = $1`,
            [rfq_id]
        );

        const rfq = rfqRes.rows[0];

        if (!rfq || rfq.status !== 'active') {
            throw new Error('RFQ not active');
        }

        // 2. Insert bid
        await client.query(
            `INSERT INTO bids (rfq_id, supplier_id, total_amount)
             VALUES ($1,$2,$3)`,
            [rfq_id, decoded.id, amount]
        );

        // 3. Extension Logic
        const now = new Date();
        const closeTime = new Date(rfq.bid_close_time);

        const triggerWindow = 10; // minutes (simplified)
        const extension = 5; // minutes

        const diffMinutes = (closeTime - now) / 60000;

        if (diffMinutes <= triggerWindow) {
            const newClose = new Date(closeTime.getTime() + extension * 60000);

            await client.query(
                `UPDATE rfqs SET bid_close_time = $1 WHERE id = $2`,
                [newClose, rfq_id]
            );

            await client.query(
                `INSERT INTO auction_logs (rfq_id, event_type, description)
                 VALUES ($1,'time_extended','Extended due to last-minute bid')`,
                [rfq_id]
            );
        }

        await client.query('COMMIT');

        io.emit('new-bid', { rfq_id, amount, supplier_id: decoded.id });
        res.json({ message: 'Bid placed successfully' });

    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ message: e.message });
    } finally {
        client.release();
    }
});
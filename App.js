const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://rfq-frontend-phi.vercel.app';
const JWT_SECRET = process.env.JWT_SECRET || 'britishRFQ';

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  }),
);

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: FRONTEND_URL,
    methods: ['GET', 'POST'],
  },
});

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    'postgresql://us-west-2.api.thenile.dev/v2/databases/019db60b-50a1-7466-8027-a076f50bc1df',
});

const EXTENSION_TRIGGERS = {
  BID_RECEIVED: 'bid_received_last_x',
  ANY_RANK_CHANGE: 'any_rank_change_last_x',
  L1_RANK_CHANGE: 'l1_rank_change_last_x',
};

const getAuctionStatus = (rfq) => {
  const now = new Date();
  if (now >= new Date(rfq.forced_close_time)) return 'Force Closed';
  if (now >= new Date(rfq.bid_close_time)) return 'Closed';
  return 'Active';
};

const authMiddleware = (roles = []) => (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authorization token missing' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    if (roles.length && !roles.includes(decoded.role)) {
      return res.status(403).json({ message: 'You are not allowed to perform this action' });
    }

    req.user = decoded;
    return next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const normalizeRanks = (bids) => {
  const sorted = [...bids].sort((a, b) => Number(a.total_amount) - Number(b.total_amount));
  return sorted.map((bid, index) => ({
    ...bid,
    rank: `L${index + 1}`,
  }));
};

const getSupplierRankMap = (rankedBids) =>
  rankedBids.reduce((acc, bid) => {
    acc[bid.supplier_id] = bid.rank;
    return acc;
  }, {});

const initializeDatabase = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) UNIQUE NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('buyer', 'supplier')),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rfqs (
      id SERIAL PRIMARY KEY,
      rfq_name VARCHAR(200) NOT NULL,
      reference_id VARCHAR(80) UNIQUE NOT NULL,
      buyer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      bid_start_time TIMESTAMP NOT NULL,
      bid_close_time TIMESTAMP NOT NULL,
      forced_close_time TIMESTAMP NOT NULL,
      pickup_service_date DATE NOT NULL,
      trigger_window_minutes INTEGER NOT NULL,
      extension_duration_minutes INTEGER NOT NULL,
      extension_trigger VARCHAR(40) NOT NULL,
      status VARCHAR(20) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bids (
      id SERIAL PRIMARY KEY,
      rfq_id INTEGER REFERENCES rfqs(id) ON DELETE CASCADE,
      supplier_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      carrier_name VARCHAR(150) NOT NULL,
      freight_charges NUMERIC(12,2) NOT NULL DEFAULT 0,
      origin_charges NUMERIC(12,2) NOT NULL DEFAULT 0,
      destination_charges NUMERIC(12,2) NOT NULL DEFAULT 0,
      transit_time VARCHAR(100) NOT NULL,
      quote_validity DATE NOT NULL,
      total_amount NUMERIC(12,2) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auction_logs (
      id SERIAL PRIMARY KEY,
      rfq_id INTEGER REFERENCES rfqs(id) ON DELETE CASCADE,
      event_type VARCHAR(50) NOT NULL,
      description TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
};

io.on('connection', (socket) => {
  socket.on('disconnect', () => {});
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query(`SELECT * FROM users WHERE name = $1`, [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid Username' });
    }

    const user = result.rows[0];
    const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: 'Invalid Password' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        role: user.role,
      },
      JWT_SECRET,
    );

    return res.status(200).json({
      message: 'User Logged In Successfully',
      token,
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
      },
    });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error.message}` });
  }
});

app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role = 'supplier' } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({
        message: 'All fields (name, email, password) are required',
      });
    }
    if (!['buyer', 'supplier'].includes(role)) {
      return res.status(400).json({ message: 'Role must be buyer or supplier' });
    }

    const existingUser = await pool.query(`SELECT name, email FROM users WHERE name = $1 OR email = $2`, [
      name,
      email,
    ]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Username or Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role`,
      [name, email, hashedPassword, role],
    );

    const user = newUser.rows[0];
    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET);

    return res.status(201).json({
      message: 'User registered successfully',
      token,
      user,
    });
  } catch (error) {
    return res.status(500).json({ message: `Error: ${error.message}` });
  }
});

app.post('/rfq/create', authMiddleware(['buyer']), async (req, res) => {
  try {
    const {
      rfq_name,
      reference_id,
      bid_start_time,
      bid_close_time,
      forced_bid_close_time,
      pickup_service_date,
      trigger_window_minutes,
      extension_duration_minutes,
      extension_trigger,
    } = req.body;

    if (
      !rfq_name ||
      !bid_start_time ||
      !bid_close_time ||
      !forced_bid_close_time ||
      !pickup_service_date ||
      !trigger_window_minutes ||
      !extension_duration_minutes ||
      !extension_trigger
    ) {
      return res.status(400).json({ message: 'Missing required British auction fields' });
    }

    const startTime = new Date(bid_start_time);
    const closeTime = new Date(bid_close_time);
    const forcedCloseTime = new Date(forced_bid_close_time);
    if (closeTime <= startTime) {
      return res.status(400).json({ message: 'Bid Close Date & Time must be after Bid Start Date & Time' });
    }
    if (forcedCloseTime <= closeTime) {
      return res.status(400).json({ message: 'Forced Bid Close Date & Time must be greater than Bid Close Date & Time' });
    }
    if (!Object.values(EXTENSION_TRIGGERS).includes(extension_trigger)) {
      return res.status(400).json({ message: 'Invalid extension trigger selected' });
    }

    const generatedReferenceId = reference_id || `RFQ-${Date.now()}`;

    const result = await pool.query(
      `INSERT INTO rfqs (
        rfq_name, reference_id, buyer_id, bid_start_time, bid_close_time, forced_close_time,
        pickup_service_date, trigger_window_minutes, extension_duration_minutes, extension_trigger, status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active')
      RETURNING *`,
      [
        rfq_name,
        generatedReferenceId,
        req.user.id,
        startTime,
        closeTime,
        forcedCloseTime,
        pickup_service_date,
        Number(trigger_window_minutes),
        Number(extension_duration_minutes),
        extension_trigger,
      ],
    );

    const newRFQ = result.rows[0];
    await pool.query(
      `INSERT INTO auction_logs (rfq_id, event_type, description)
       VALUES ($1,'rfq_created',$2)`,
      [newRFQ.id, `RFQ created with close at ${new Date(newRFQ.bid_close_time).toLocaleString()}`],
    );

    io.emit('new-rfq', {
      id: newRFQ.id,
      rfq_name: newRFQ.rfq_name,
      reference_id: newRFQ.reference_id,
      bid_close_time: newRFQ.bid_close_time,
      forced_close_time: newRFQ.forced_close_time,
      auction_status: getAuctionStatus(newRFQ),
      lowest_bid: 0,
    });

    return res.status(201).json(newRFQ);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get('/rfq/all', authMiddleware(['buyer', 'supplier']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        r.*,
        u.name AS buyer_name,
        COALESCE(MIN(b.total_amount), 0) AS lowest_bid
      FROM rfqs r
      JOIN users u ON r.buyer_id = u.id
      LEFT JOIN bids b ON r.id = b.rfq_id
      GROUP BY r.id, u.name
      ORDER BY r.created_at DESC
    `);

    const auctions = result.rows.map((rfq) => ({
      ...rfq,
      auction_status: getAuctionStatus(rfq),
    }));

    return res.json(auctions);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get('/supplier/rfqs', authMiddleware(['supplier']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        r.*,
        COALESCE(MIN(b.total_amount), 0) AS lowest_bid
      FROM rfqs r
      LEFT JOIN bids b ON r.id = b.rfq_id
      GROUP BY r.id
      ORDER BY r.created_at DESC
    `);

    const activeAuctions = result.rows
      .map((rfq) => ({ ...rfq, auction_status: getAuctionStatus(rfq) }))
      .filter((rfq) => rfq.auction_status === 'Active');

    return res.json(activeAuctions);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get('/rfq/:id', authMiddleware(['buyer', 'supplier']), async (req, res) => {
  try {
    const { id } = req.params;
    const rfqResult = await pool.query(
      `SELECT r.*, u.name AS buyer_name
       FROM rfqs r JOIN users u ON r.buyer_id = u.id
       WHERE r.id = $1`,
      [id],
    );
    if (!rfqResult.rows.length) {
      return res.status(404).json({ message: 'RFQ not found' });
    }

    const rfq = rfqResult.rows[0];
    const bidResult = await pool.query(
      `SELECT b.*, u.name AS supplier_name
       FROM bids b JOIN users u ON b.supplier_id = u.id
       WHERE b.rfq_id = $1
       ORDER BY b.total_amount ASC, b.created_at ASC`,
      [id],
    );
    const rankedBids = normalizeRanks(bidResult.rows);
    const logsResult = await pool.query(
      `SELECT * FROM auction_logs WHERE rfq_id = $1 ORDER BY created_at DESC`,
      [id],
    );

    return res.json({
      ...rfq,
      auction_status: getAuctionStatus(rfq),
      bids: rankedBids,
      logs: logsResult.rows,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post('/supplier/bid', authMiddleware(['supplier']), async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      rfq_id,
      carrier_name,
      freight_charges = 0,
      origin_charges = 0,
      destination_charges = 0,
      transit_time,
      quote_validity,
      amount,
    } = req.body;

    if (!rfq_id || !carrier_name || !transit_time || !quote_validity || !amount) {
      return res.status(400).json({ message: 'Missing bid fields' });
    }

    await client.query('BEGIN');
    const rfqRes = await client.query(`SELECT * FROM rfqs WHERE id = $1 FOR UPDATE`, [rfq_id]);
    if (!rfqRes.rows.length) {
      throw new Error('RFQ not found');
    }
    const rfq = rfqRes.rows[0];
    const now = new Date();

    if (getAuctionStatus(rfq) !== 'Active') {
      throw new Error('RFQ is not active');
    }
    if (now < new Date(rfq.bid_start_time)) {
      throw new Error('Bidding has not started yet');
    }

    const bidBeforeRes = await client.query(
      `SELECT supplier_id, total_amount, created_at
       FROM bids WHERE rfq_id = $1
       ORDER BY total_amount ASC, created_at ASC`,
      [rfq_id],
    );
    const previousRankedBids = normalizeRanks(bidBeforeRes.rows);
    const previousRankMap = getSupplierRankMap(previousRankedBids);
    const previousL1Supplier = previousRankedBids[0]?.supplier_id || null;
    const lowestBid = previousRankedBids[0]?.total_amount ? Number(previousRankedBids[0].total_amount) : null;
    const numericAmount = Number(amount);
    if (lowestBid !== null && numericAmount >= lowestBid) {
      throw new Error('Bid amount must be lower than current lowest bid');
    }

    await client.query(
      `INSERT INTO bids (
        rfq_id, supplier_id, carrier_name, freight_charges, origin_charges, destination_charges,
        transit_time, quote_validity, total_amount
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        rfq_id,
        req.user.id,
        carrier_name,
        Number(freight_charges),
        Number(origin_charges),
        Number(destination_charges),
        transit_time,
        quote_validity,
        numericAmount,
      ],
    );

    await client.query(
      `INSERT INTO auction_logs (rfq_id, event_type, description)
       VALUES ($1, 'bid_submitted', $2)`,
      [rfq_id, `Supplier ${req.user.name} submitted bid ${numericAmount}`],
    );

    const bidAfterRes = await client.query(
      `SELECT supplier_id, total_amount, created_at
       FROM bids WHERE rfq_id = $1
       ORDER BY total_amount ASC, created_at ASC`,
      [rfq_id],
    );
    const currentRankedBids = normalizeRanks(bidAfterRes.rows);
    const currentRankMap = getSupplierRankMap(currentRankedBids);
    const currentL1Supplier = currentRankedBids[0]?.supplier_id || null;

    const rankChangedForAnySupplier = Object.keys(currentRankMap).some(
      (supplierId) => previousRankMap[supplierId] && previousRankMap[supplierId] !== currentRankMap[supplierId],
    );
    const l1Changed = previousL1Supplier && currentL1Supplier && previousL1Supplier !== currentL1Supplier;
    const minutesToClose = (new Date(rfq.bid_close_time) - now) / 60000;
    const withinTriggerWindow = minutesToClose >= 0 && minutesToClose <= Number(rfq.trigger_window_minutes);

    let shouldExtend = false;
    let extensionReason = '';
    if (withinTriggerWindow) {
      if (rfq.extension_trigger === EXTENSION_TRIGGERS.BID_RECEIVED) {
        shouldExtend = true;
        extensionReason = 'Bid received in the trigger window';
      } else if (rfq.extension_trigger === EXTENSION_TRIGGERS.ANY_RANK_CHANGE && rankChangedForAnySupplier) {
        shouldExtend = true;
        extensionReason = 'Supplier rank changed in the trigger window';
      } else if (rfq.extension_trigger === EXTENSION_TRIGGERS.L1_RANK_CHANGE && l1Changed) {
        shouldExtend = true;
        extensionReason = 'Lowest bidder (L1) changed in the trigger window';
      }
    }

    let extendedTo = null;
    if (shouldExtend) {
      const proposedClose = new Date(new Date(rfq.bid_close_time).getTime() + Number(rfq.extension_duration_minutes) * 60000);
      const forcedClose = new Date(rfq.forced_close_time);
      const newClose = proposedClose > forcedClose ? forcedClose : proposedClose;

      if (newClose > new Date(rfq.bid_close_time)) {
        await client.query(`UPDATE rfqs SET bid_close_time = $1 WHERE id = $2`, [newClose, rfq_id]);
        extendedTo = newClose;
        await client.query(
          `INSERT INTO auction_logs (rfq_id, event_type, description)
           VALUES ($1,'time_extended',$2)`,
          [rfq_id, `${extensionReason}. Bid close moved to ${newClose.toLocaleString()}`],
        );
      }
    }

    await client.query('COMMIT');

    io.emit('new-bid', {
      rfq_id: Number(rfq_id),
      amount: numericAmount,
      supplier_id: req.user.id,
    });
    io.emit('rfq-updated', { rfq_id: Number(rfq_id) });

    return res.json({
      message: 'Bid placed successfully',
      extended_to: extendedTo,
    });
  } catch (error) {
    await client.query('ROLLBACK');
    return res.status(400).json({ message: error.message });
  } finally {
    client.release();
  }
});

initializeDatabase()
  .then(() => {
    const port = process.env.PORT || 3001;
    server.listen(port, () => {
      console.log(`Server Started at port ${port}`);
    });
  })
  .catch((error) => {
    console.error('Database initialization failed:', error.message);
    process.exit(1);
  });
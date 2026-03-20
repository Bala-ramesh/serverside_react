const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
require('dotenv').config();

app.set('trust proxy', 1);

// Setup DOMPurify to clean inputs
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const app = express();

// --- 1. SECURITY MIDDLEWARE ---
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'Too many requests, please try again after 15 minutes.' }
});

// --- 2. CORS ---
const allowedOrigins = [
    'http://localhost:3000',   // Standard React (npm start)
    'http://localhost:5173',   // Standard Vite (npm run dev)
    'http://127.0.0.1:3000',    // Some systems use IP instead of "localhost"
    'https://bala-ramesh.github.io',
    'https://bala-ramesh.github.io/React_web' // <--- Add this!
    ].filter(Boolean);


app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['POST'],
  credentials: true
}));

// --- 3. NODEMAILER ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// --- 4. THE SECURE ROUTE ---
app.post('/send-email', contactLimiter, async (req, res) => {
  // Pull data out
  const { name, email, subject, message } = req.body;

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  // MANUALLY SANITIZE: Scrub any HTML/Scripts from the user's text
  const cleanName = DOMPurify.sanitize(name);
  const cleanSubject = DOMPurify.sanitize(subject);
  const cleanMessage = DOMPurify.sanitize(message);

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER,
    replyTo: email,
    subject: `Portfolio Contact: ${cleanSubject} from ${cleanName}`,
    text: `New message from ${cleanName} (${email}):\n\n${cleanMessage}`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully!' });
  } catch (error) {
    console.error('SMTP Error:', error);
    res.status(500).json({ message: 'Server error: Failed to send email.' });
  }
});

const PORT = process.env.PORT || 5001;

// Adding '0.0.0.0' allows Railway to route external traffic to your app
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is live and listening on port ${PORT}`);
});
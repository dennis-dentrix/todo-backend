const express = require("express");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require('path');

const globalErrorHandler = require("./controllers/errorController");
const listRouter = require("./routes/listRoutes");
const userRouter = require("./routes/userRoute");
const AppError = require("./utils/appError");

const app = express();
// BODY PARSER
app.use(express.json({ limit: "10kb" }));
app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, 'views'));

app.set('trust proxy', true);

// Define allowed origins based on environment
const allowedOrigins = [
  "http://localhost:5173", // Development origin
  "https://todolist-web-3j2j.onrender.com",
];

const corsOptions = {
  origin: allowedOrigins,
  credentials: true, // Allow cookies, authorization headers, etc.
  methods: ['GET', 'POST', 'PATCH', 'DELETE']
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(cookieParser())

app.use(helmet());

// RATE LIMITING(requests per set time limit)
const rateLimiter = rateLimit({
  windowMs: 20 * 60 * 1000, 
  max: 100, 
  message: "Too many requests. Please try again later",
});

app.use("/api", rateLimiter);


// DATA SANITIZATION
app.use(mongoSanitize());
app.use(xss());

app.use(compression());

app.use("/api/v1/list", listRouter);
app.use("/api/v1/users", userRouter);


app.use("*", (req, res, next) => {
  return next(
    new AppError(`The requested url ${req.originalUrl} can't be found`)
  );
});

app.use(globalErrorHandler);

module.exports = app;

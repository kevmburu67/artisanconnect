// Dependencies
const express = require("express");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const Stripe = require("stripe");
const paypal = require("@paypal/checkout-server-sdk");
const { check, validationResult } = require("express-validator");

dotenv.config();

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// PayPal SDK Setup
const paypalClient = new paypal.core.PayPalHttpClient(new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
));

// Middleware setup
app.use(helmet()); // Security headers
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'mysecretkey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS in production
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Set the directory for uploaded files
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Use a unique file name
    }
});
const upload = multer({ storage: storage });

// MySQL Connection
const connection = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "kinyua",
    database: process.env.DB_NAME || "artisanke"
});

connection.connect(error => {
    if (error) {
        console.error("Error connecting to the database:", error);
        process.exit(1); // Gracefully shut down the server
    }
    console.log("Connected to the database successfully!");
});

// Serve the signup page
app.get("/", (req, res) => {
    res.render("signup");
});

// Serve the login page
app.get("/login", (req, res) => {
    res.render("index");
});

// Handle user signup
app.post("/signup", [
    check("username").notEmpty().withMessage("Username is required"),
    check("password").notEmpty().withMessage("Password is required"),
    check("role").notEmpty().withMessage("Role is required"),
    check("phone_number").notEmpty().withMessage("Phone number is required")
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).render('signup', { errors: errors.array() });
    }

    const { username, password, role, phone_number } = req.body;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("Error hashing the password:", err);
            return res.status(500).send("Internal server error");
        }

        const query = "INSERT INTO users (username, password, role, phone_number) VALUES (?, ?, ?, ?)";
        connection.query(query, [username, hashedPassword, role, phone_number], (error, results) => {
            if (error) {
                console.error("Error during the sign-up query:", error);
                return res.status(500).send("Internal server error");
            }
            console.log("User signed up successfully:", results);
            res.redirect("/login");
        });
    });
});

// Handle user login
app.post("/login", [
    check("username").notEmpty().withMessage("Username is required"),
    check("password").notEmpty().withMessage("Password is required")
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).render('login', { errors: errors.array() });
    }

    const { username, password } = req.body;

    const query = "SELECT * FROM users WHERE username = ?";
    connection.query(query, [username], (error, results) => {
        if (error) {
            console.error("Error during the login query:", error);
            return res.status(500).send("Internal server error");
        }
        if (results.length > 0) {
            const user = results[0];
            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    console.error("Error comparing passwords:", err);
                    return res.status(500).send("Internal server error");
                }
                if (result) {
                    console.log("User logged in successfully:", user);
                    req.session.user = user;
                    if (user.role === 'buyer') {
                        return res.redirect('/views/buyer-dashboard');
                    } else if (user.role === 'artisan') {
                        return res.redirect(`/views/artisan-dashboard?username=${user.username}`);
                    } else {
                        console.error("Invalid user role:", user.role);
                        return res.status(403).send("Forbidden: Invalid user role");
                    }
                } else {
                    return res.status(401).render('login', { errors: [{ msg: "Incorrect username or password" }] });
                }
            });
        } else {
            return res.status(401).render('login', { errors: [{ msg: "Incorrect username or password" }] });
        }
    });
});

// Handle product upload
app.post("/upload-product", upload.single('productImage'), [
    check("productName").notEmpty().withMessage("Product name is required"),
    check("productDescription").notEmpty().withMessage("Product description is required"),
    check("price").notEmpty().withMessage("Price is required"),
    check("username").notEmpty().withMessage("Username is required")
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(errors.array());
    }

    const { productName, productDescription, price, username } = req.body;
    const productImage = req.file ? req.file.filename : null;

    const query = "INSERT INTO products (product_name, product_description, price, username, product_image) VALUES (?, ?, ?, ?, ?)";
    connection.query(query, [productName, productDescription, price, username, productImage], (error, results) => {
        if (error) {
            console.error("Error during the product upload query:", error);
            return res.status(500).send("Internal server error");
        }
        console.log("Product uploaded successfully:", results);
        res.redirect(`/views/artisan-dashboard?username=${username}`);
    });
});

// Render the buyer dashboard with search functionality
app.get("/views/buyer-dashboard", (req, res) => {
    const searchQuery = req.query.q ? `%${req.query.q}%` : '%';
    const query = "SELECT * FROM products WHERE product_name LIKE ? OR product_description LIKE ?";
    connection.query(query, [searchQuery, searchQuery], (error, results) => {
        if (error) {
            console.error("Error fetching products:", error);
            return res.status(500).send("Internal server error");
        }
        res.render("buyer-dashboard", { products: results, searchQuery: req.query.q || '' });
    });
});

// Render the artisan dashboard with product list
app.get("/views/artisan-dashboard", (req, res) => {
    const username = req.query.username;
    const query = "SELECT * FROM products WHERE username = ?";
    connection.query(query, [username], (error, results) => {
        if (error) {
            console.error("Error fetching products for artisan:", error);
            return res.status(500).send("Internal server error");
        }
        res.render("artisan-dashboard", { products: results, username: username });
    });
});

// Handle product deletion
app.post("/delete-product", [
    check("productId").notEmpty().withMessage("Product ID is required"),
    check("username").notEmpty().withMessage("Username is required")
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(errors.array());
    }

    const { productId, username } = req.body;

    const query = "DELETE FROM products WHERE id = ? AND username = ?";
    connection.query(query, [productId, username], (error, results) => {
        if (error) {
            console.error("Error deleting product:", error);
            return res.status(500).send("Internal server error");
        }
        console.log("Product deleted successfully:", results);
        res.redirect(`/views/artisan-dashboard?username=${username}`);
    });
});

// Render the checkout page for Stripe payment
app.get("/checkout-stripe", (req, res) => {
    const productId = req.query.productId;
    const query = "SELECT * FROM products WHERE id = ?";
    connection.query(query, [productId], (error, results) => {
        if (error) {
            console.error("Error fetching product details:", error);
            return res.status(500).send("Internal server error");
        }
        if (results.length === 0) {
            return res.status(404).send("Product not found");
        }
        const product = results[0];
        res.render("checkout-stripe", { product: product, stripePublicKey: process.env.STRIPE_PUBLIC_KEY });
    });
});

// Render the checkout page for PayPal payment
app.get("/checkout-paypal", (req, res) => {
    const productId = req.query.productId;
    const query = "SELECT * FROM products WHERE id = ?";
    connection.query(query, [productId], (error, results) => {
        if (error) {
            console.error("Error fetching product details:", error);
            return res.status(500).send("Internal server error");
        }
        if (results.length === 0) {
            return res.status(404).send("Product not found");
        }
        const product = results[0];
        res.render("checkout-paypal", { product: product, paypalClientId: process.env.PAYPAL_CLIENT_ID });
    });
});

// Handle Stripe payment
app.post("/stripe-payment", async (req, res) => {
    const { productId, token } = req.body;

    try {
        const query = "SELECT * FROM products WHERE id = ?";
        connection.query(query, [productId], async (error, results) => {
            if (error) {
                console.error("Error fetching product details:", error);
                return res.status(500).send("Internal server error");
            }
            if (results.length === 0) {
                return res.status(404).send("Product not found");
            }
            const product = results[0];

            const charge = await stripe.charges.create({
                amount: Math.round(product.price * 100), // Stripe amount in cents
                currency: "usd",
                description: product.product_description,
                source: token
            });

            console.log("Payment successful:", charge);
            res.send("Payment successful");
        });
    } catch (error) {
        console.error("Error processing Stripe payment:", error);
        res.status(500).send("Internal server error");
    }
});

// Handle PayPal payment
app.post("/paypal-payment", async (req, res) => {
    const { productId, orderId } = req.body;

    const request = new paypal.orders.OrdersGetRequest(orderId);
    try {
        const order = await paypalClient.execute(request);
        const query = "SELECT * FROM products WHERE id = ?";
        connection.query(query, [productId], async (error, results) => {
            if (error) {
                console.error("Error fetching product details:", error);
                return res.status(500).send("Internal server error");
            }
            if (results.length === 0) {
                return res.status(404).send("Product not found");
            }
            const product = results[0];
            if (order.result.purchase_units[0].amount.value == product.price) {
                console.log("Payment successful:", order);
                res.send("Payment successful");
            } else {
                console.error("Payment amount mismatch");
                res.status(400).send("Payment amount mismatch");
            }
        });
    } catch (error) {
        console.error("Error processing PayPal payment:", error);
        res.status(500).send("Internal server error");
    }
});

// Handle user logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Error destroying session during logout:", err);
            return res.status(500).send("Internal server error");
        }
        res.redirect('/login');
    });
});

// Serve the portfolio page for artisans
app.get("/views/portfolio", (req, res) => {
    const username = req.query.username;
    const query = "SELECT * FROM users WHERE username = ?";
    connection.query(query, [username], (error, results) => {
        if (error) {
            console.error("Error fetching user details for portfolio:", error);
            return res.status(500).send("Internal server error");
        }
        if (results.length > 0) {
            const user = results[0];
            res.render("portfolio", { user: user });
        } else {
            return res.status(404).send("User not found");
        }
    });
});

// Handle portfolio updates
app.post("/update-portfolio", [
    check("username").notEmpty().withMessage("Username is required"),
    check("bio").notEmpty().withMessage("Bio is required"),
    check("skills").notEmpty().withMessage("Skills are required")
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(errors.array());
    }

    const { username, bio, skills } = req.body;

    const query = "UPDATE users SET bio = ?, skills = ? WHERE username = ?";
    connection.query(query, [bio, skills, username], (error, results) => {
        if (error) {
            console.error("Error updating portfolio:", error);
            return res.status(500).send("Internal server error");
        }
        console.log("Portfolio updated successfully:", results);
        res.redirect(`/views/artisan-dashboard?username=${username}`);
    });
});

// Start the server
const port = process.env.PORT || 5500;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

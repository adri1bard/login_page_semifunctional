const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

const initializePassport = require('./passport-config');
initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
);

const users = [];

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret', // Use a default secret for development
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(express.static('views'));
// Route for the homepage. Check if the user is authenticated before rendering the page.
app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name }) // Pass the user's name to the index view
})

// Route for the login page. Check if the user is not authenticated before rendering the login form.
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

// Handle the login form submission. Use Passport's local strategy for authentication.
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/', // Redirect to the homepage after successful login
    failureRedirect: '/login',
    failureFlash: true
}));

// Route for the registration page. Check if the user is not authenticated before rendering the registration form.
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = {
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        };
        users.push(newUser);
        req.login(newUser, err => {
            if (err) {
                return res.redirect('/login');
            }
            res.redirect('/login'); // Redirect to the login page after successful registration
        });
    } catch {
        res.redirect('/register');
    }
});

// Handle the logout action. This will log out the user and redirect to the login page.
app.delete('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
})

// Middleware function to check if the user is authenticated. If not, redirect to the login page.
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }

    res.redirect('/login')
}

// Middleware function to check if the user is not authenticated. If authenticated, redirect to the homepage.
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }
    next()
}

// Start the server and listen on port 3000
app.listen(80)

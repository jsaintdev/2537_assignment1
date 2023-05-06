//Imports the necessary modules
require("./utils.js");

require('dotenv').config();
const url = require('url');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

// Creates an instance of express. 'app' will define routes and handle server requests
const app = express();

const Joi = require("joi");

// Expires after 1 hour
const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* end secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}
));

// Sets the port number for the application
const port = process.env.PORT || 3000;

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Admin", link: "/admin"}
]

// Home Page
app.get('/', (req, res) => {
    const isAuthenticated = req.session.authenticated || false;
    const name = req.session.name || '';

    res.render('index', { authenticated: isAuthenticated, userName: name, navLinks: navLinks, currentURL: url.parse(req.url).pathname });
});

// noSQL Injection code
app.get('/nosql-injection', async (req, res) => {
    var email = req.query.email;

    if (!email) {
        res.render('nosql-injection', { emailProvided: false, attackDetected: false, result: null });
        return;
    }
    console.log("email: " + email);

    const schema = Joi.string().email().max(50).required();
    const validationResult = schema.validate(email);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('nosql-injection', { emailProvided: true, attackDetected: true, result: null });
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.render('nosql-injection', { emailProvided: true, attackDetected: false, result: result[0] });
});

// Form for creating user with name, email, and password
app.get('/signUp', (req, res) => {

    res.render("signup", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});


// Creates login page
app.get('/login', (req, res) => {

    res.render("login", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    let missingFields = "";
    if (!name) missingFields += "<br>Name is required";
    if (!email) missingFields += "<br>Email is required";
    if (!password) missingFields += "<br>Password is required";

    if (missingFields) {
        res.render('signup-submit', { missingFields: missingFields });
        return;
    }

    const schema = Joi.object(
        {
            name: Joi.string().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({name, email, password});
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signUp");
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
    console.log("Successfully created user");

    // Log in the user
    req.session.authenticated = true;
    req.session.name = name;

    res.redirect("/members");
});

// Checks if username and password are correct
app.post('/loggingin', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1}).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.render('logging-in', { invalidCredentials: true });
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.render('logging-in', { invalidCredentials: true });
        return;
    }
});

// Logs the user out
app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
})

// Creates member page with a random pic of one of my girls <3
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    res.render('members', {name: req.session.name, navLinks: navLinks, currentURL: url.parse(req.url).pathname})
});

// Serves static files to the client-side browser
app.use(express.static(__dirname + "/public"));

// Creates a 404 page
app.get("*", (req, res) => {
    res.status(404);
    res.render("404", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

//
app.listen(port, () => {
    console.log("Node app listening on port " +port);
});
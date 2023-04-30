//Imports the necessary modules
require("./utils.js");

require('dotenv').config();
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

// Home Page
app.get('/', (req, res) => {
    let html = "";

    if (req.session.authenticated) {
        const name = req.session.name || '';
        html = `Hello ${name}!
        <form action='/members' method='get'>
        <button>Go to Members Area</button>
        </form>
        <form action='/logout' method='get'>
        <button>Log out</button>
        </form>
        `;
    } else {
        html = `
        <form action='/signUp' method='get'>
        <button>Sign Up</button>
        </form>
        <form action='/logIn' method='get'>
        <button>Log in</button>
        </form>
        `;
    }

    res.send(html);
});

// noSQL Injection code
app.get('/nosql-injection', async (req, res) => {
    var email = req.query.email;

    if (!email) {
        res.send(`<h3>No email provided - try /nosql-injection?email=email@example.com</h3> <h3>or /nosql-injection?email[$ne]=email@example.com</h3>`);
        return;
    }
    console.log("email: " + email);

    const schema = Joi.string().email().max(50).required();
    const validationResult = schema.validate(email);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${result[0].name}</h1>`);
});

// Form for creating user with name, email, and password
app.get('/signUp', (req, res) => {

    const html = `
    Create user
    <form action='/signupSubmit' method='post'>
    <input name='name' type='text' placeholder='Name'><br>
    <input name='email' type='email' placeholder='Email'><br>
    <input name='password' type='password' placeholder='Password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


// Creates login page
app.get('/login', (req, res) => {
    var html = `
    Log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


// Lists existing users
app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    let missingFields = "";
    if (!name) missingFields += "<br>Name is required";
    if (!email) missingFields += "<br>Email is required";
    if (!password) missingFields += "<br>Password is required";

    if (missingFields) {
        const html = `
        ${missingFields}
        <br><a href='/signUp'>Try Again</a>
        `;
        res.send(html);
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
        const html = `
        Invalid email/password combination
        <br><a href='/login'>Try Again</a>
        `;
        res.send(html);
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
        const html = `
        Invalid email/password combination
        <br><a href='/login'>Try Again</a>
        `;
        res.send(html);
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

    const catImages = [
        { id: 1, src: '/Adria.jpg' },
        { id: 2, src: '/KitKat.jpg' },
        { id: 3, src: '/Roe.jpg' },
    ];

    const randomCat = catImages[Math.floor(Math.random() * catImages.length)];

    const html = `
        <h1>Hello, ${req.session.name}.</h1>
        <img src='${randomCat.src}' style='width:250px;'>
        <br>
        <form action='/logout' method='get'>
            <button>Sign out</button>
        </form>
    `;

    res.send(html);
});


// Serves static files to the client-side browser
app.use(express.static(__dirname + "/public"));

// Creates a 404 page
app.get("*", (req, res) => {
    res.status(404);
    res.send('Page not found -- <span style="color: red;">404</span>');
});

//
app.listen(port, () => {
    console.log("Node app listening on port " +port);
});
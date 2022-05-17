require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs  = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption'); // Used in level 2
// const md5 = require('md5'); //Used in level 3
// const bcrypt = require('bcrypt'); // Level 4
// const saltRounds = 10; // Level 4
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose'); 
const { use } = require('passport/lib');

const app = express();

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

// Setup the session with some configuration and tell the app to use it
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

// Initialise and setup passport to deal with/ manage those  sessions
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

// Setup passport-local-mongoose and add it as plugin to schema
// This is used to salt and hash passwords and store data into the mongo database
userSchema.plugin(passportLocalMongoose);

// console.log(process.env.API_KEY);
// userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model('User', userSchema);
//Create a local strategy to authenticate users based on username and password
//Serialise and deserialise is used whenever passport is used
//Serialise (create cookie) and deserialise (open and fetch cookie contents) the user
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.get('/', function(req, res){
    res.render('home');
});

app.get('/register', function(req, res){
    res.render('register');
});

app.get('/login', function(req, res){
    res.render('login');
});

app.post('/login', function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    // A new user based on login credentials is created and then using login function of passport, we authenticate it
    // Err is generated if the user cant be found in database.
    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{ //Meaning user exists, so we proceed towards authenticating this user
            passport.authenticate("local")(req, res, function(){
                res.redirect('/secrets');
            });
        }
      });
});

app.post('/register', function(req, res){
    //Using passport-local-mongoose package to register a new user
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect('/register');
        }
        else{ //If no errors, we now authenticate our user using passport
            // Local here is the type of authentication, here we r using a local authentication
            passport.authenticate("local")(req, res, function(){ //This callback is triggered only if the authentication was successfull
                //Here, successfull authentication means the cookie was successfully created and now stores thisss user's login session.
                //Hence we redirect it to the secrets route NOT secrets PAGE (this function callback runs only when authentication successfull)
                res.redirect('/secrets'); //Here onwards we have a secret route itself cuz a logged in user should be able to access secrets page directly(as long as he's in his logged in session) without having to authenticate himself every single time.
            }); 
        }
    });
});

app.get('/secrets', function(req, res){
    //Any random user shouldnt be able to simply type /secrets and access it in his url.
    //We therefore use passport and sessions to ensure that only a logged in user is allowed to proceed further and view the secrets.
    if(req.isAuthenticated()){
        res.render('secrets'); 
    } else{ //Send them to login before accessing secrets page
        res.redirect('/login');
    }
});

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});

app.get('/submit', function(req, res){
    res.render('submit');
});

app.listen(3000, function(){
    console.log("Server started on port 3000");
})



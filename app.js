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
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')


const app = express(); 

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

// Setup the session with some configuration and tell the app to use it
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));

// Initialise and setup passport to deal with/ manage those  sessions
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String, //Added in level 6 becuz users can now register via google or locally by giving username and password
    githubId: String,
    twitterId: String,
    facebookId: String,
    secrets: [{type: String}] //Way of specifying that each user can have an array of strings/secrets.
});

// Setup passport-local-mongoose and add it as plugin to schema
// This is used to salt and hash passwords and store data into the mongo database
userSchema.plugin(passportLocalMongoose);
// Add findOrCreate plugin for that function to work
userSchema.plugin(findOrCreate);

// console.log(process.env.API_KEY);
// userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model('User', userSchema);
//Create a local strategy to authenticate users based on username and password
//Serialise and deserialise is used whenever passport is used
//Serialise (create cookie) and deserialise (open and fetch cookie contents) the user
passport.use(User.createStrategy());
//These serialise and deserialise functions work for any authentication (not only local like previous commits)
// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
});
// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


// Facebook - Just put http://localhost:3000 in site url
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

// Twitter
passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_CONSUMER_KEY,
    consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
    callbackURL: "http://localhost:3000/auth/twitter/secrets"    // Notice how localhost isnt used here...even in twitter console make sure the same 127....is there as callback url character to character
  },
  function(token, tokenSecret, profile, cb) {
    User.findOrCreate({ twitterId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



// GITHUB
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET, 
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

// GOOGLE - see google developer console for site url and callback url
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        //This function adds a document for this user the first time they register via google and pther times, it finds
        //the dpcument by the google id of the user and authenticates it
      return cb(err, user);
    });
  }
));

app.get('/', function(req, res){
    res.render('home');
});

//Using the same passport library, many different stratergies of authenticating passwords can be implemented
//Initiate authentication with google by using google as stratergy, and also tell that we want profile of user 
// containing username and email id for storing in databse etc
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

//Users will be redirected to this path after they have authenticated with Google. 
//The path will be appended with the authorization code for access, 
//Here we are authenticating it locally!!! using google stratergy, if failure return to login otherwise secrets
//Here, successfull authentication means the cookie was successfully created and now stores thisss user's login session.
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login ' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
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
            // See /auth/google we use google stratergy
            passport.authenticate("local")(req, res, function(){ //This callback is triggered only if the authentication was successfull
                //Here, successfull authentication means the cookie was successfully created and now stores thisss user's login session.
                //Hence we redirect it to the secrets route NOT secrets PAGE (this function callback runs only when authentication successfull)
                res.redirect('/secrets'); //Here onwards we have a secret route itself cuz a logged in user should be able to access secrets page directly(as long as he's in his logged in session) without having to authenticate himself every single time.
            }); 
        }
    });
});

app.get('/secrets', function(req, res){
    //Any random user shouldnt be able to simply type /secrets and access it in his url. - Until Level 6
    //We therefore use passport and sessions to ensure that only a logged in user is allowed to proceed further and view the secrets. -Until Level 6
    // if(req.isAuthenticated()){
    //     res.render('secrets'); 
    // } else{ //Send them to login before accessing secrets page
    //     res.redirect('/login');
    // }

    // Finally we want an application wherein anybody can view the secrets (no need to even log in) as they will be viewing 
    // secrets by anonymous people. We only check for authentication when they want to submit a secret.
    // We search the database for all the users who have a secret/secrets associated with their document.
    // This means we search for documents having 'secrets' not null (exists:true) and also not empty that is atleast one secret they have  {$size: 0}.
    User.find({secret: { $exists: true, $not: {$size: 0} }}, function(err, foundUsers){
      if(err)console.log(err);
      else if(foundUsers){
        res.render('secrets', {users: foundUsers});
      }
    });

});

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});

app.get('/submit', function(req, res){
    // User must be authenticated before he gets access to submit his secret.
    if(req.isAuthenticated()){
      res.render('submit'); 
  } else{ //Send them to login before tehy can submit a secret.
      res.redirect('/login');
  }
});

app.post('/submit', function(req, res){
  const secret = req.body.secret;
  //req.user.id gives us the unique id of the users document. (That user who made post request to /submit route)
  //Passport automatically attaches the id of document(user) to the req whenever the user is logged in session and makes a post request.
  User.findById(req.user.id, function(err, user){
    if(err)console.log(err);
    else if(user){
      user.secrets.push(secret);
      user.save(function(){
        res.redirect('/secrets');
      });
    }
  });
});

app.listen(3000, function(){
    console.log("Server started on port 3000");
})



require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs  = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption'); // Used in level 2
// const md5 = require('md5'); //Used in level 3
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

// console.log(process.env.API_KEY);
// userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model('User', userSchema);

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
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({username: username}, function(err, user){
        if(err)console.log(err);
        else if(user){
            bcrypt.compare(password, user.password, function(err, result) {
                // result == true
                if(result === true) res.render('secrets');
            });
        }
        else console.log("Wrong password");
    });
});

app.post('/register', function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    bcrypt.hash(password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const user = new User({
            username: username,
            password: hash
        });
        user.save(function(err){
            if(err)console.log(err);
            else res.render('secrets');
        });
    });
});

app.get('/submit', function(req, res){
    res.render('submit');
});

app.listen(3000, function(){
    console.log("Server started on port 3000");
})



//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require('express-session')
const mongoose = require('mongoose');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();


app.use(session({
    secret:"Our little secrets",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB", {useUnifiedTopology: true, useNewUrlParser: true,useCreateIndex: true});


const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId:String,
    secret: [String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



const User = mongoose.model("User",userSchema);


passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENTID,
        clientSecret: process.env.Cilen_Secret,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.set('view engine', 'ejs');


app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.static("public"));

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));
app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });
app.route("/")
    .get(function (req,res) {
        res.render("home");
    })
app.route("/login")
    .get(function (req,res) {
        res.render("login");
    })
    .post(function(req,res) {
        const user = User ({
            username: req.body.username,
            password:req.body.password
        })
        req.login(user,function(err) {
            if(err) {
                res.redirect("/login");
            }else {
                passport.authenticate("local")(req,res,function (){
                    res.redirect("/secrets");
                })
            }
        })
    })
app.get("/secrets",function (req,res){


    User.find({"secret": {$ne:null}},function (err,result) {
        if(err) {
            res.redirect("/login");
        }else {
            if(result) {
                res.render("secrets",{submited:result})
            }
        }
    })
});


app.get("/logout",function (req,res) {
    req.logout();
    res.redirect("/");
})
app.get("/submit",function (req,res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    }else {
        res.redirect("/login");
    }
})
app.post("/submit",function (req,res) {
    const scretSubmit = req.body.secret;

    User.findById(req.user.id,function(err,result) {
        if(err) {
            res.redirect("/secrets");
        }else {
            result.secret.push(scretSubmit);
            result.save(function () {
                res.redirect("/secrets");
            });
        }
    })
})

app.route("/register")
    .get(function (req,res) {
        res.render("register");
    })
    .post(function(req,res) {
        User.register({username:req.body.username},req.body.password,function (err,user) {
            if(err) {
                res.redirect("/register");
            }else {
                passport.authenticate("local")(req,res,function (){
                    res.redirect("/secrets");
                })
            }
        })

    })

app.listen(3000, function() {
    console.log("Server started on port 3000");
});
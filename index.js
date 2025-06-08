import express from 'express';
import bodyParser from 'body-parser';
import env from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import { Strategy } from 'passport-local';
import passport from 'passport';
import rooms from './rooms.js';
import GoogleStrategy from 'passport-google-oauth2';

const app = express();
const port = process.env.port || 3000;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({

    secret: process.env.SECRET_WORD,
    resave: false,
    saveUninitialized: true,

    cookie: {

        maxAge: 1000 * 60 * 60 * 24

    }

}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({

    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT

});

db.connect();

app.get('/', (req, res) => {

    res.render('index.ejs');

});

app.get('/login', (req, res) => {

    res.render('login.ejs');

});

app.get('/register', (req, res) => {

    res.render('register.ejs');

});

app.get('/recreateaccount', async (req, res) => {

    res.render('recreateaccount.ejs');

});

app.get('/rooms', (req, res) => {

    if (req.isAuthenticated()) {
        
        res.render('room.ejs', {rooms});

    } else {
        
        res.redirect('/login');

    }

});

app.get('/admin', async (req, res) => {

    if (req.isAuthenticated()) {
        
        let adminDetails = await db.query("SELECT * FROM luser");
        let admin = [];
        admin = adminDetails.rows;
        res.render('admin.ejs', { admin });
        
    } else {
        
        res.redirect('/admin/login');

    }

});

app.get('/admindetails/id/:id', async (req, res) => {
    
    const deleteId = req.params.id;
    await db.query("DELETE FROM luser WHERE id = $1", [deleteId]);
    res.redirect('/admin');

});

app.get('/admin/login', (req, res) => {

    res.render('adminlogin.ejs');

});

app.get('/auth/google', passport.authenticate("google", {

    scope: ["profile", "email"],

}));

app.get('/auth/google/rooms', passport.authenticate("google", {

    successRedirect: '/rooms',
    failureRedirect: '/login',

}));

app.get('/logout', (req, res) => {

    req.logout((err) => {

        if (err) {
            
            console.log(err);

        } else {
            
            res.redirect('/admin/login');

        }

    })
   
})

app.post("/adminlogin", passport.authenticate("admin", {

    successRedirect: '/admin',
    failureRedirect: '/admin/login',

}));

passport.use("admin", new Strategy(async function verify(username, password, cb) {
    
    const checkAdmin = await db.query("SELECT * FROM lloginuser WHERE email = $1", [username]);

    if (checkAdmin.rows.length !== 0) {
        
        const adminDetails = checkAdmin.rows[0];
        const adminpass = adminDetails.password;

        bcrypt.compare(password, adminpass, (err, result) => {

            if (err) {
                
                return cb(err);

            } else {
                
                if (result) {
                    
                    return cb(null, adminDetails);

                } else {
                    
                    return cb(null, false);

                }

            }

        });

    } else {
        
        bcrypt.genSalt(12, (err, salt) => {

            if (err) {
                
                return cb(err);

            }

            bcrypt.hash(password, salt, async (err, hash) => {

                if (err) {
                    
                    return cb(err);

                }

                await db.query("INSERT INTO lloginuser(email, password) VALUES($1, $2)", [username, hash]);


            });

        });

    }

}));

app.post('/register', async (req, res) => {

    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const result = await db.query('SELECT * FROM luser WHERE email = $1', [email]);

    if (result.rows.length > 0) {
        
       res.redirect("/recreateaccount");

    } else {
        
        bcrypt.genSalt(12, async (err, salt) => {

            if (err) {
                
                console.log(err);

            }
                
            bcrypt.hash(password, salt, async (err, hash) => {

                if (err) {
                        
                    console.log(err);

                }

                let user = await db.query("INSERT INTO luser(name, email, password) VALUES($1, $2, $3) RETURNING *", [name, email, hash]);
                
                let registeredUser = user.rows[0];

                req.login(registeredUser, function (err) {
                    
                    if (err) {
                        
                        console.log(err);

                    } else {
                        
                        res.redirect('/rooms');

                    }

                });

            });

        })

    }

});

app.post('/login', passport.authenticate("local", {

    successRedirect: '/rooms',
    failureRedirect: '/login',

}));

passport.use("local", new Strategy(async function varify(username, password, cb) {
    
    const checkUser = await db.query("SELECT * FROM luser WHERE email = $1", [username]);

    if (checkUser.rows.length > 0) {
        
        let user = checkUser.rows[0];
        let pass = user.password;

        bcrypt.compare(password, pass, (err, result) => {
            
            if (err) {
                
                return cb(err);

            } else {
                
                if (result) {
                    
                    return cb(null, user);

                } else {
                    
                    return cb(null, false);

                }

            }

        });

    } else {
        
        cb('user not found');

    }

}));

passport.use(
  "google",
  new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    userProfileURL: process.env.USER_PROFILE_URL,
  },
  async (accessToke, refreshToken, profile, cb) => {
    const googleUser = await db.query("SELECT * FROM luser WHERE email = $1", [
      profile.email,
    ]);

    if (googleUser.rows.length === 0) {
      const newGoogleUser = await db.query(
        "INSERT INTO luser(name, email, password) VALUES($1, $2, $3)",
        [profile.given_name, profile.email, "google"]
      );
      return cb(null, newGoogleUser);
    } else {
      return cb(null, googleUser);
    }
  }
));

passport.serializeUser((user, cb) => {

    cb(null, user);

});

passport.deserializeUser((user, cb) => {

    cb(null, user);

});

app.listen(port, () => {

    console.log(`Server is started on ${port} port`);

});
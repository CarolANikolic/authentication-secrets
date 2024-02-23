import express from "express";
import bodyParser from "body-parser";
import queries from "./queries.js";
import db from "./db.js";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: 'TOPSECRET',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
  },
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.render('home.ejs');
});

app.get('/login', (req, res) => {
  res.render('login.ejs');
});

app.get('/register', (req, res) => {
  res.render('register.ejs');
});

app.get('/secrets', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('secrets.ejs')
  } else {
    res.redirect('/login')
  }
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  if (!email || !password) {
    return res.send('Email and password cannot be empty.');
  }

  try {
    const resultByEmail = await db.query(queries.queryByEmail, [email]);
    
    if (!resultByEmail.rows.length) {
      // Password Hashing
      bcrypt.hash(password, saltRounds, async (error, hash) => {
        if (error) {
          console.log('Error hashing password:', error);
        } else {
          await db.query(queries.insertUser, [email, hash])
          res.render('secrets.ejs');
        }
      });
    } else {
      res.send('Email alread exists. Try loggin in.')
    }
  } catch (error) {
    console.log('Error registering the user:', error);
    res.status(500).send('Internal server error.');
  }
});

app.post("/login", passport.authenticate('local', {
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));

passport.use(new Strategy(async function verify(username, password, cb) {
  try {
    const resultByEmail = await db.query(queries.queryByEmail, [username]);
    
    if (resultByEmail.rows.length) {
      const user = resultByEmail.rows[0];
      bcrypt.compare(password, user.password, (error, result) => {
        if(error) {
          return cb(error)
        } else {
          if (result) {
            return cb(null, user)
          } else {
            return cb(null, false)
          }
        }
      });
    } else {
      return cb('User not registered. Please, create an account.');
    }
    
  } catch (error) {
    return cb(error);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

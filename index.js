import express from "express";
import bodyParser from "body-parser";
import queries from "./queries.js";
import db from "./db.js";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth20";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config()

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
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

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  '/auth/google/secrets',
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get('/logout', (req, res) => {
  req.logout((error) => {
    if (error) console.log(error);
    res.redirect('/')
  })
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

// Local strategy for manual user authentication
passport.use('local', new Strategy(async function verify(username, password, cb) {
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

// Google strategy for oauth user authentication
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile._json.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile._json.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

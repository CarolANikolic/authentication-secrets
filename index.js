import express from "express";
import bodyParser from "body-parser";
import queries from "./queries.js";
import db from "./db.js";

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
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
      await db.query(queries.insertUser, [email, password])
      res.render('secrets.ejs');
    } else {
      res.send('Email alread exists. Try loggin in.')
    }
  } catch (error) {
    console.log('Error registering the user:', error);
    res.status(500).send('Internal server error.');
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  if (!email || !password) {
    return res.send('Email and password cannot be empty.');
  }

  try {
    const resultByEmail = await db.query(queries.queryByEmail, [email]);
    const resultByPassword = await db.query(queries.queryByPassword, [password]);

    if(!resultByPassword.rows.length) {
      return res.send('Wrong password. Try again.');
    }
    
    if (resultByEmail.rows.length && resultByPassword.rows.length) {
      const user = resultByEmail.rows[0];
      if (user.password === password) {
        res.render('secrets.ejs');
      } else {
        res.send('Wrong password. Try again.');
      }
    } else {
      res.send('User not registered. Please, create an account.');
    }
    
  } catch (error) {
    console.log('Error logging in the user:', error);
    res.status(500).send('Internal server error.');
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;


const port = process.env.PORT || 1020;

const app = express();

const Joi = require("joi");

app.set('view engine', 'ejs');
app.use(express.static("public"));

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
  secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get("/", (req, res) => {
  if (req.session.user) {
    var username = req.query.user;
    console.log(username);
    res.render("entry");
  } else {
    res.render("newentry");
    }
  });

  app.get('/nosql-injection', async (req,res) => {
    var name = req.query.user;
  
    if (!name) {
      res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
      return;
    }
    //console.log("user: "+name);
  
    const schema = Joi.string().max(100).required();
    const validationResult = schema.validate(name);
  
      var invalid = false;
    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) { 
          invalid = true;
        console.log(validationResult.error);
    //    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
    //    return;
    }	
      var numRows = -1;
      //var numRows2 = -1;
      try {
        const result = await userCollection.find({name: name}).project({username: 1, password: 1, _id: 1}).toArray();
        //const result2 = await userCollection.find("{name: "+name).project({username: 1, password: 1, _id: 1}).toArray(); //mongoDB already prevents using catenated strings like this
          //console.log(result);
          numRows = result.length;
          //numRows2 = result2.length;
      }
      catch (err) {
          console.log(err);
          res.send(`<h1>Error querying db</h1>`);
          return;
      }
  
      console.log(`invalid: ${invalid} - numRows: ${numRows} - user: `,name);
  
      // var query = {
      //     $where: "this.name === '" + req.body.username + "'"
      // }
  
      // const result2 = await userCollection.find(query).toArray(); //$where queries are not allowed.
      
      // console.log(result2);
  
      res.send(`<h1>Hello</h1> <h3> num rows: ${numRows}</h3>`); 
      //res.send(`<h1>Hello</h1>`);

  });
  
  app.get("/signup", (req, res) => {
    res.render("signup");
  });
  
  app.post("/signupSubmit", async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
  
    const schema = Joi.object({
      username: Joi.string().alphanum().max(20).required(),
      password: Joi.string().max(20).required(),
      email: Joi.string().email().required(),
    });
  
    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/signup");
      return;
    }
  
    var hashedPassword = await bcrypt.hash(password, saltRounds);
  
    await userCollection.insertOne({
      username: username,
      password: hashedPassword,
      email: email,
      user_type: "user",
    });
    console.log("User has been inserted");
  
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect("/members");
  });
  
  app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
      res.redirect("/");
      return;
    }
    
    res.render("members", { username: req.session.username });
  });
  

  app.get("/login", (req, res) => {
    const errorMsg = req.query.errorMsg;
    res.render("login", { errorMsg });
  });
  

app.post("/loginSubmit", async (req, res) => {
  
    var email = req.body.email;
    var password = req.body.password;
    
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required(),
    });
  
    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/login");
      return;
    }
    
    const result = await userCollection.find({email: email}).project({ email: 1, password: 1, _id: 1, username: 1 }).toArray();
    
    console.log(result);
    if (result.length != 1) {
      console.log("User is not found...");
      res.redirect("/login");
      return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
      console.log("right password");
      await userCollection.updateOne(
        { email: email },
        { $set: { user_type: "user" } }
      );
      req.session.authenticated = true;
      req.session.username = result[0].username;
      req.session.cookie.maxAge = expireTime;
      
      res.redirect("/members");
      return;
    } else {
      console.log("wrong password");
      res.redirect("/login?errorMsg=Invalid email/password combination.");
      return;
    }
  });
  

app.get("/login-wrong-password", (req, res) => {
  res.render("login-wrong-password");
});

app.get("/admin", (req, res) => {
  res.render("admin");
});
 
app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

const express = require("express");       // server framework
const app = express();
const mongoose = require("mongoose");     // MongoDB connection
const bcrypt = require("bcrypt");         // password hashing
const session = require("express-session"); // session management
const nodemailer = require("nodemailer"); // send email
require("dotenv").config();               // .env file load
const ejs = require("ejs");               // view engine (form render ke liye)

// apke khud ke models
const User = require("./models/user");
const Otp = require("./models/otp");
const notes = require("./models/notes");
const { ConnectionPoolMonitoringEvent } = require("mongodb");


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

//  Express Session Setup
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }, // 1 hour
    rolling: false,
  })
);

//  Nodemailer Transporter
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// OTP Generator
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
}

// ================= Routes =================

// Render registration page
app.get('/', (req, res) => {
  res.render('home');
})
app.get("/reg", (req, res) => {
  res.render("reg");
});

// Registration + Send OTP
app.post("/signup", async (req, res) => {
  try {
    const { name, dob, email,password } = req.body;
   

    let existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send( "User already registered" );
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create new user
   

    req.session.signupData = { name, dob, email, password:hashedPassword };

    const otp = generateOTP();

    // Save OTP in DB (expire after 5 minutes)
    await Otp.create({ email, otp, createdAt: new Date() });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Hi ${name}, your OTP is ${otp}. It will expire in 5 minutes.`,
    });

    // res.json({ message: "OTP sent successfully" });
    res.redirect("/verifyemail");
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /verifyemail
app.get("/verifyemail", (req, res) => {
  // Get user data from session
  const signupData = req.session.signupData;
  if (!signupData) return res.redirect("/reg"); // no data → go back to registration
  res.render("checkotp", { email: signupData.email });
});

// POST /verify-signup-otp
app.post("/verify-signup-otp", async (req, res) => {
  try {
    const { otp } = req.body;

    // Get signup data from session
    const signupData = req.session.signupData;
    if (!signupData) return res.status(400).send("Session expired. Please register again.");
  
    const { name, dob, email, password } = signupData;

    // Check OTP in DB
    const validOtp = await Otp.findOne({ email, otp });
    if (!validOtp) {
      return res.status(400).send("Invalid or expired OTP");
    }



    // Create user
    await User.create({
      name,
      dob,
      email,
      password,
      isVerified: true,
    });

    // Delete used OTP
    await Otp.deleteMany({ email });

    // Clear session data
    req.session.signupData = null;
    res.redirect('/Signin')
    // res.send("Registration successful! You can now login.");
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});


//-------------------------------------------------

app.get("/Signin",(req,res)=>{
  res.render('Signin');
})

app.post("/checkuser",async (req,res)=>{

const { email, password } = req.body;

    // check user exists
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send( "User not found" );

    // verify password
    const isMatch = await bcrypt.compare(password, user.password);
       if (!isMatch) return res.status(400).send("wrong email or password" );


    req.session.userId = user._id;
    req.session.email = user.email;

     res.redirect('/dashboard');

})






//-----------------------------------------


// Render login page
app.get("/verifyuser", (req, res) => {
  res.render("verify");
});

// POST /login-request
app.post("/login-request", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("User not registered");

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP in DB (5 min expiry)
    await Otp.create({ email, otp, createdAt: new Date() });

    // Send OTP via email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Login OTP",
      text: `Your login OTP is ${otp}. It expires in 5 minutes.`,
    });

    // Optionally, store email in session for OTP verification
    req.session.loginEmail = email;
    res.render('checkloginotp');
    // res.send("OTP sent to your email.");
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});


// POST /verify-login-otp
app.post("/verify-login-otp", async (req, res) => {
  try {
    const { otp } = req.body;
    const email = req.session.loginEmail;
    if (!email) return res.status(400).send("Session expired. Try login again.");

    // Check OTP in DB
    const validOtp = await Otp.findOne({ email, otp });
    if (!validOtp) return res.status(400).send("Invalid or expired OTP");

    // Get user
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("User not found");

    // Create session
    req.session.userId = user._id;
    req.session.email = user.email;

    // Delete OTP after use
    await Otp.deleteMany({ email });

    // Clear loginEmail session
    req.session.loginEmail = null;

    // res.send("Login successful! Session created.");
    res.redirect('/changepass');
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});


// ================= Middleware =================
const auth = (req, res, next) => {
  if (!req.session.userId) {
    // return res.status(401).json({ msg: "Not logged in" });
    return res.redirect('/Signin');
  }
  next();
};

// ================= Protected Route =================

app.get("/changepass", auth, async(req,res)=>{
 res.render('change');
})

app.post("/setpass",async(req,res)=>{
  try{

   const {password,cpassword}=req.body;
   if(password!=cpassword) return  res.status(500).send(" password not match enter correct password ");

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);
   
      await User.findByIdAndUpdate( req.session.userId, { password:hashedPassword });
      res.redirect('/Signin');

    // create new user
   

   


  }catch(err){
    res.status(500).json({ error: err.message });
  }
})





//---------------------




app.get("/dashboard", auth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select("-password");
    if (!user) return res.status(404).json({ msg: "User not found" });
    // res.json(user);
    const userNotes = await notes.find({ userId: user._id }).sort({ createdAt: -1 });
    res.render('dashboard', { user, userNotes });
  } catch (err) {
    res.status(500).json({ error: err.message });

  }
});


app.post('/notes', auth, async (req, res) => {
  try {

    const user = await User.findById(req.session.userId);
    const { Note_Title, Note_content } = req.body;
    

    const newNote = await notes.create({
      userId: user._id,
      Note_Title,
      Note_content,
    });

    req.session.notesId = newNote._id;
    res.redirect('/notestable');


  } catch (err) {
    res.status(500).json({ error: err.message });
  }
})

app.get('/notestable', auth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  const userNotes = await notes.find({ userId: user._id })
  res.render('notes', { user, userNotes });
})

app.post('/edit', auth, async (req, res) => {
  const { notesid } = req.body;
  const user = await User.findById(req.session.userId);
  const userNotes = await notes.findById(notesid)
  res.render('update', { user, userNotes });
})



// Update Note API
app.post('/update', auth, async (req, res) => {
  try {
    const { Note_Title, Note_content, notesid } = req.body;
    const userId = req.session.userId;

    // Sirf wahi note update ho jo current user ka hai
    const updatedNote = await notes.findOneAndUpdate( 
      { _id: notesid, userId },  // condition: noteId + owner check
      { Note_Title, Note_content },
      { new: true } // updated document return karega
    );

    if (!updatedNote) {
      return res.status(404).send("Note not found or you don't have permission to edit");
    }

    res.redirect('/notestable'); // update ke baad redirect
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});


app.post('/delete', auth, async (req, res) => {
  const { notesid } = req.body;

  await notes.findByIdAndDelete(notesid)
  res.redirect('/notestable');
})
// Logout
app.get("/logout", auth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ msg: "Logout failed" });
    res.clearCookie("connect.sid");
    // res.json({ msg: "Logged out successfully" });
    res.redirect('/');
  });
});

const PORT = process.env.PORT || 4000; // fallback sirf local ke liye

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

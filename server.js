import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({origin:"*"}));

const username = process.env.MONGO_USERNAME;
const password = encodeURIComponent(process.env.MONGO_PASSWORD);

const mongoURI = `mongodb+srv://${username}:${password}@cluster0.qd4iu.mongodb.net/testSeries?retryWrites=true&w=majority`;

mongoose
.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology:true,
})
.then(() => console.log("MongoDB Connected "))
.catch((err) => {
  console.error("MongoDB Connection Error:", err);
  process.exit(1);
});

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  mobile: {type:String, unique:true},
  password: String,
});

const User = mongoose.model("User", userSchema);

// Register API
app.post("/api/register", async (req, res) => {
  try {
    console.log("Request Body:", req.body);
    const { name, email, mobile, password, confirmPassword } = req.body;

    if(!name || !email || !mobile || !password || !confirmPassword){
      return res.status(400).json({ error: "All fields are required"});
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    const userExist = await User.findOne({email});
    if(userExist){
      return res.status(400).json({error:"Email already exists"});
    }

    const mobileExist = await User.findOne({ mobile });
    if (mobileExist) {
      return res.status(400).json({ error: "Mobile number already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({name, email, mobile, password: hashedPassword});
    await newUser.save();

    res.status(201).json({message: "User registered successfully"});

  } catch(err){
    console.error("Registration Error:", err);
    res.status(500).json({error: "Registration failed"});
  }
});

// Login API
app.post("/api/login", async (req, res) => {  
  try {
    const { email, password } = req.body;
    if(!email || !password){
      return res.status(400).json({error: "Email and password are required"});
    }

    const user = await User.findOne({email});
    if(!user){
      return res.status(400).json({error: "Invalid Email or Password"});
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch) {
      return res.status(400).json({error: "Invalid Email or Password"});
    }

    if(!process.env.JWT_SECRET){
      return res.status(500).json({error: "Server configuration error"});
    }

    const token = jwt.sign({id:user._id}, process.env.JWT_SECRET, {expiresIn: "1h"});

    res.json({token, user});

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/user", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Error fetching users" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));



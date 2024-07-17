import express from 'express';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from "cors";
import admin from 'firebase-admin';
import serviceAccountkey from './blog-56d43-firebase-adminsdk-c83a5-d78a99a082.json' assert { type: 'json' };

import { getAuth } from 'firebase-admin/auth';

//schema below
import User from './Schema/User.js';

const server = express();
const PORT = 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountkey),
});

const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true
});

const formatDatatoSend = (user) => {
  const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY);
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

const generateUsername = async (email) => {
  let username = email.split("@")[0];
  const isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => result);

  if (isUsernameNotUnique) {
    username += nanoid().substring(0, 5);
  }

  return username;
};

server.post("/signup", async (req, res) => {
  const { fullname, email, password } = req.body;

  //validating the data from frontend
  if (fullname.length < 3) {
    return res.status(403).json({ "error": "Fullname must be at least 3 letters long" });
  }
  if (!email.length) {
    return res.status(403).json({ "error": "Enter the email" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ "error": "Invalid email" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a numeric, 1 lowercase, and 1 uppercase" });
  }

  try {
    const hashed_password = await bcrypt.hash(password, 10);
    const username = await generateUsername(email);

    const user = new User({
      personal_info: { fullname, email, password: hashed_password, username }
    });

    const savedUser = await user.save();
    return res.status(200).json(formatDatatoSend(savedUser));
  } catch (err) {
    if (err.code === 11000) {
      return res.status(500).json({ "error": "Email already exists" });
    }
    return res.status(500).json({ "error": err.message });
  }
});

server.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ "personal_info.email": email });
    if (!user) {
      return res.status(403).json({ "error": "Email not found" });
    }

    const isMatch = await bcrypt.compare(password, user.personal_info.password);
    if (!isMatch) {
      return res.status(403).json({ "error": "Incorrect password" });
    }
    return res.status(200).json(formatDatatoSend(user));
  } catch (err) {
    return res.status(500).json({ "error": err.message });
  }
});

server.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;

  getAuth().verifyIdToken(access_token)
    .then(async (decodedUser) => {
      const { email, name, picture } = decodedUser;
      const formattedPicture = picture.replace("s96-c", "s384-c");

      const username = await generateUsername(email);

      let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullname personal_info.email personal_info.username personal_info.profile_img google_auth")
      .then((u) => {
        return u || null;
      })
      .catch(err => {
        return res.status(500).json({ "error": err.message });
      });

      if (!user) {
        user = new User({
          personal_info: { fullname: name, email, username, profile_img: formattedPicture },
          google_auth: true
        });
      }

      await user.save().then((u) => {
        user = u;
      })
      .catch(err => {
        return res.status(500).json({ "error": err.message });
      });

      return res.status(200).json(formatDatatoSend(user));
    })
    .catch(err => {
      return res.status(500).json({ "error": "Failed to authenticate you with Google. Try with another Google account." });
    });
});


server.listen(PORT, () => {
  console.log('listening on port -> ' + PORT);
});

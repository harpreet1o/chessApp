// routes/auth.js
import express from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { createUser, findUserByEmail, matchPassword, findUserById } from '../models/User.js';
import { getGamesByUserId } from '../models/games.js';
import config from '../config.js';

const secretKeyJWT=config.secretKeyJWT;
const cors=config.corsOrigin;

passport.use(new GoogleStrategy({
  clientID: config.googleClientId,
  clientSecret: config.googleClientSecret,
  callbackURL: 'http://chess2650.com:3000/oauth2/redirect/google',
  scope: ['profile', 'email', 'openid']
}, async (accessToken, refreshToken, profile, cb) => {
  try {
    // Extract user details from profile
    const newUser = {
      id: profile.id,
      email: profile.emails[0].value,
      name: profile.displayName,
    };

    // Check if the user already exists
    let user = await findUserById(profile.id);
    if (user) {
      // User already exists
      return cb(null, user);
    }

    // Create a new user if not found
    user = await createUser(newUser);
    return cb(null, user);
  } catch (err) {
    console.error("Error in Google Strategy:", err);
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  process.nextTick(() => {
    cb(null, user.id);
  });
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await findUserById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});


const router = express.Router();

// Utility function to generate JWT
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, secretKeyJWT, { expiresIn: '24h' });
};

// Middleware to authenticate the JWT token
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;

  if (token) {
    jwt.verify(token, secretKeyJWT, (err, decoded) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = decoded;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// User registration route
router.post('/register', (req, res) => {
  const { email, name, password } = req.body;

  findUserByEmail(email, (err, existingUser) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists.' });
    }

    const newUser = {
      id: uuidv4(),
      email,
      name,
      password
    };

    createUser(newUser, (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Internal server error.' });
      }
      const token = generateToken(user.id);
      res.cookie('token', token, { httpOnly: true, secure: false, same_Site: "none" });
      res.status(201).json({ message: "created succesfully" });
    });
  });
});

// User login route
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  findUserByEmail(email, (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }
    if (!user || !matchPassword(password, user.password)) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const token = generateToken(user.id);
    res.cookie('token', token, { httpOnly: true, secure: false, same_Site: "none" });
    res.json({ user, token });
  });
});

router.get('/login/federated/google', (req, res, next) => {
  if (req.cookies && req.cookies.token) {
    const token = req.cookies.token;
    jwt.verify(token, secretKeyJWT, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Failed to authenticate token.' });
      }
      findUserById(decoded.id, (err, user) => {
        if (err) {
          return res.status(500).json({ message: 'Internal server error.' });
        }
        if (user) {
          res.redirect(`http://chess2650.com`);
        }
        return next();
      });
    });
  } else {
    passport.authenticate('google')(req, res, next);
  }
});

router.get('/oauth2/redirect/google', passport.authenticate('google', {
  session: false,
  failureRedirect: 'http://chess2650.com/login'
}), (req, res) => {
  const token = generateToken(req.user.id);
  res.cookie('token', token, { httpOnly: true, secure: false, same_Site: "none" });
  res.redirect(`http://chess2650.com`);

});

router.post('/logout', (req, res) => {

  res.clearCookie('token', {
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    same_Site: 'None' // Ensure this matches the setting used when setting the cookie
  });
  res.json({message:"removed succesfully"});

});

// Route to get current user
router.get('/current_user', authenticateJWT, (req, res) => {
  findUserById(req.user.id, (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error.' });
    }
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json({ username: user.name });
  });

});

router.get('/user/profile', authenticateJWT, (req, res) => {
  try {
    findUserById(req.user.id, (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Internal server error.' });
      }
      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      };
      res.json(user);
    });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

router.get('/user/games', authenticateJWT, (req, res) => {
  try {
    getGamesByUserId(req.user.id, (err, games) => {
      if (err) {
        return res.status(500).json({ message: 'Internal server error.' });
      }
      res.json(games);
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

export default router;

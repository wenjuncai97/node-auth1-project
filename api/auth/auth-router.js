const express = require('express');
const router = express.Router();
const User = require('../users/users-model');
const bcrypt = require('bcryptjs');

const {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree
} = require('./auth-middleware')

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

  router.post('/register', checkPasswordLength, checkUsernameFree, (req, res, next) => {
    const {username, password} = req.body;
    const hash = bcrypt.hashSync(password, 8)

    User.add({username, password: hash})
      .then(saved => {
        res.status(201).json(saved)
      })
      .catch(next)
  })

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

  // router.post('/login', checkUsernameExists, (req, res, next) => {
  //   const {password} = req.body;
  //   if(bcrypt.compareSync(password, req.user.password)) {
  //     req.session.user = req.user;
  //     res.status(200).json({message: `Welcome ${req.user.username}!`})
  //   } else {
  //     next({status: 401, message: "Invalid credentials"});
  //     return;
  //   }
  // })
  router.post('/login', checkUsernameExists, (req, res) => {
    let {username, password} = req.body;    
    User.findBy({username})
    .then(user => {      
      if (user && bcrypt.compareSync(password, user[0].password)) {
      req.session.user = user[0];
      res.status(200).json({message: `Welcome ${user[0].username}`})
      } else {
        res.status(401).json({message: "Invalid credentials"})
      }
    })  
    .catch( err => res.status(500).json(err))
   })

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req, res) => {
    if(req.session.user) {
      delete req.session.user;
      res.status(200).json({message: "logged out"})
    } else [
      res.status(200).json({message: "no session"})
    ]
  })

  module.exports = router;
// Don't forget to add the router to the `exports` object so it can be required in other modules

var express = require('express');
var router = express.Router();
var passport = require('passport');
var jwt = require("jsonwebtoken"); 
var auth = require("../auth"); 

var env       = process.env.NODE_ENV || 'development';
var config    = require(__dirname + '/../config/config.json')[env];

router.post('/access_token', function(req, res) {
  if (req.body.username && req.body.password) {
     var payload = {
       id: req.body.username
     };
     var token = jwt.sign(payload, config.jwtSecret);
     res.json({
       access_token: token
     });
  } else {
     res.status(403).json({
       message: "access_denied"
     });
  }
});

router.get('/userinfo', auth.isAuthenticated, function(req, res) {
  res.json({
    id: req.user.id
  });
});

module.exports = router;

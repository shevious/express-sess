var express = require('express');
var router = express.Router();
var passport = require('passport');

router.get('/', function(req, res, next) {
  if (req.isAuthenticated()) {
    res.redirect('/');
  } else {
    res.render('login', { });
  }
});

router.post('/', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    if (!user) {
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      if (err) return next(err);
      if (!req.isAuthenticated()) {
         console.log('###################');
         console.log('not logged in yet!!!!!!')
      }
      return res.redirect('/');
    });
  })(req, res, next);
});

module.exports = router;

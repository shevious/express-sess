/*
 * Check the request if the user is authenticated.
 * Return an error message if not, otherwise keep going :)
 */
var passport = require("passport");  

function isAuthenticated(req, res, next) {
    passport.authenticate('jwt', {session: false}, function(err, user, info) {
      if (err) {
        return next(err); 
      }
      if (user) { // jwt valid
        /* session login
        req.logIn(user, function(err) {
          if (err) return next(err);
          next();
        });
        */
        req.user = user;
        next();
      } else {
        // try check session auth
        if (req.isAuthenticated()) {
          next(); // success with session
        } else {
          res.status(403).json({
            error: "not authorized"
          });
        }
      } 
    })(req, res, next);
}
exports.isAuthenticated = isAuthenticated;

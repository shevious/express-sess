/*
 * Check the request if the user is authenticated.
 * Return an error message if not, otherwise keep going :)
 */
var passport = require("passport");  
var passportJWT = require("passport-jwt");  

var env       = process.env.NODE_ENV || 'development';
var config    = require(__dirname + '/config/config.json')[env];

var ExtractJwt = passportJWT.ExtractJwt;  
var Strategy = passportJWT.Strategy;  
var params = {  
    secretOrKey: config.jwtSecret,
    //jwtFromRequest: ExtractJwt.fromAuthHeader()
    jwtFromRequest: ExtractJwt.fromUrlQueryParameter('access_token')
};


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
          console.log('logged in using session!');
          next();
        } else {
          res.status(403).json({
            error: "not authorized"
          });
        }
      } 
    })(req, res, next);
}
exports.isAuthenticated = isAuthenticated;

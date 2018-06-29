var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var SequelizeStore =  require('connect-session-sequelize')(session.Store);
var Sequelize = require('sequelize');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var passportJWT = require("passport-jwt");

var auth = require('./auth');

var env       = process.env.NODE_ENV || 'development';
var config    = require(__dirname + '/config/config.json')[env];
var sequelize = new Sequelize(config.database, config.username, config.password, config);


var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var loginRouter = require('./routes/login');
var apiRouter = require('./routes/api');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


var myStore = new SequelizeStore({
    db: sequelize,
    // The interval at which to cleanup expired sessions in milliseconds.
    //checkExpirationInterval: 1000,
    //expiration: 60 * 1000  // The maximum age (in milliseconds) of a valid session.
})
app.use(session({
 secret: 'secret', //change secret
 store: myStore,
 resave: true,
 rolling: true,
 cookie: {maxAge: 20000},
 saveUninitialized: false
}));
myStore.sync();

passport.use(new LocalStrategy(function(username, password, done) {
      if (username && username != '') {
        user = {id: username};
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
}));
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  done(null, {id: id});
});

var ExtractJwt = passportJWT.ExtractJwt;
var JWTStrategy = passportJWT.Strategy;
var params = {
    secretOrKey: config.jwtSecret,
    //jwtFromRequest: ExtractJwt.fromAuthHeader()
    jwtFromRequest: ExtractJwt.fromUrlQueryParameter('access_token')
};

var jwtstrategy = new JWTStrategy(params, function(payload, done) {
    var user = {id: payload.id} || null;
    if (user) {
        return done(null, user);
    } else {
        return done(new Error("User not found"), null);
    }
});
passport.use(jwtstrategy);

app.use(passport.initialize());
app.use(passport.session());

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/login', loginRouter);
app.get('/logout', function(req, res) {
  // clear session
  req.logout();
  res.redirect('/');
});
app.use('/api', apiRouter);
app.get('/secret', auth.isAuthenticated, function(req, res) {
  if (req.isAuthenticated()) {
    res.render('secret', {
      user: JSON.stringify(req.user),
      sess: req.session.cookie.maxAge / 1000
    });
  } else {
    res.redirect('/');
  }
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

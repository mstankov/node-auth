const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// LocalStrategy
const localOptions = {
    usernameField: 'email'
};
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
    // Verify this username and password, call 'done' with the user
    // if it is the correct credentials combination
    // otherwise call 'done' with 'false'

    User.findOne({ email: email }, function(err, user) {
        if (err) { return done(err); };
        if (!user) { return done(null, false); };

        // compare passwords - is 'password' equal to user.password?
        user.comparePassword(password, function(err, isMatch) {
            if (err) { return done(err); };
            if (!isMatch) { return done(null, false); };

            return done(null, user);
        })
    })
});

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // See if user exists in DB
    // If it does -> call 'done' with that other
    // Else -> call 'done' without a user object
    User.findById(payload.sub, function(err, user) {
        if (err) { return done(err, false); };

        if (user) {
            done(null, user);
        } else {
            done(null, false);
        };
    });
});

// Tell passport to use our strategies
passport.use(jwtLogin);
passport.use(localLogin);
const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser (user) {
    const timeStamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timeStamp }, config.secret);
};

exports.signin = function(req, res, next) {
    // User had already had their email and password auth'd
    // Just give them their token

    // due to the 'done' callback supplied by passportjs in 'passport.js'
    // we have a 'user' object on the request 'req' object
    res.send({ token: tokenForUser(req.user) });
};

exports.signup = function(req, res, next) {
    const password = req.body.password;
    const email = req.body.email;

    if(!password || !email) {
        return res.status(422).send({ error: 'You must provide email and password' });
    }

    // See if the user with the given email exists
    User.findOne({ email: email }, function(err, existingUser) {
        if (err) { return next(err); };

        // If a user with email does exist, return error
        if (existingUser) {
            return res.status(422).send({ error: 'Email is in use'} );
        };

        // If a user with email does NOT exist, create and save user record
        const user = new User({
            email: email,
            password: password
        });

        user.save(function(err) {
            if (err) { return next(err); };

            // Respond to request for the newly created user
            res.json({ token: tokenForUser(user) });
        });
    });
};
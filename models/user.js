const mongoose =  require('mongoose');
const bcrypt = require('bcrypt');
const Schema = mongoose.Schema;

// Define our module
const userSchema = new Schema({
    email: { type: String, unique: true , lowercase: true },
    password: String
});

// On Save hook, encrypt password
userSchema.pre('save', function(next) {
    // Get access to the user model
    const user = this;

    // Generate salt
    bcrypt.genSalt(10, function(err, salt) {
        if (err) { return next(err); };

        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) { return next(err); };

            // encrypt password with hashed password
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) { return callback(err); };

        callback(null, isMatch);
    });
};

// Create the model class
const ModelClass = mongoose.model('user', userSchema);

// Export the model
module.exports = ModelClass;
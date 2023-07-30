// passport-config.js

const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

// Initialize Passport.js with the local strategy for authentication.
function initialize(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email)
        if (user == null) {
            return done(null, false, { message: 'No user with that email' })
        }

        try {
            // Compare the provided password with the hashed password in the database.
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user) // Authentication successful
            } else {
                return done(null, false, { message: 'Password incorrect' }) // Incorrect password
            }
        } catch (e) {
            return done(e)
        }
    }

    // Use the local strategy with the usernameField set to 'email' and the authenticateUser function.
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
    // Serialize the user object to store in the session.
    passport.serializeUser((user, done) => done(null, user.id))
    // Deserialize the user object from the session based on the user ID.
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id))
    })
}

module.exports = initialize

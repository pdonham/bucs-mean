/*
This is back-end authorization; it can be used to protect individual routes
from being hit either directly or through the front end. We'd want to
check the user's login status on the front end, too, possibly to hide
parts of the interface from unauthenticated users.
 */
const jwt = require('jsonwebtoken')
const jwtConfig = require('../config/jwtConfig')
const User = require('../models/UserWithCrypto')
const crypto = require('crypto')

const checkAuthorization = function (req, res, next) {

    //See if there is a token on the request...if not, reject immediately
    //
    const userJWT = req.cookies.twitterAccessJwt
    if (!userJWT) {
        res.send(401, 'Invalid or missing authorization token')
    }
    //There's a token; see if the signature is valid and retrieve the payload if it is
    //
    else {
        const userJWTPayload = jwt.verify(userJWT, jwtConfig.jwtSecret)
        if (!userJWTPayload) {
            //The token signature is not valid; clear the cookie
            //
            res.clearCookie('twitterAccessJwt')
            res.send(401, 'Invalid or missing authorization token')
        }
        else {
            //There's a valid token...see if it is one we have in the db as a logged-in user
            //
            User.findOne({'twitterAccessTokenHash': userJWTPayload.twitterAccessTokenHash})
                .then(function (user) {
                    //No corresponding user...they are not logged in
                    //
                    if (!user) {
                        res.send(401, 'User not currently logged in')
                    }
                    else {
                        //Even though there's a logged-in user with the hash value, it might have
                        //been MITM'd, so make sure that the stored token hashes to the same value
                        //
                        console.log('Valid user:', user.name)
                        //Place the user object on the request
                        req.user = user
                        next()
                    }

                })
        }
    }
}

module.exports = checkAuthorization

//The payload on the token is the second item; split it and
//retrieve the token. It's base64 encoded, so we need to decode it, then
//convert the resulting string buffer to JSON. The decode is shown here
//for reference...a much simpler approach is to use the verify method on
//the jsonwebtoken package...it verifies the signature and returns the
//decoded token
//
// const encodedJWTPayload = userJWT.split('.')[1]
// const userJWTPayload = JSON.parse(Buffer.from(encodedJWTPayload, 'base64').toString())
//
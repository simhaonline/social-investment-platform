"use strict";

var _require = require('util'),
    promisify = _require.promisify;

var crypto = require('crypto');

var nodemailer = require('nodemailer');

var nodemailerSendgrid = require('nodemailer-sendgrid');

var passport = require('passport');

var _ = require('lodash');

var validator = require('validator');

var mailChecker = require('mailchecker');

var User = require('../models/User');

var randomBytesAsync = promisify(crypto.randomBytes);
/**
 * Helper Function to Send Mail.
 */

var sendMail = function sendMail(settings) {
  var transportConfig;

  if (process.env.SENDGRID_API_KEY) {
    transportConfig = nodemailerSendgrid({
      apiKey: process.env.SENDGRID_API_KEY
    });
  } else {
    transportConfig = {
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      }
    };
  }

  var transporter = nodemailer.createTransport(transportConfig);
  return transporter.sendMail(settings.mailOptions).then(function () {
    settings.req.flash(settings.successfulType, {
      msg: settings.successfulMsg
    });
  })["catch"](function (err) {
    if (err.message === 'self signed certificate in certificate chain') {
      console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
      transportConfig.tls = transportConfig.tls || {};
      transportConfig.tls.rejectUnauthorized = false;
      transporter = nodemailer.createTransport(transportConfig);
      return transporter.sendMail(settings.mailOptions).then(function () {
        settings.req.flash(settings.successfulType, {
          msg: settings.successfulMsg
        });
      });
    }

    console.log(settings.loggingError, err);
    settings.req.flash(settings.errorType, {
      msg: settings.errorMsg
    });
    return err;
  });
};
/**
 * GET /login
 * Login page.
 */


exports.getLogin = function (req, res) {
  if (req.user) {
    return res.redirect('/');
  } // return res.jsonp({"lamees":"oak"});


  res.render('account/login', {
    title: 'Login'
  });
};
/**
 * POST /login
 * Sign in using email and password.
 */


exports.postLogin = function (req, res, next) {
  var validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({
    msg: 'Please enter a valid email address.'
  });
  if (validator.isEmpty(req.body.password)) validationErrors.push({
    msg: 'Password cannot be blank.'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/login');
  }

  req.body.email = validator.normalizeEmail(req.body.email, {
    gmail_remove_dots: false
  });
  passport.authenticate('local', function (err, user, info) {
    if (err) {
      return next(err);
    }

    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }

    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }

      req.flash('success', {
        msg: 'Success! You are logged in.'
      });
      res.redirect(req.session.returnTo || '/');
    });
  })(req, res, next);
};
/**
 * GET /logout
 * Log out.
 */


exports.logout = function (req, res) {
  req.logout();
  req.session.destroy(function (err) {
    if (err) console.log('Error : Failed to destroy the session during logout.', err);
    req.user = null;
    res.redirect('/');
  });
};
/**
 * GET /signup
 * Signup page.
 */


exports.getSignup = function (req, res) {
  if (req.user) {
    return res.redirect('/');
  }

  res.render('account/signup', {
    title: 'Create Account'
  });
};
/**
 * POST /signup
 * Create a new local account.
 */


exports.postSignup = function (req, res, next) {
  var validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({
    msg: 'Please enter a valid email address.'
  });
  if (!validator.isLength(req.body.password, {
    min: 8
  })) validationErrors.push({
    msg: 'Password must be at least 8 characters long'
  });
  if (req.body.password !== req.body.confirmPassword) validationErrors.push({
    msg: 'Passwords do not match'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/signup');
  }

  req.body.email = validator.normalizeEmail(req.body.email, {
    gmail_remove_dots: false
  });
  var user = new User({
    email: req.body.email,
    password: req.body.password
  });
  User.findOne({
    email: req.body.email
  }, function (err, existingUser) {
    if (err) {
      return next(err);
    }

    if (existingUser) {
      req.flash('errors', {
        msg: 'Account with that email address already exists.'
      });
      return res.redirect('/signup');
    }

    user.save(function (err) {
      if (err) {
        return next(err);
      }

      req.logIn(user, function (err) {
        if (err) {
          return next(err);
        }

        res.redirect('/');
      });
    });
  });
};
/**
 * GET /account
 * Profile page.
 */


exports.getAccount = function (req, res) {
  res.render('account/profile', {
    title: 'Account Management'
  });
};
/**
 * POST /account/profile
 * Update profile information.
 */


exports.postUpdateProfile = function (req, res, next) {
  var validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({
    msg: 'Please enter a valid email address.'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }

  req.body.email = validator.normalizeEmail(req.body.email, {
    gmail_remove_dots: false
  });
  User.findById(req.user.id, function (err, user) {
    if (err) {
      return next(err);
    }

    if (user.email !== req.body.email) user.emailVerified = false;
    user.email = req.body.email || '';
    user.profile.name = req.body.name || '';
    user.profile.gender = req.body.gender || '';
    user.profile.location = req.body.location || '';
    user.profile.website = req.body.website || '';
    user.save(function (err) {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', {
            msg: 'The email address you have entered is already associated with an account.'
          });
          return res.redirect('/account');
        }

        return next(err);
      }

      req.flash('success', {
        msg: 'Profile information has been updated.'
      });
      res.redirect('/account');
    });
  });
};
/**
 * POST /account/password
 * Update current password.
 */


exports.postUpdatePassword = function (req, res, next) {
  var validationErrors = [];
  if (!validator.isLength(req.body.password, {
    min: 8
  })) validationErrors.push({
    msg: 'Password must be at least 8 characters long'
  });
  if (req.body.password !== req.body.confirmPassword) validationErrors.push({
    msg: 'Passwords do not match'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, function (err, user) {
    if (err) {
      return next(err);
    }

    user.password = req.body.password;
    user.save(function (err) {
      if (err) {
        return next(err);
      }

      req.flash('success', {
        msg: 'Password has been changed.'
      });
      res.redirect('/account');
    });
  });
};
/**
 * POST /account/delete
 * Delete user account.
 */


exports.postDeleteAccount = function (req, res, next) {
  User.deleteOne({
    _id: req.user.id
  }, function (err) {
    if (err) {
      return next(err);
    }

    req.logout();
    req.flash('info', {
      msg: 'Your account has been deleted.'
    });
    res.redirect('/');
  });
};
/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */


exports.getOauthUnlink = function (req, res, next) {
  var provider = req.params.provider;
  User.findById(req.user.id, function (err, user) {
    if (err) {
      return next(err);
    }

    user[provider.toLowerCase()] = undefined;
    var tokensWithoutProviderToUnlink = user.tokens.filter(function (token) {
      return token.kind !== provider.toLowerCase();
    }); // Some auth providers do not provide an email address in the user profile.
    // As a result, we need to verify that unlinking the provider is safe by ensuring
    // that another login method exists.

    if (!(user.email && user.password) && tokensWithoutProviderToUnlink.length === 0) {
      req.flash('errors', {
        msg: "The ".concat(_.startCase(_.toLower(provider)), " account cannot be unlinked without another form of login enabled.") + ' Please link another account or add an email address and password.'
      });
      return res.redirect('/account');
    }

    user.tokens = tokensWithoutProviderToUnlink;
    user.save(function (err) {
      if (err) {
        return next(err);
      }

      req.flash('info', {
        msg: "".concat(_.startCase(_.toLower(provider)), " account has been unlinked.")
      });
      res.redirect('/account');
    });
  });
};
/**
 * GET /reset/:token
 * Reset Password page.
 */


exports.getReset = function (req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }

  var validationErrors = [];
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({
    msg: 'Invalid Token.  Please retry.'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/forgot');
  }

  User.findOne({
    passwordResetToken: req.params.token
  }).where('passwordResetExpires').gt(Date.now()).exec(function (err, user) {
    if (err) {
      return next(err);
    }

    if (!user) {
      req.flash('errors', {
        msg: 'Password reset token is invalid or has expired.'
      });
      return res.redirect('/forgot');
    }

    res.render('account/reset', {
      title: 'Password Reset'
    });
  });
};
/**
 * GET /account/verify/:token
 * Verify email address
 */


exports.getVerifyEmailToken = function (req, res, next) {
  if (req.user.emailVerified) {
    req.flash('info', {
      msg: 'The email address has been verified.'
    });
    return res.redirect('/account');
  }

  var validationErrors = [];
  if (req.params.token && !validator.isHexadecimal(req.params.token)) validationErrors.push({
    msg: 'Invalid Token.  Please retry.'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/account');
  }

  if (req.params.token === req.user.emailVerificationToken) {
    User.findOne({
      email: req.user.email
    }).then(function (user) {
      if (!user) {
        req.flash('errors', {
          msg: 'There was an error in loading your profile.'
        });
        return res.redirect('back');
      }

      user.emailVerificationToken = '';
      user.emailVerified = true;
      user = user.save();
      req.flash('info', {
        msg: 'Thank you for verifying your email address.'
      });
      return res.redirect('/account');
    })["catch"](function (error) {
      console.log('Error saving the user profile to the database after email verification', error);
      req.flash('errors', {
        msg: 'There was an error when updating your profile.  Please try again later.'
      });
      return res.redirect('/account');
    });
  } else {
    req.flash('errors', {
      msg: 'The verification link was invalid, or is for a different account.'
    });
    return res.redirect('/account');
  }
};
/**
 * GET /account/verify
 * Verify email address
 */


exports.getVerifyEmail = function (req, res, next) {
  if (req.user.emailVerified) {
    req.flash('info', {
      msg: 'The email address has been verified.'
    });
    return res.redirect('/account');
  }

  if (!mailChecker.isValid(req.user.email)) {
    req.flash('errors', {
      msg: 'The email address is invalid or disposable and can not be verified.  Please update your email address and try again.'
    });
    return res.redirect('/account');
  }

  var createRandomToken = randomBytesAsync(16).then(function (buf) {
    return buf.toString('hex');
  });

  var setRandomToken = function setRandomToken(token) {
    User.findOne({
      email: req.user.email
    }).then(function (user) {
      user.emailVerificationToken = token;
      user = user.save();
    });
    return token;
  };

  var sendVerifyEmail = function sendVerifyEmail(token) {
    var mailOptions = {
      to: req.user.email,
      from: 'hackathon@starter.com',
      subject: 'Please verify your email address on Hackathon Starter',
      text: "Thank you for registering with hackathon-starter.\n\n\n        This verify your email address please click on the following link, or paste this into your browser:\n\n\n        http://".concat(req.headers.host, "/account/verify/").concat(token, "\n\n\n        \n\n\n        Thank you!")
    };
    var mailSettings = {
      successfulType: 'info',
      successfulMsg: "An e-mail has been sent to ".concat(req.user.email, " with further instructions."),
      loggingError: 'ERROR: Could not send verifyEmail email after security downgrade.\n',
      errorType: 'errors',
      errorMsg: 'Error sending the email verification message. Please try again shortly.',
      mailOptions: mailOptions,
      req: req
    };
    return sendMail(mailSettings);
  };

  createRandomToken.then(setRandomToken).then(sendVerifyEmail).then(function () {
    return res.redirect('/account');
  })["catch"](next);
};
/**
 * POST /reset/:token
 * Process the reset password request.
 */


exports.postReset = function (req, res, next) {
  var validationErrors = [];
  if (!validator.isLength(req.body.password, {
    min: 8
  })) validationErrors.push({
    msg: 'Password must be at least 8 characters long'
  });
  if (req.body.password !== req.body.confirm) validationErrors.push({
    msg: 'Passwords do not match'
  });
  if (!validator.isHexadecimal(req.params.token)) validationErrors.push({
    msg: 'Invalid Token.  Please retry.'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('back');
  }

  var resetPassword = function resetPassword() {
    return User.findOne({
      passwordResetToken: req.params.token
    }).where('passwordResetExpires').gt(Date.now()).then(function (user) {
      if (!user) {
        req.flash('errors', {
          msg: 'Password reset token is invalid or has expired.'
        });
        return res.redirect('back');
      }

      user.password = req.body.password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      return user.save().then(function () {
        return new Promise(function (resolve, reject) {
          req.logIn(user, function (err) {
            if (err) {
              return reject(err);
            }

            resolve(user);
          });
        });
      });
    });
  };

  var sendResetPasswordEmail = function sendResetPasswordEmail(user) {
    if (!user) {
      return;
    }

    var mailOptions = {
      to: user.email,
      from: 'hackathon@starter.com',
      subject: 'Your Hackathon Starter password has been changed',
      text: "Hello,\n\nThis is a confirmation that the password for your account ".concat(user.email, " has just been changed.\n")
    };
    var mailSettings = {
      successfulType: 'success',
      successfulMsg: 'Success! Your password has been changed.',
      loggingError: 'ERROR: Could not send password reset confirmation email after security downgrade.\n',
      errorType: 'warning',
      errorMsg: 'Your password has been changed, however we were unable to send you a confirmation email. We will be looking into it shortly.',
      mailOptions: mailOptions,
      req: req
    };
    return sendMail(mailSettings);
  };

  resetPassword().then(sendResetPasswordEmail).then(function () {
    if (!res.finished) res.redirect('/');
  })["catch"](function (err) {
    return next(err);
  });
};
/**
 * GET /forgot
 * Forgot Password page.
 */


exports.getForgot = function (req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }

  res.render('account/forgot', {
    title: 'Forgot Password'
  });
};
/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */


exports.postForgot = function (req, res, next) {
  var validationErrors = [];
  if (!validator.isEmail(req.body.email)) validationErrors.push({
    msg: 'Please enter a valid email address.'
  });

  if (validationErrors.length) {
    req.flash('errors', validationErrors);
    return res.redirect('/forgot');
  }

  req.body.email = validator.normalizeEmail(req.body.email, {
    gmail_remove_dots: false
  });
  var createRandomToken = randomBytesAsync(16).then(function (buf) {
    return buf.toString('hex');
  });

  var setRandomToken = function setRandomToken(token) {
    return User.findOne({
      email: req.body.email
    }).then(function (user) {
      if (!user) {
        req.flash('errors', {
          msg: 'Account with that email address does not exist.'
        });
      } else {
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour

        user = user.save();
      }

      return user;
    });
  };

  var sendForgotPasswordEmail = function sendForgotPasswordEmail(user) {
    if (!user) {
      return;
    }

    var token = user.passwordResetToken;
    var mailOptions = {
      to: user.email,
      from: 'hackathon@starter.com',
      subject: 'Reset your password on Hackathon Starter',
      text: "You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n\n        Please click on the following link, or paste this into your browser to complete the process:\n\n\n        http://".concat(req.headers.host, "/reset/").concat(token, "\n\n\n        If you did not request this, please ignore this email and your password will remain unchanged.\n")
    };
    var mailSettings = {
      successfulType: 'info',
      successfulMsg: "An e-mail has been sent to ".concat(user.email, " with further instructions."),
      loggingError: 'ERROR: Could not send forgot password email after security downgrade.\n',
      errorType: 'errors',
      errorMsg: 'Error sending the password reset message. Please try again shortly.',
      mailOptions: mailOptions,
      req: req
    };
    return sendMail(mailSettings);
  };

  createRandomToken.then(setRandomToken).then(sendForgotPasswordEmail).then(function () {
    return res.redirect('/forgot');
  })["catch"](next);
};
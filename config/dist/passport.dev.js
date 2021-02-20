"use strict";

var passport = require('passport');

var refresh = require('passport-oauth2-refresh');

var axios = require('axios');

var _require = require('passport-instagram'),
    InstagramStrategy = _require.Strategy;

var _require2 = require('passport-local'),
    LocalStrategy = _require2.Strategy;

var _require3 = require('passport-facebook'),
    FacebookStrategy = _require3.Strategy;

var _require4 = require('passport-snapchat'),
    SnapchatStrategy = _require4.Strategy;

var _require5 = require('passport-twitter'),
    TwitterStrategy = _require5.Strategy;

var _require6 = require('passport-twitch-new'),
    TwitchStrategy = _require6.Strategy;

var _require7 = require('passport-github2'),
    GitHubStrategy = _require7.Strategy;

var _require8 = require('passport-google-oauth'),
    GoogleStrategy = _require8.OAuth2Strategy;

var _require9 = require('passport-linkedin-oauth2'),
    LinkedInStrategy = _require9.Strategy;

var _require10 = require('passport-openid'),
    OpenIDStrategy = _require10.Strategy;

var _require11 = require('passport-oauth'),
    OAuthStrategy = _require11.OAuthStrategy;

var _require12 = require('passport-oauth'),
    OAuth2Strategy = _require12.OAuth2Strategy;

var _ = require('lodash');

var moment = require('moment');

var User = require('../models/User');

passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
/**
 * Sign in using Email and Password.
 */

passport.use(new LocalStrategy({
  usernameField: 'email'
}, function (email, password, done) {
  User.findOne({
    email: email.toLowerCase()
  }, function (err, user) {
    if (err) {
      return done(err);
    }

    if (!user) {
      return done(null, false, {
        msg: "Email ".concat(email, " not found.")
      });
    }

    if (!user.password) {
      return done(null, false, {
        msg: 'Your account was registered using a sign-in provider. To enable password login, sign in using a provider, and then set a password under your user profile.'
      });
    }

    user.comparePassword(password, function (err, isMatch) {
      if (err) {
        return done(err);
      }

      if (isMatch) {
        return done(null, user);
      }

      return done(null, false, {
        msg: 'البريد الإلكتروني أو كلمة المرور خاطئة'
      });
    });
  });
}));
/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a provider id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */

/**
 * Sign in with Snapchat.
 */

passport.use(new SnapchatStrategy({
  clientID: process.env.SNAPCHAT_ID,
  clientSecret: process.env.SNAPCHAT_SECRET,
  callbackURL: '/auth/snapchat/callback',
  profileFields: ['id', 'displayName', 'bitmoji'],
  scope: ['user.display_name', 'user.bitmoji.avatar'],
  passReqToCallback: true
}, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({
      snapchat: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already a Snapchat account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.snapchat = profile.id;
          user.tokens.push({
            kind: 'snapchat',
            accessToken: accessToken
          });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.picture = user.profile.picture || profile.bitmoji.avatarUrl;
          user.save(function (err) {
            req.flash('info', {
              msg: 'Snapchat account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      snapchat: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      var user = new User(); // Similar to Twitter & Instagram APIs, assign a temporary e-mail address
      // to get on with the registration process. It can be changed later
      // to a valid e-mail address in Profile Management.

      user.email = "".concat(profile.id, "@snapchat.com");
      user.snapchat = profile.id;
      user.tokens.push({
        kind: 'snapchat',
        accessToken: accessToken
      });
      user.profile.name = profile.displayName;
      user.profile.picture = profile.bitmoji.avatarUrl;
      user.save(function (err) {
        done(err, user);
      });
    });
  }
}));
/**
 * Sign in with Facebook.
 */

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: "".concat(process.env.BASE_URL, "/auth/facebook/callback"),
  profileFields: ['name', 'email', 'link', 'locale', 'timezone', 'gender'],
  passReqToCallback: true
}, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({
      facebook: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already a Facebook account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.facebook = profile.id;
          user.tokens.push({
            kind: 'facebook',
            accessToken: accessToken
          });
          user.profile.name = user.profile.name || "".concat(profile.name.givenName, " ").concat(profile.name.familyName);
          user.profile.gender = user.profile.gender || profile._json.gender;
          user.profile.picture = user.profile.picture || "https://graph.facebook.com/".concat(profile.id, "/picture?type=large");
          user.save(function (err) {
            req.flash('info', {
              msg: 'Facebook account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      facebook: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      User.findOne({
        email: profile._json.email
      }, function (err, existingEmailUser) {
        if (err) {
          return done(err);
        }

        if (existingEmailUser) {
          req.flash('errors', {
            msg: 'There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings.'
          });
          done(err);
        } else {
          var user = new User();
          user.email = profile._json.email;
          user.facebook = profile.id;
          user.tokens.push({
            kind: 'facebook',
            accessToken: accessToken
          });
          user.profile.name = "".concat(profile.name.givenName, " ").concat(profile.name.familyName);
          user.profile.gender = profile._json.gender;
          user.profile.picture = "https://graph.facebook.com/".concat(profile.id, "/picture?type=large");
          user.profile.location = profile._json.location ? profile._json.location.name : '';
          user.save(function (err) {
            done(err, user);
          });
        }
      });
    });
  }
}));
/**
 * Sign in with GitHub.
 */

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_ID,
  clientSecret: process.env.GITHUB_SECRET,
  callbackURL: "".concat(process.env.BASE_URL, "/auth/github/callback"),
  passReqToCallback: true,
  scope: ['user:email']
}, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({
      github: profile.id
    }, function (err, existingUser) {
      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already a GitHub account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.github = profile.id;
          user.tokens.push({
            kind: 'github',
            accessToken: accessToken
          });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.picture = user.profile.picture || profile._json.avatar_url;
          user.profile.location = user.profile.location || profile._json.location;
          user.profile.website = user.profile.website || profile._json.blog;
          user.save(function (err) {
            req.flash('info', {
              msg: 'GitHub account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      github: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      User.findOne({
        email: profile._json.email
      }, function (err, existingEmailUser) {
        if (err) {
          return done(err);
        }

        if (existingEmailUser) {
          req.flash('errors', {
            msg: 'There is already an account using this email address. Sign in to that account and link it with GitHub manually from Account Settings.'
          });
          done(err);
        } else {
          var user = new User();
          user.email = _.get(_.orderBy(profile.emails, ['primary', 'verified'], ['desc', 'desc']), [0, 'value'], null);
          user.github = profile.id;
          user.tokens.push({
            kind: 'github',
            accessToken: accessToken
          });
          user.profile.name = profile.displayName;
          user.profile.picture = profile._json.avatar_url;
          user.profile.location = profile._json.location;
          user.profile.website = profile._json.blog;
          user.save(function (err) {
            done(err, user);
          });
        }
      });
    });
  }
}));
/**
 * Sign in with Twitter.
 */

passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_KEY,
  consumerSecret: process.env.TWITTER_SECRET,
  callbackURL: "".concat(process.env.BASE_URL, "/auth/twitter/callback"),
  passReqToCallback: true
}, function (req, accessToken, tokenSecret, profile, done) {
  if (req.user) {
    User.findOne({
      twitter: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already a Twitter account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.twitter = profile.id;
          user.tokens.push({
            kind: 'twitter',
            accessToken: accessToken,
            tokenSecret: tokenSecret
          });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.location = user.profile.location || profile._json.location;
          user.profile.picture = user.profile.picture || profile._json.profile_image_url_https;
          user.save(function (err) {
            if (err) {
              return done(err);
            }

            req.flash('info', {
              msg: 'Twitter account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      twitter: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      var user = new User(); // Twitter will not provide an email address.  Period.
      // But a person’s twitter username is guaranteed to be unique
      // so we can "fake" a twitter email address as follows:

      user.email = "".concat(profile.username, "@twitter.com");
      user.twitter = profile.id;
      user.tokens.push({
        kind: 'twitter',
        accessToken: accessToken,
        tokenSecret: tokenSecret
      });
      user.profile.name = profile.displayName;
      user.profile.location = profile._json.location;
      user.profile.picture = profile._json.profile_image_url_https;
      user.save(function (err) {
        done(err, user);
      });
    });
  }
}));
/**
 * Sign in with Google.
 */

var googleStrategyConfig = new GoogleStrategy({
  clientID: process.env.GOOGLE_ID,
  clientSecret: process.env.GOOGLE_SECRET,
  callbackURL: '/auth/google/callback',
  passReqToCallback: true
}, function (req, accessToken, refreshToken, params, profile, done) {
  if (req.user) {
    User.findOne({
      google: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser && existingUser.id !== req.user.id) {
        req.flash('errors', {
          msg: 'There is already a Google account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.google = profile.id;
          user.tokens.push({
            kind: 'google',
            accessToken: accessToken,
            accessTokenExpires: moment().add(params.expires_in, 'seconds').format(),
            refreshToken: refreshToken
          });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.gender = user.profile.gender || profile._json.gender;
          user.profile.picture = user.profile.picture || profile._json.picture;
          user.save(function (err) {
            req.flash('info', {
              msg: 'Google account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      google: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      User.findOne({
        email: profile.emails[0].value
      }, function (err, existingEmailUser) {
        if (err) {
          return done(err);
        }

        if (existingEmailUser) {
          req.flash('errors', {
            msg: 'There is already an account using this email address. Sign in to that account and link it with Google manually from Account Settings.'
          });
          done(err);
        } else {
          var user = new User();
          user.email = profile.emails[0].value;
          user.google = profile.id;
          user.tokens.push({
            kind: 'google',
            accessToken: accessToken,
            accessTokenExpires: moment().add(params.expires_in, 'seconds').format(),
            refreshToken: refreshToken
          });
          user.profile.name = profile.displayName;
          user.profile.gender = profile._json.gender;
          user.profile.picture = profile._json.picture;
          user.save(function (err) {
            done(err, user);
          });
        }
      });
    });
  }
});
passport.use('google', googleStrategyConfig);
refresh.use('google', googleStrategyConfig);
/**
 * Sign in with LinkedIn.
 */

passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_ID,
  clientSecret: process.env.LINKEDIN_SECRET,
  callbackURL: "".concat(process.env.BASE_URL, "/auth/linkedin/callback"),
  scope: ['r_liteprofile', 'r_emailaddress'],
  passReqToCallback: true
}, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({
      linkedin: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already a LinkedIn account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.linkedin = profile.id;
          user.tokens.push({
            kind: 'linkedin',
            accessToken: accessToken
          });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.picture = user.profile.picture || profile.photos[3].value;
          user.save(function (err) {
            if (err) {
              return done(err);
            }

            req.flash('info', {
              msg: 'LinkedIn account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      linkedin: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      User.findOne({
        email: profile.emails[0].value
      }, function (err, existingEmailUser) {
        if (err) {
          return done(err);
        }

        if (existingEmailUser) {
          req.flash('errors', {
            msg: 'There is already an account using this email address. Sign in to that account and link it with LinkedIn manually from Account Settings.'
          });
          done(err);
        } else {
          var user = new User();
          user.linkedin = profile.id;
          user.tokens.push({
            kind: 'linkedin',
            accessToken: accessToken
          });
          user.email = profile.emails[0].value;
          user.profile.name = profile.displayName;
          user.profile.picture = user.profile.picture || profile.photos[3].value;
          user.save(function (err) {
            done(err, user);
          });
        }
      });
    });
  }
}));
/**
 * Sign in with Instagram.
 */

passport.use(new InstagramStrategy({
  clientID: process.env.INSTAGRAM_ID,
  clientSecret: process.env.INSTAGRAM_SECRET,
  callbackURL: '/auth/instagram/callback',
  passReqToCallback: true
}, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({
      instagram: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already an Instagram account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.instagram = profile.id;
          user.tokens.push({
            kind: 'instagram',
            accessToken: accessToken
          });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.picture = user.profile.picture || profile._json.data.profile_picture;
          user.profile.website = user.profile.website || profile._json.data.website;
          user.save(function (err) {
            req.flash('info', {
              msg: 'Instagram account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      instagram: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      var user = new User();
      user.instagram = profile.id;
      user.tokens.push({
        kind: 'instagram',
        accessToken: accessToken
      });
      user.profile.name = profile.displayName; // Similar to Twitter API, assigns a temporary e-mail address
      // to get on with the registration process. It can be changed later
      // to a valid e-mail address in Profile Management.

      user.email = "".concat(profile.username, "@instagram.com");
      user.profile.website = profile._json.data.website;
      user.profile.picture = profile._json.data.profile_picture;
      user.save(function (err) {
        done(err, user);
      });
    });
  }
}));
/**
 * Twitch API OAuth.
 */

var twitchStrategyConfig = new TwitchStrategy({
  clientID: process.env.TWITCH_CLIENT_ID,
  clientSecret: process.env.TWITCH_CLIENT_SECRET,
  callbackURL: "".concat(process.env.BASE_URL, "/auth/twitch/callback"),
  scope: ['user_read', 'chat:read', 'chat:edit', 'whispers:read', 'whispers:edit', 'user:read:email'],
  passReqToCallback: true
}, function (req, accessToken, refreshToken, params, profile, done) {
  if (req.user) {
    User.findOne({
      twitch: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser && existingUser.id !== req.user.id) {
        req.flash('errors', {
          msg: 'There is already a Twitch account that belongs to you. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.twitch = profile.id;
          user.tokens.push({
            kind: 'twitch',
            accessToken: accessToken,
            accessTokenExpires: moment().add(params.expires_in, 'seconds').format(),
            refreshToken: refreshToken
          });
          user.profile.name = user.profile.name || profile.display_name;
          user.profile.email = user.profile.gender || profile.email;
          user.profile.picture = user.profile.picture || profile.profile_image_url;
          user.save(function (err) {
            req.flash('info', {
              msg: 'Twitch account has been linked.'
            });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({
      twitch: profile.id
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        return done(null, existingUser);
      }

      User.findOne({
        email: profile.email
      }, function (err, existingEmailUser) {
        if (err) {
          return done(err);
        }

        if (existingEmailUser) {
          req.flash('errors', {
            msg: 'There is already an account using this email address. Sign in to that account and link it with Twtich manually from Account Settings.'
          });
          done(err);
        } else {
          var user = new User();
          user.email = profile.email;
          user.twitch = profile.id;
          user.tokens.push({
            kind: 'twitch',
            accessToken: accessToken,
            accessTokenExpires: moment().add(params.expires_in, 'seconds').format(),
            refreshToken: refreshToken
          });
          user.profile.name = profile.display_name;
          user.profile.email = profile.email;
          user.profile.picture = profile.profile_image_url;
          user.save(function (err) {
            done(err, user);
          });
        }
      });
    });
  }
});
passport.use('twitch', twitchStrategyConfig);
refresh.use('twitch', twitchStrategyConfig);
/**
 * Tumblr API OAuth.
 */

passport.use('tumblr', new OAuthStrategy({
  requestTokenURL: 'https://www.tumblr.com/oauth/request_token',
  accessTokenURL: 'https://www.tumblr.com/oauth/access_token',
  userAuthorizationURL: 'https://www.tumblr.com/oauth/authorize',
  consumerKey: process.env.TUMBLR_KEY,
  consumerSecret: process.env.TUMBLR_SECRET,
  callbackURL: '/auth/tumblr/callback',
  passReqToCallback: true
}, function (req, token, tokenSecret, profile, done) {
  User.findById(req.user._id, function (err, user) {
    if (err) {
      return done(err);
    }

    user.tokens.push({
      kind: 'tumblr',
      accessToken: token,
      tokenSecret: tokenSecret
    });
    user.save(function (err) {
      done(err, user);
    });
  });
}));
/**
 * Foursquare API OAuth.
 */

passport.use('foursquare', new OAuth2Strategy({
  authorizationURL: 'https://foursquare.com/oauth2/authorize',
  tokenURL: 'https://foursquare.com/oauth2/access_token',
  clientID: process.env.FOURSQUARE_ID,
  clientSecret: process.env.FOURSQUARE_SECRET,
  callbackURL: process.env.FOURSQUARE_REDIRECT_URL,
  passReqToCallback: true
}, function (req, accessToken, refreshToken, profile, done) {
  User.findById(req.user._id, function (err, user) {
    if (err) {
      return done(err);
    }

    user.tokens.push({
      kind: 'foursquare',
      accessToken: accessToken
    });
    user.save(function (err) {
      done(err, user);
    });
  });
}));
/**
 * Steam API OpenID.
 */

passport.use(new OpenIDStrategy({
  apiKey: process.env.STEAM_KEY,
  providerURL: 'http://steamcommunity.com/openid',
  returnURL: "".concat(process.env.BASE_URL, "/auth/steam/callback"),
  realm: "".concat(process.env.BASE_URL, "/"),
  stateless: true,
  passReqToCallback: true
}, function (req, identifier, done) {
  var steamId = identifier.match(/\d+$/)[0];
  var profileURL = "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=".concat(process.env.STEAM_KEY, "&steamids=").concat(steamId);

  if (req.user) {
    User.findOne({
      steam: steamId
    }, function (err, existingUser) {
      if (err) {
        return done(err);
      }

      if (existingUser) {
        req.flash('errors', {
          msg: 'There is already an account associated with the SteamID. Sign in with that account or delete it, then link it with your current account.'
        });
        done(err);
      } else {
        User.findById(req.user.id, function (err, user) {
          if (err) {
            return done(err);
          }

          user.steam = steamId;
          user.tokens.push({
            kind: 'steam',
            accessToken: steamId
          });
          axios.get(profileURL).then(function (res) {
            var profile = res.data.response.players[0];
            user.profile.name = user.profile.name || profile.personaname;
            user.profile.picture = user.profile.picture || profile.avatarmedium;
            user.save(function (err) {
              done(err, user);
            });
          })["catch"](function (err) {
            user.save(function (err) {
              done(err, user);
            });
            done(err, null);
          });
        });
      }
    });
  } else {
    axios.get(profileURL).then(function (_ref) {
      var data = _ref.data;
      var profile = data.response.players[0];
      var user = new User();
      user.steam = steamId;
      user.email = "".concat(steamId, "@steam.com"); // steam does not disclose emails, prevent duplicate keys

      user.tokens.push({
        kind: 'steam',
        accessToken: steamId
      });
      user.profile.name = profile.personaname;
      user.profile.picture = profile.avatarmedium;
      user.save(function (err) {
        done(err, user);
      });
    })["catch"](function (err) {
      done(err, null);
    });
  }
}));
/**
 * Pinterest API OAuth.
 */

passport.use('pinterest', new OAuth2Strategy({
  authorizationURL: 'https://api.pinterest.com/oauth/',
  tokenURL: 'https://api.pinterest.com/v1/oauth/token',
  clientID: process.env.PINTEREST_ID,
  clientSecret: process.env.PINTEREST_SECRET,
  callbackURL: process.env.PINTEREST_REDIRECT_URL,
  passReqToCallback: true
}, function (req, accessToken, refreshToken, profile, done) {
  User.findById(req.user._id, function (err, user) {
    if (err) {
      return done(err);
    }

    user.tokens.push({
      kind: 'pinterest',
      accessToken: accessToken
    });
    user.save(function (err) {
      done(err, user);
    });
  });
}));
/**
 * Intuit/QuickBooks API OAuth.
 */

var quickbooksStrategyConfig = new OAuth2Strategy({
  authorizationURL: 'https://appcenter.intuit.com/connect/oauth2',
  tokenURL: 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
  clientID: process.env.QUICKBOOKS_CLIENT_ID,
  clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET,
  callbackURL: "".concat(process.env.BASE_URL, "/auth/quickbooks/callback"),
  passReqToCallback: true
}, function (res, accessToken, refreshToken, params, profile, done) {
  User.findById(res.user._id, function (err, user) {
    if (err) {
      return done(err);
    }

    user.quickbooks = res.query.realmId;

    if (user.tokens.filter(function (vendor) {
      return vendor.kind === 'quickbooks';
    })[0]) {
      user.tokens.some(function (tokenObject) {
        if (tokenObject.kind === 'quickbooks') {
          tokenObject.accessToken = accessToken;
          tokenObject.accessTokenExpires = moment().add(params.expires_in, 'seconds').format();
          tokenObject.refreshToken = refreshToken;
          tokenObject.refreshTokenExpires = moment().add(params.x_refresh_token_expires_in, 'seconds').format();
          if (params.expires_in) tokenObject.accessTokenExpires = moment().add(params.expires_in, 'seconds').format();
          return true;
        }

        return false;
      });
      user.markModified('tokens');
      user.save(function (err) {
        done(err, user);
      });
    } else {
      user.tokens.push({
        kind: 'quickbooks',
        accessToken: accessToken,
        accessTokenExpires: moment().add(params.expires_in, 'seconds').format(),
        refreshToken: refreshToken,
        refreshTokenExpires: moment().add(params.x_refresh_token_expires_in, 'seconds').format()
      });
      user.save(function (err) {
        done(err, user);
      });
    }
  });
});
passport.use('quickbooks', quickbooksStrategyConfig);
refresh.use('quickbooks', quickbooksStrategyConfig);
/**
 * Login Required middleware.
 */

exports.isAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login');
};
/**
 * Authorization Required middleware.
 */


exports.isAuthorized = function (req, res, next) {
  var provider = req.path.split('/')[2];
  var token = req.user.tokens.find(function (token) {
    return token.kind === provider;
  });

  if (token) {
    // Is there an access token expiration and access token expired?
    // Yes: Is there a refresh token?
    //     Yes: Does it have expiration and if so is it expired?
    //       Yes, Quickbooks - We got nothing, redirect to res.redirect(`/auth/${provider}`);
    //       No, Quickbooks and Google- refresh token and save, and then go to next();
    //    No:  Treat it like we got nothing, redirect to res.redirect(`/auth/${provider}`);
    // No: we are good, go to next():
    if (token.accessTokenExpires && moment(token.accessTokenExpires).isBefore(moment().subtract(1, 'minutes'))) {
      if (token.refreshToken) {
        if (token.refreshTokenExpires && moment(token.refreshTokenExpires).isBefore(moment().subtract(1, 'minutes'))) {
          res.redirect("/auth/".concat(provider));
        } else {
          refresh.requestNewAccessToken("".concat(provider), token.refreshToken, function (err, accessToken, refreshToken, params) {
            User.findById(req.user.id, function (err, user) {
              user.tokens.some(function (tokenObject) {
                if (tokenObject.kind === provider) {
                  tokenObject.accessToken = accessToken;
                  if (params.expires_in) tokenObject.accessTokenExpires = moment().add(params.expires_in, 'seconds').format();
                  return true;
                }

                return false;
              });
              req.user = user;
              user.markModified('tokens');
              user.save(function (err) {
                if (err) console.log(err);
                next();
              });
            });
          });
        }
      } else {
        res.redirect("/auth/".concat(provider));
      }
    } else {
      next();
    }
  } else {
    res.redirect("/auth/".concat(provider));
  }
};
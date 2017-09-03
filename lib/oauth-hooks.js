(function(exports) {
  "use strict";

  var log = require("debug")("nqm-utils:oauthHooks");
  var errLog = require("debug")("nqm-utils:oauthHooks:error");
  var ipaddr = require("ipaddr.js");
  var _ = require("lodash");
  var requestIP = require("request-ip");
  var Promise = require("bluebird");
  var authParser = require("auth-header");
  var constants = require("nqm-core-utils").constants;

  var grantClientTokenEx = exports.grantClientTokenEx = function (credentials, req, cb) {
    // Load auth server when we need it to prevent circular dependencies (auth server uses nqmUtils)
    var authServer = require("nqm-core-auth-server");

    if (!credentials || !credentials.clientId || !credentials.clientSecret) {
      // Check for non-base64 encoded credentials (for legacy support).
      var authHeader = req.headers.authorization && authParser.parse(req.headers.authorization); 

      if (!authHeader || authHeader.scheme !== "Basic" || !authHeader.token || authHeader.token.length !== 2) {
        errLog("grantClientToken - invalid credentials: %j", credentials || "[no credentials]");
        return cb(null, false);
      }
      credentials = {};
      credentials.clientId = authHeader.token[0];
      credentials.clientSecret = authHeader.token[1];
    }

    var accountId = decodeURIComponent(credentials.clientId);
    log("grantClientToken for %s", accountId);
    authServer.adminApi.getAccountForUser(accountId)
      .then(function(account) {
        if (!account) {
          errLog("account not found: %s", accountId);
          return Promise.reject(new Error("no match found for " + accountId));
        }
        return doCheckAccountSecret(account, credentials.clientSecret);
      })
      .then(function(account) {
        if (!account) {
          errLog("hash compare failed");
          return Promise.reject(new Error("hash compare failed"));
        }

        if (!account.verified || !account.approved) {
          return Promise.reject(new Error("not verified or approved"));
        }

        if (account.expires && account.expires < Date.now()) {
          errLog("account %s expired at %s", account.username, (new Date(account.expires)).toString());
          return Promise.reject(new Error("account expired"));
        }

        var incomingIP = requestIP.getClientIp(req);

        // Check against whitelist.
        if (account.whitelist && account.whitelist.length) {
          var whitelisted = _.find(account.whitelist, function(ip) {
            return _.isEqual(ipaddr.process(ip), ipaddr.process(incomingIP));
          });
          if (!whitelisted) {
            errLog("requesting ip not in whitelist [%s]", incomingIP);
            return Promise.reject(new Error("not in whitelist"));
          }
        }

        // Ask auth server to sign the account identity.
        return [
          account,
          authServer.adminApi.createVerifiedIdentityToken(
            account.username,
            incomingIP,
            null,
            req.body ? req.body.ttl : undefined
          )
        ];
      })
      .spread(function(account, signedToken) {
        log("got signed token");
        cb(null, {account: account.toObject(), token: signedToken});
      })
      .catch(function(err) {
        errLog("authServer token lookup failed: %s",err.message);
        cb(null, false);
      });
  };

  exports.grantClientToken = function (credentials, req, cb) {
    return grantClientTokenEx(credentials, req, function(err, authData) {
      if (authData) {
        cb(err, authData.token);
      } else {
        cb(err);
      }
    });
  };

  exports.authenticateToken = function(tokenId, req, cb) {
    // Load auth server when we need it to prevent circular dependencies (auth server uses nqmUtils)
    var authServer = require("nqm-core-auth-server");

    var reqIP = ipaddr.process(requestIP.getClientIp(req));
    log("authenticateToken - performing jwt decode");
    var decoded;
    authServer.testApi.verify(tokenId)
      .then(function(decodedToken) {
        decoded = decodedToken;

        // Check referrers match.
        if (!_.isEqual(ipaddr.process(decoded.ref), reqIP)) {
          errLog("auth token remote address mismatch, wanted %s got %s", decoded.ref, reqIP);
          return Promise.reject(new Error("mismatched remote address"));
        }

        // Check expiry time
        if (!decoded.exp || (decoded.exp * 1000) < Date.now()) {
          errLog("auth token expired");
          return Promise.reject(new Error("token expired"));
        }

        if (decoded.ver) {
          // This is a verified token - check the account.
          return authServer.adminApi.getAccountForUser(decoded.sub);
        } else {
          // Not verified - this is an ad-hoc token with an arbitrary subject.
          return null;
        }
      })
      .then(function(account) {
        if (account) {
          // Check account expiry.
          if (account.expires && account.expires < Date.now()) {
            errLog("account %s expired at %s", account.username, (new Date(account.expires)).toString());
            return Promise.reject(new Error("account expired"));          
          }
          
          // Check account whitelist.
          if (account.whitelist && account.whitelist.length) {
            var whitelisted = _.find(account.whitelist, function(ip) {
              return _.isEqual(ipaddr.process(ip), reqIP);
            });
            if (!whitelisted) {
              errLog("requesting ip not in whitelist [%s]", reqIP);
              return Promise.reject(new Error("IP not in whitelist"));
            }
          }

        } else {
          if (decoded.ver) {
            // Verified tokens must have a valid account.
            errLog("no account for token %s", decoded.sub);
            return Promise.reject(new Error("account not found"));
          }
        }

        var authData = {
          account: account,
          capability: decoded,
          token: tokenId,
        };
        req.clientId = authData;
        cb(null, authData);
      })
      .catch(function(err) {
        errLog("failed to verify jwt: %s", err.message);
        cb(null, false);
      });
  };

  var doCheckAccountSecret = function(account, secret) {
    var bcrypt = Promise.promisifyAll(require("bcryptjs"));
    if (!account || !secret) {
      return Promise.reject(new Error("invalid args"));
    }
    
    // For user accounts, check the account uses local authentication (i.e. oauth-based accounts aren't supported).
    if (account.accountType === constants.userAccountType && (!account.oauth || !account.oauth.local)) {
      log("not a local user account")
      return Promise.resolve(null);
    } else if (!account.hash) {
      log("no hash present");
      return Promise.resolve(null);
    }
    
    // Compare the hash.
    return bcrypt.compareAsync(secret, account.hash)
      .then(function(result) {
        if (result) {
          log("hash compare OK");
          return account;
        } else {
          errLog("hash compare failed");
          return null;
        }
      });
  };

  exports.checkAccountSecret = function(account, secret, cb) {
    doCheckAccountSecret(account, secret)
      .then(function(share) {
        if (!share) {
          errLog("checkAccountSecret - hash compare failed");
          cb(new Error("hash compare failed"));
        } else {
          cb(null, share);
        }
      })
      .catch(function(err) {
        errLog("checkAccountSecret - exception [%s]", err.message);
        cb(err);
      });
  };

}(module.exports));

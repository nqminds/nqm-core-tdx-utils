
(function(exports) {
  "use strict";

  var Promise = require("bluebird");
  var errLog = require("debug")("nqm-process:check-params:error");
  var constants = require("nqm-core-constants");

  var checkParams = exports.check = function(param, type, name) {
    var typeCheck = typeof type === "string" ? type : type.name;
    if (typeof param === "undefined" || param.constructor.name !== typeCheck) {
      var errText = "checkParams failed for '" + (name || "[unnamed param]") + "': wanted '" + typeCheck + "', got '" + (param ? param.constructor.name : "undefined") + "'";
      errLog(errText);
      return Promise.reject(new Error(errText));
    }
    return Promise.resolve();
  };

  exports.checkAuthToken = function(authToken) {
    var checks = [
      checkParams(authToken, Object, "authToken"),
      checkParams(authToken.token, String, "authToken.token"),
      checkParams(authToken.capability, Object, "authToken.capability"),
      checkParams(authToken.capability.sub, String, "authToken.sub"),
      new Promise(function(resolve, reject) {
        if (authToken.capability.sub.length > 0) {
          resolve();
        } else {
          reject(new Error("empty subject length"));
        }
      })
    ];
    return Promise.all(checks);
  };


}(module.exports));

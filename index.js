module.exports = (function() {
  "use strict";
  var _ = require("lodash");

  var coreUtils = require("nqm-core-utils");

  var utils = _.extend({}, coreUtils, {
    loadConfig: require("./lib/load-config"),
    applyJSONPatch: require("./lib/apply-json-patch"),
    params: require("./lib/check-params"),
    oauthHooks: require("./lib/oauth-hooks"),
    email: require("./lib/email"),
  });

  return utils;
}());

module.exports = (function() {
  "use strict";
  var _ = require("lodash");
  var coreUtils = require("nqm-core-utils");

  // Create a MongoDB ObjectId from a timestamp (n.b. 1 second granularity).
  var objectIdFromTimestamp = function (timestamp) {
    return Math.floor(timestamp / 1000).toString(16) + "0000000000000000";
  };

  // Merge with nqm-core-utils
  var utils = _.extend(
    {},
    coreUtils,
    {
      loadConfig: require("./lib/load-config"),
      applyJSONPatch: require("./lib/apply-json-patch"),
      params: require("./lib/check-params"),
      oauthHooks: require("./lib/oauth-hooks"),
      objectIdFromTimestamp: objectIdFromTimestamp,
      email: require("./lib/email"),
    }
  );

  return utils;
}());

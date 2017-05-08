
module.exports = (function(key) {
  "use strict";
  
  var log = require("debug")("nqm-utils:loadConfig");
  var errLog = require("debug")("nqm-utils:loadConfig:error");
  var argv = require("minimist")(process.argv.slice(2));
  var path = require("path");

  log("starting in %s", __dirname);
  var configFile;
  if (!argv.config) {
    log("using default config file");
    configFile = "./config.json";
  } else {
    configFile = argv.config;
  }
  configFile = path.resolve(path.dirname(require.main.filename), configFile);
  log("config file is %s", configFile);  
  
  var config;
  try {
    log("loading config file");
    var loaded = require(configFile);
    config = loaded[key] || loaded; 
  } catch (e) {
    errLog("failed to load config file %s [%s]", configFile, e.message);
    process.exit();
  }
  log("config is %j", config);

  return config;
});
module.exports = (function() {
  "use strict";

  var _ = require("lodash");

  var markPointerModified = function(doc, pointer) {
    doc.markModified(pointer);
  };

  var setPointer = function(doc, path, value) {
    var parser = require("mongo-parse");
    var pointer = parser.DotNotationPointers(doc, path)[0];
    pointer.val = value;
    markPointerModified(doc, path);
  };

  //
  // n.b. nqm-core-command/domain/dataset-document has a similar function, make sure they are in sync.
  // TODO - refactor
  //
  var applyUpdate = function(update, markModified) {
    // Default to mongoose model.
    markModified = markModified || markPointerModified;

    var parser = require("mongo-parse");
    var pointer = parser.DotNotationPointers(this, update.p)[0];
    var tmp;
    switch (update.m) {
      case "a":
        // add
        // Determine if target is an array
        if (pointer.val && pointer.val instanceof Array) {
          pointer.val = _.union(pointer.val, [].concat(update.v));
        } else {
          pointer.val = update.v;
        }
        markModified(this, update.p);
        break;
      case "r":
        // replace
        pointer.val = update.v;
        markModified(this, update.p);
        break;
      case "d":
        // delete
        if (pointer.val && pointer.val instanceof Array) {
          _.pull(pointer.val, update.v);
        } else {
          delete pointer.propertyInfo.obj[pointer.propertyInfo.last];
        }
        markModified(this, update.p);
        break;
      case "m":
        // move
        // TODO - untested - review
        tmp = pointer.val;
        delete pointer.propertyInfo.obj[pointer.propertyInfo.last];
        markModified(this, update.p);

        pointer = parser.DotNotationPointers(this, update.v)[0];
        pointer.val = tmp;
        markModified(this, update.v);
        break;
      case "c":
        // copy
        tmp = pointer.val;
        pointer = parser.DotNotationPointers(this, update.v)[0];
        pointer.val = tmp;
        markModified(this, update.v);
        break;
      default:
        errLog("unrecognised update method '%s'", update.m);
        break;
    }
  };

  return applyUpdate;
}());

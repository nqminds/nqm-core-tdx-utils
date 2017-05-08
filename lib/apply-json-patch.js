module.exports = (function() {
  "use strict";

  var markPointerModified = function(doc, pointer) {
    doc.markModified(pointer);
  };

  var setPointer = function(doc, path, value) {
    var parser = require("mongo-parse");
    var pointer = parser.DotNotationPointers(doc, path)[0];
    pointer.val = value;
    markPointerModified(doc, path);
  };

  var applyUpdate = function(update) {
    var parser = require("mongo-parse");
    var pointer;
    var tmp;
    switch (update.m) {
      case "a":
        // add
        pointer = parser.DotNotationPointers(this, update.p)[0];
        // Determine if target is an array
        if (pointer.val && pointer.val instanceof Array) {
          pointer.val.push(update.v);
        } else {
          pointer.val = update.v;
        }
        markPointerModified(this, update.p);
        break;
      case "r":
        // replace
        setPointer(this, update.p, update.v);
        break;
      case "d":
        // delete
        pointer = parser.DotNotationPointers(this, update.p)[0];
        if (pointer.val && pointer.val instanceof Array) {
          pointer.val.pull(update.v);
        } else {
          delete pointer.propertyInfo.obj[pointer.propertyInfo.last];
        }
        markPointerModified(this, update.p);
        break;
      case "m":
        // move
        pointer = parser.DotNotationPointers(this, update.p)[0];
        tmp = pointer.val;
        // TODO - untested - review
        delete pointer.propertyInfo.obj[pointer.propertyInfo.last];
        markPointerModified(this, update.p);
        setPointer(this, update.v, tmp);
        break;
      case "c":
        // copy
        pointer = parser.DotNotationPointers(this, update.p)[0];
        setPointer(this, update.v, pointer.val);
        break;
      default:
        errLog("unrecognised update method '%s'", update.m);
        break;
    }
  };

  return applyUpdate;
}());

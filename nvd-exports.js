/* 
    This is where we are going to turn the nvd-cli code into a module.exports
    API

*/

'use strict';
const fs = require('fs');                                       // for reading the JSON file
var extract = require('extract-zip');
const util = require('util');                                   // for using child-process
const PDFDocument = require('pdfkit');
const exec = require('child-process-promise').exec;
const config = require('./config.js');                          // config file for script
const NVDClass = require('./NVDJSONClass.js');                  // helper for getting at NVD Data for specific years
const debug = config.debug;                                     // used to allow/disallow verbose logging
const ver = '0.5.0';                                            // arbitrary version number, should match NPM version

var globalNVDJSON;

module.exports.sayHi = function() {
    return 'hi';
}
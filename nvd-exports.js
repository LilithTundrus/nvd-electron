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

module.exports.getArgs = function (optsObj) {
    // deconstruct the obj here
    return console.log(optsObj);
}
 
// NON-PUBLIC functions

function capitalizeFirstLetter(string) {                            // used to clean up some of the NVD names for products
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function getNVDZipFile(url, fileLocation) {
    return new Promise((resolve, reject) => {
        exec(`curl "${url}" > ${fileLocation}`)
            .then(function (result) {
                var stdout = result.stdout;
                var stderr = result.stderr;
                if (debug) { console.log('stderr: ', stderr); }
                return resolve(stdout);
            });
    });
}

// this is a hacky solution.
function extractZipFile(fileNameToExtract) {
    return new Promise((resolve, reject) => {
        return extract(fileNameToExtract, { dir: process.cwd() }, function (err) {
            return resolve(err);
        });
    });
}

function productSearchHandler(yearToSearch, productSearchQuery, outputLocation, outputFormat, outputName) {
    if (typeof (productSearchQuery) !== 'string') {
        return console.log('Error: Product search term must be a string');
    } else if (productSearchQuery.length < 3) {
        console.log(`Error: please give a product name with at least 3 characters`);
        process.exit(0);
    } else {
        console.log(`Searching NVD year ${yearToSearch} for ${productSearchQuery}`);
        let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
        return Promise.resolve()                                               // start the promise chain as resolved to avoid issues
            .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
            .then(() => extractZipFile(NVDFileData.zipFileLocation))
            .then(() => {
                let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
                let parsedNVDData = JSON.parse(NVDJSON);
                globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
                return parsedNVDData;
            })
            .then((NVDData) => searchNVDProducts(NVDData, productSearchQuery))
            .then((affectedItemsArray) => {
                if (outputFormat == '.pdf') {
                    writePDFReport(affectedItemsArray, `SEARCH '${productSearchQuery}' ${yearToSearch}`, outputName);
                } else if (outputFormat == '.txt') {
                    writeTextReport(affectedItemsArray, `SEARCH '${productSearchQuery}' ${yearToSearch}`, outputName)
                } else {
                    throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
                }
            })
            .then(() => {
                if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
            })
            .catch((err) => {
                console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
            })
    }
}

function vendorSearchHanlder(yearToSearch, vendorSearchQuery, outputLocation, outputFormat, outputName) {
    if (typeof (vendorSearchQuery) !== 'string') {
        return console.log('Error: Product search term must be a string');
    } else if (vendorSearchQuery.length < 3) {
        console.log(`Error: please give a product name with at least 3 characters`);
        process.exit(0);
    } else {
        console.log(`Searching NVD year ${yearToSearch} for ${vendorSearchQuery}`);
        let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
        return Promise.resolve()                                               // start the promise chain as resolved to avoid issues
            .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
            .then(() => extractZipFile(NVDFileData.zipFileLocation))
            .then(() => {
                let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
                let parsedNVDData = JSON.parse(NVDJSON);
                globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
                return parsedNVDData;
            })
            .then((NVDData) => searchNVDProducts(NVDData, vendorSearchQuery))
            .then((affectedItemsArray) => {
                if (outputFormat == '.pdf') {
                    writePDFReport(affectedItemsArray, `SEARCH '${vendorSearchQuery}' ${yearToSearch}`, outputName);
                } else if (outputFormat == '.txt') {
                    writeTextReport(affectedItemsArray, `SEARCH '${vendorSearchQuery}' ${yearToSearch}`, outputName);
                } else {
                    throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
                }
            })
            .then(() => {
                if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
            })
            .catch((err) => {
                console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
            })
    }
}

function NVDYearValidator(yearToValidate) {
    if (typeof (yearToValidate) !== 'number') {
        return false;
    } else {
        if (isNaN(yearToValidate) || yearToValidate.toString().charAt(0) !== '2' || yearToValidate.toString().charAt(1) !== '0' || yearToValidate.length < 4 || yearToValidate.length > 4 || yearToValidate < 2003) {
            return false;
        }
        return true;
    }
}

function parseNVDData(NVDObjArray, checklist) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var affectedItems = [];
    let swChecklist = JSON.parse(fs.readFileSync(checklist, 'utf-8'));
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of vendors to check for vulnerabilities
            swChecklist.forEach((item, itemIndex) => {
                if (entryV.vendor_name.toLowerCase() == item.manufacturerName.toLowerCase()) {
                    entryV.product.product_data.forEach((product, productIndex) => {
                        if (product.product_name == item.softwareName.toLowerCase()) {
                            if (debug) { console.log(entry); }
                            var versionsAffected = [];
                            var referenceURLs = [];
                            entryV.product.product_data[0].version.version_data.forEach((version) => {
                                versionsAffected.push(version.version_value);
                            });
                            if (entry.cve.hasOwnProperty('references')) {
                                entry.cve.references.reference_data.forEach((ref, refIndex) => {
                                    referenceURLs.push(ref.url);
                                });
                            }
                            // push all of the data to an the affectedItem Obj
                            affectedItem.ID = entry.cve.CVE_data_meta.ID;
                            affectedItem.vendorName = entryV.vendor_name;
                            affectedItem.productName = entryV.product.product_data[0].product_name;
                            affectedItem.publishedDate = entry.publishedDate;
                            affectedItem.lastModifiedDate = entry.lastModifiedDate;
                            affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                            affectedItem.versionsAffected = versionsAffected;
                            affectedItem.referenceURLs = referenceURLs
                            // validate that v3 exists
                            if (entry.impact.hasOwnProperty('baseMetricV3')) {
                                affectedItem.v3SeverityScore = {
                                    severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                                    scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                                }
                                affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector;
                            } else {
                                affectedItem.v3SeverityScore = {
                                    severity: 'NONE',
                                    scoreString: 'NONE'
                                }
                            }
                            // Do the same for v2
                            if (entry.impact.hasOwnProperty('baseMetricV2')) {
                                affectedItem.v2SeverityScore = {
                                    severity: entry.impact.baseMetricV2.severity,
                                    scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                                }
                            } else {
                                affectedItem.v2SeverityScore = {
                                    severity: 'NONE',
                                    scoreString: 'NONE'
                                }
                            }
                            affectedItems.push(affectedItem);       // push the affected item to the array to return
                        }
                    });
                }
            });
        });
    });
    console.log(`Number of matches found: ${affectedItems.length}`);
    return affectedItems;
}

function searchNVDProducts(NVDObjArray, productSearchQuery) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var matches = [];
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of products to match
            entryV.product.product_data.forEach((product, productIndex) => {
                if (product.product_name == productSearchQuery.toLowerCase() || product.product_name.includes(productSearchQuery.toLowerCase())) {
                    if (debug) { console.log(entry); }
                    var versionsAffected = [];
                    var referenceURLs = [];
                    entryV.product.product_data[0].version.version_data.forEach((version) => {
                        versionsAffected.push(version.version_value);
                    });
                    if (entry.cve.hasOwnProperty('references')) {
                        entry.cve.references.reference_data.forEach((ref, refIndex) => {
                            referenceURLs.push(ref.url);
                        });
                    }
                    // push all of the data to an the affectedItem Obj
                    affectedItem.ID = entry.cve.CVE_data_meta.ID;
                    affectedItem.vendorName = entryV.vendor_name;
                    affectedItem.productName = entryV.product.product_data[0].product_name;
                    affectedItem.publishedDate = entry.publishedDate;
                    affectedItem.lastModifiedDate = entry.lastModifiedDate;
                    affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                    affectedItem.versionsAffected = versionsAffected;
                    affectedItem.referenceURLs = referenceURLs
                    // validate that v3 exists
                    if (entry.impact.hasOwnProperty('baseMetricV3')) {
                        affectedItem.v3SeverityScore = {
                            severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                            scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                        }
                        affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector;
                    } else {
                        affectedItem.v3SeverityScore = {
                            severity: 'NONE',
                            scoreString: 'NONE'
                        }
                    }
                    // Do the same for v2
                    if (entry.impact.hasOwnProperty('baseMetricV2')) {
                        affectedItem.v2SeverityScore = {
                            severity: entry.impact.baseMetricV2.severity,
                            scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                        }
                    } else {
                        affectedItem.v2SeverityScore = {
                            severity: 'NONE',
                            scoreString: 'NONE'
                        }
                    }
                    matches.push(affectedItem);                     // push the affected item to the array to return
                }
            });
        });
    });
    console.log(`Number of matches found for '${productSearchQuery}': ${matches.length}`);
    return matches;
}

function searchNVDVendors(NVDObjArray, vendorSearchQuery) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var matches = [];
    let swChecklist = JSON.parse(fs.readFileSync(checklist, 'utf-8'));
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of vendors to check for vulnerabilities
            if (entryV.vendor_name.toLowerCase() == vendorSearchQuery.toLowerCase()) {
                entryV.product.product_data.forEach((product, productIndex) => {
                    if (debug) { console.log(entry); }
                    var versionsAffected = [];
                    var referenceURLs = [];
                    entryV.product.product_data[0].version.version_data.forEach((version) => {
                        versionsAffected.push(version.version_value);
                    });
                    if (entry.cve.hasOwnProperty('references')) {
                        entry.cve.references.reference_data.forEach((ref, refIndex) => {
                            referenceURLs.push(ref.url);
                        });
                    }
                    // push all of the data to an the affectedItem Obj
                    affectedItem.ID = entry.cve.CVE_data_meta.ID;
                    affectedItem.vendorName = entryV.vendor_name;
                    affectedItem.productName = entryV.product.product_data[0].product_name;
                    affectedItem.publishedDate = entry.publishedDate;
                    affectedItem.lastModifiedDate = entry.lastModifiedDate;
                    affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                    affectedItem.versionsAffected = versionsAffected;
                    affectedItem.referenceURLs = referenceURLs
                    // validate that v3 exists
                    if (entry.impact.hasOwnProperty('baseMetricV3')) {
                        affectedItem.v3SeverityScore = {
                            severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                            scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                        }
                        affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector;
                    } else {
                        affectedItem.v3SeverityScore = {
                            severity: 'NONE',
                            scoreString: 'NONE'
                        }
                    }
                    // Do the same for v2
                    if (entry.impact.hasOwnProperty('baseMetricV2')) {
                        affectedItem.v2SeverityScore = {
                            severity: entry.impact.baseMetricV2.severity,
                            scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                        }
                    } else {
                        affectedItem.v2SeverityScore = {
                            severity: 'NONE',
                            scoreString: 'NONE'
                        }
                    }
                    matches.push(affectedItem);       // push the affected item to the array to return
                });
            }
        });
    });
    console.log(`Number of matches found for '${vendorSearchQuery}': ${matches.length}`);
    return matches;
}

function writePDFReport(affectedItemsArray, timeArg, outputArg) {
    var doc = new PDFDocument;
    doc.pipe(fs.createWriteStream(`${outputArg}.pdf`));
    doc.fontSize(16);
    doc.text(`NVD ${timeArg} Vulnerability Check Report ${new Date().toDateString()}`, { align: 'center', stroke: true });
    doc.fontSize(12);
    doc.text(`\n\nCVE data version: ${globalNVDJSON.CVE_data_version}`);
    doc.text(`CVE count: ${globalNVDJSON.CVE_data_numberOfCVEs}`);
    doc.text(`Last Updated: ${globalNVDJSON.CVE_data_timestamp}`);
    doc.text(`Checklist File: ${config.checklistName}`);
    doc.text(`Number of Vulnerabilites Matched: ${affectedItemsArray.length}`);
    doc.fontSize(14);
    doc.moveDown();
    // get each affected item's data and format it
    affectedItemsArray.forEach((entry, index) => {
        doc.text(`\n${capitalizeFirstLetter(entry.vendorName)} ${capitalizeFirstLetter(entry.productName)} (${entry.ID})`, { stroke: true });
        doc.text(`Published: ${entry.publishedDate}    Modified: ${entry.lastModifiedDate}`);
        doc.text(`Versions Affected: ${entry.versionsAffected.join(', ')}`);
        doc.text(`Attack Vector: ${entry.attackVector}`);
        doc.text(`\nDescription: ${entry.vulnerabilityDescription}`);
        doc.text(`\nV3 Score: ${entry.v3SeverityScore.severity} (${entry.v3SeverityScore.scoreString})`);
        doc.text(`V2 Score: ${entry.v2SeverityScore.severity} (${entry.v2SeverityScore.scoreString})`);
        doc.text(`\nReferences:`);
        doc.fillColor('blue');                                      // color ref URLs blue
        doc.text(`${entry.referenceURLs.join('\n')}`);
        doc.fillColor('black');                                     // reset the color
        doc.moveDown();                                             // Allow for some whitespace in between entries
    });
    doc.text('\n\nEnd of File');
    doc.end();
    console.log(`Wrote report as ${outputArg}.pdf`);
}

function writeTextReport(affectedItemsArray, timeArg, outputArg) {
    var textData = '';
    textData = textData + `NVD ${timeArg} Vulnerability Check Report ${new Date().toDateString()}`;
    textData = textData + `\n\nCVE data version: ${globalNVDJSON.CVE_data_version}`;
    textData = textData + `\nCVE count: ${globalNVDJSON.CVE_data_numberOfCVEs}`;
    textData = textData + `\nLast Updated: ${globalNVDJSON.CVE_data_timestamp}`;
    textData = textData + `\nChecklist File: ${config.checklistName}`;
    textData = textData + `\nNumber of Vulnerabilites Matched: ${affectedItemsArray.length}`;
    textData = textData + `\n\n`;                                   // Extra spacing before iterating through the array
    // get each affected item's data and format it
    affectedItemsArray.forEach((entry, index) => {
        textData = textData + `\n${capitalizeFirstLetter(entry.vendorName)} ${capitalizeFirstLetter(entry.productName)} (${entry.ID})`;
        textData = textData + `\nPublished: ${entry.publishedDate}    Modified: ${entry.lastModifiedDate}`;
        textData = textData + `\nVersions Affected: ${entry.versionsAffected.join(', ')}`;
        textData = textData + `\nAttack Vector: ${entry.attackVector}`;
        textData = textData + `\nDescription: ${entry.vulnerabilityDescription}`;
        textData = textData + `\nV3 Score: ${entry.v3SeverityScore.severity} (${entry.v3SeverityScore.scoreString})`;
        textData = textData + `\nV2 Score: ${entry.v2SeverityScore.severity} (${entry.v2SeverityScore.scoreString})`;
        textData = textData + `\nReferences:\n`;
        textData = textData + `${entry.referenceURLs.join('\n')}`;
        textData = textData + `\n`;                             // Allow for some whitespace in between entries
    });
    textData = textData + `\n\n\nEnd of File`;                  // Make sure the entire array was iterated through

    fs.writeFileSync(`${outputArg}.txt`, textData);
    console.log(`Wrote report as ${outputArg}.txt`);
}

function NVDCheckFull(yearToSearch, outputLocation, outputFormat, checklistLocation, outputName) {
    let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
    console.log(`Getting NVD FULL data to compare against ${checklistLocation}`);
    return Promise.resolve()                                        // start the promise chain as resolved to avoid issues
        .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
        .then(() => extractZipFile(NVDFileData.zipFileLocation))
        .then(() => {
            let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
            let parsedNVDData = JSON.parse(NVDJSON);
            globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
            return parsedNVDData;
        })
        .then((NVDData) => parseNVDData(NVDData, checklistLocation))                   // sort through the entire data list and parse for matches
        .then((affectedItemsArray) => {
            if (outputFormat == '.pdf') {
                writePDFReport(affectedItemsArray, yearToSearch, outputName);
            } else if (outputFormat == '.txt') {
                writeTextReport(affectedItemsArray, yearToSearch, outputName);
            } else {
                throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
            }
        })
        .then(() => {
            if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
        })
        .catch((err) => {
            console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
        })
}

function NVDCheckRecent(outputLocation, outputFormat, checklistLocation, outputName) {
    console.log(`Getting NVD recent data to compare against ${checklistLocation}`);
    Promise.resolve()                                               // start the promise chain as resolved to avoid issues
        .then(() => getNVDZipFile(config.NVDURLRecent, config.zipFileNameRecent))        // Get the RECENT json that is in .zip format
        .then(() => extractZipFile(config.zipFileNameRecent))
        .then(() => {
            let NVDJSON = fs.readFileSync(config.NVDJSONFileNameRecent, 'utf-8');
            let parsedNVDData = JSON.parse(NVDJSON);
            globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
            return parsedNVDData;
        })
        .then((NVDData) => parseNVDData(NVDData, checklistLocation))
        .then((affectedItemsArray) => {
            if (outputFormat == '.pdf') {
                writePDFReport(affectedItemsArray, 'RECENT', outputName);
            } else if (outputFormat == '.txt') {
                writeTextReport(affectedItemsArray, 'RECENT', outputName);
            } else {
                throw new Error('Error: Unknown output format was passed to function NVDCheckRecent');
            }
        })
        .then(() => {
            if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
        })
        .catch((err) => {
            console.log(`Ended with error at ${new Date().toISOString()}: ${err}`);
        })
}
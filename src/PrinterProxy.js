/**
 *
 * ____ _ ____ ___  ____ _ _  _ ___    ___  ____ ____ _  _ _   _
 * |__| | |__/ |__] |__/ | |\ |  |     |__] |__/ |  |  \/   \_/
 * |  | | |  \ |    |  \ | | \|  |     |    |  \ |__| _/\_   |
 *
 * AirPrint Proxy
 *
 * Copyright (C) 2017 Marcus Zhou
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

"use strict";

const mdns = require("multicast-dns")();
const EventEmitter = require("events");
const utils = require("./utils");
const resolveAndCreate = require("./resolve");
const ServiceTypes = require("./ServiceTypes");

function PrinterProxy() {
    this.printers = [];
    this.serviceUniversalIpp = ServiceTypes.UniversalIpp;
    this.serviceUniversalIpps = ServiceTypes.UniversalIpps;
    this.serviceIpp = ServiceTypes.Ipp;
    this.serviceIpps = ServiceTypes.Ipps;
    this.proxyService = ServiceTypes.Proxy;

    this.scannerService = ServiceTypes.Scanner;
    this.uScanService = ServiceTypes.UScan;
    // _uscans._tcp N/A
    // _printer._tcp N/A
    // _ptp._tcp N/A
    this.pdlService = ServiceTypes.Pdl;

    mdns.on("query", this.onServiceQuery.bind(this));
}

utils.inherits(PrinterProxy, EventEmitter);

PrinterProxy.prototype.onServiceQuery = function (query) {
    const that = this;
    query.questions.forEach(function (t) {
        //console.log("Question: "+JSON.stringify(t));

        //Discovery
        if (t.type === "PTR") {
	if (Object.keys(ServiceTypes).includes(t.name)) {
	console.log(t.name + ' PTR?');
	} else {
	console.log('                  ... other query: ' + t.name + ' PTR?');
	}
            if (ServiceTypes.Print.includes(t.name)) {
                that.onPrinterListRequest(ServiceTypes.SecurePrint.includes(t.name), false);
            } else if (ServiceTypes.Scan.includes(t.name)) {
                that.onScannerListRequest(false);
            }
        }

        //Address Record
        if (t.type === "A") {
            that.printers.forEach(function (printer) {
                if (printer.host === t.name) {
                    //Respond printer IP
                    mdns.respond({
                        answers: [
                            {
                                name: printer.host,
                                type: "A",
                                ttl: 300,
                                data: printer.ip
                            }
                        ]
                    });
                }
            });
        }

        //Txt
        if (t.type === "TXT") {
            const answers = [];
            that.printers.forEach(function (printer) {
                if (t.name === printer.service) {
                    answers.push({
                        name: printer.service,
                        type: "TXT",
                        ttl: 300,
                        data: printer.compileRecordOptions()
                    });
                    answers.push({
                        name: printer.service,
                        type: "PTR",
                        ttl: 300,
                        data: printer.host
                    });
                    answers.push({
                        name: printer.host,
                        type: "A",
                        ttl: 300,
                        data: printer.ip
                    });
                } else if (t.name === printer.serviceIpps) {
                    answers.push({
                        name: printer.serviceIpps,
                        type: "TXT",
                        ttl: 300,
                        data: printer.compileRecordOptions()
                    });
                    answers.push({
                        name: printer.serviceIpps,
                        type: "PTR",
                        ttl: 300,
                        data: printer.host
                    });
                    answers.push({
                        name: printer.host,
                        type: "A",
                        ttl: 300,
                        data: printer.ip
                    });
                }
            });
            mdns.respond({ answers: answers });
        }
    });
};

PrinterProxy.prototype.onScannerListRequest = function (flush) {
    const proxy = this;
    const flushCache = flush || false;

	if (!flush) {
		console.log('onScannerListRequest');
	}

    this.printers.forEach(function (printer) {

        var answers = [];

        //txt record
        // answers.push({
        //     name: printer.scannerService,
        //     type: "TXT",
        //     flush: flushCache,
        //     ttl: 300,
        //     data: printer.compileRecordOptions()
        // });
        //proxy ptr
        answers.push({
            name: proxy.proxyService,
            type: "PTR",
            flush: flushCache,
            ttl: 300,
            data: proxy.uScanService,
        });
        answers.push({
            name: proxy.proxyService,
            type: "PTR",
            flush: flushCache,
            ttl: 300,
            data: proxy.scannerService,
        });
        answers.push({
            name: proxy.scannerService,
            type: "PTR",
            ttl: 300,
            data: printer.scannerService,
        });
        answers.push({
            name: proxy.uScanService,
            type: "PTR",
            ttl: 300,
            data: printer.uScanService,
        });
        answers.push({
            name: printer.uScanService,
            type: "SRV",
            flush: flushCache,
            ttl: 300,
            data: {
                port: printer.port,
                weight: 0,
                priority: 40,
                target: printer.host
            }
        });
        answers.push({
            name: printer.scannerService,
            type: "SRV",
            flush: flushCache,
            ttl: 300,
            data: {
                port: printer.port,
                weight: 0,
                priority: 40,
                target: printer.host
            }
        });

        mdns.respond({
            answers: answers
        });
    });
}

PrinterProxy.prototype.onPrinterListRequest = function (requestIpps, flush) {
    const proxy = this;
    const flushCache = flush || false;

    this.printers.forEach(function (printer) {
        if (requestIpps && !printer.useIpps) return;

        var answers = [];

        //txt record
        answers.push({
            name: requestIpps ? printer.serviceIpps : printer.service,
            type: "TXT",
            flush: flushCache,
            ttl: 300,
            data: printer.compileRecordOptions()
        });
        //proxy ptr
        answers.push({
            name: proxy.proxyService,
            type: "PTR",
            flush: flushCache,
            ttl: 300,
            data: requestIpps ? proxy.serviceIpps : proxy.serviceIpp
        });
        //universal record, point ipp to service
        answers.push({
            name: requestIpps ? proxy.serviceUniversalIpps : proxy.serviceUniversalIpp,
            type: "PTR",
            ttl: 300,
            data: requestIpps ? printer.serviceIpps : printer.service
        });
        //ipp record, point ipp to service
        answers.push({
            name: requestIpps ? proxy.serviceIpps : proxy.serviceIpp,
            type: "PTR",
            ttl: 300,
            data: requestIpps ? printer.serviceIpps : printer.service
        });
        //A record, for host to service
        answers.push({
            name: printer.host,
            type: "A",
            flush: flushCache,
            ttl: 300,
            data: printer.ip
        });
        //with subtype record
        answers.push({
            name: requestIpps ? printer.serviceIpps : printer.service,
            type: "SRV",
            flush: flushCache,
            ttl: 300,
            data: {
                port: printer.port,
                weight: 0,
                priority: 40,
                target: printer.host
            }
        });

        mdns.respond({
            answers: answers
        });
    });
};

/**
 * Broadcast this printer on the local network
 *
 * @param {Printer} printer
 */
PrinterProxy.prototype.addPrinter = function (printer) {
    //Do not update again
    if (this.printers.filter(function (t) { return t.uuid === printer.uuid; }).length > 0) {
        return false;
    }
    //Handle updates and readvertise the printer
    /*const adv = mdns.createAdvertisement(
        printer.useIpps ? this.serviceTypeIpps : this.serviceTypeIpp,
        printer.port,
        {
            txtRecord: printer.compileRecordOptions(),
            name: printer.name,
            host: printer.host
        }
    );
    printer.on("update", function () {
        //Update txt record if there is an update for options
        adv.updateTXTRecord(printer.compileRecordOptions());
    });
    this.printers.push({ object: printer, advertisement: adv });
    adv.start();
    */

    const update = function () {
        this.onPrinterListRequest(false, true);
        this.onPrinterListRequest(true, true);
        this.onScannerListRequest(true);
    };

    printer.on("update", update.bind(this));
    this.printers.push(printer);
    update.call(this);
};

/**
 * Automatically resolves the name and capabilities from the printer
 * if the printer does accept unicast mdns query from the address
 * that airprint-proxy is running on.
 *
 * @param address IP address of the printer
 * @param callback Callback function. See resolve.js.
 *                 You don't need to add the printers in the callback
 *                 function.
 */
PrinterProxy.prototype.resolvePrinter = function (address, argv, callback) {
    resolveAndCreate(address, argv, function (error, printers) {
        if (typeof callback !== "undefined") callback(error, printers);
        if (error) {
            console.error("Error resolving printers from address", error);
            return;
        }
        printers.forEach(this.addPrinter.bind(this));
    }.bind(this));
};

module.exports = PrinterProxy;
module.exports.default = PrinterProxy;

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

const PrinterProxy = require("./PrinterProxy");

console.info("[*] Setting up printers...");

const proxy = new PrinterProxy();

function onNewPrinter(err, printers){
    const printer = printers[0];
    console.info(`[*] ${printer.ip} is resolved as '${printer.name}'`);
}

// proxy.resolvePrinter("10.20.0.95", onNewPrinter);
// proxy.resolvePrinter("10.20.0.92", onNewPrinter);
proxy.resolvePrinter("10.35.0.18", onNewPrinter);

setInterval(function () {
    //Readvertise every 2 seconds
    proxy.onPrinterListRequest(false, false);
}, 2000);

console.info("[*] Advertising printers");

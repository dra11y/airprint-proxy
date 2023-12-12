const ServiceTypes = {
	UniversalIpp: "_universal._sub._ipp._tcp.local",
	UniversalIpps: "_universal._sub._ipps._tcp.local",
	Ipp: "_ipp._tcp.local",
	Ipps: "_ipps._tcp.local",
	Proxy: "_services._dns-sd._udp.local",
	Scanner: "_scanner._tcp.local",
	UScan: "_uscan._tcp.local",
	Pdl: "_pdl-datastream._tcp.local",

	Print: function() {
		return [
			this.Ipp,
            this.Ipps,
			this.UniversalIpp,
            this.UniversalIpps,
			this.Pdl,
        ];
	},

    SecurePrint: function() {
        return [
            this.Ipps,
            this.UniversalIpps,
        ];
    },

	Scan: function() {
        return [
            this.UScan,
            this.Scanner,
        ];
	},
}

module.exports = ServiceTypes;
module.exports.default = ServiceTypes;

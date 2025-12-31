// pac-server.js - Standalone PAC file server
const http = require('http');
const fs = require('fs');

const PAC_FILE = `function FindProxyForURL(url, host) {
    // Your proxy server address
    var PROXY = "PROXY localhost:3128";
    
    // Domains that go through proxy
    var proxiedDomains = [
        "*.cloud.sap",
        "*.github.com",
    ];
    
    // Local/internal addresses
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "localhost") ||
        shExpMatch(host, "127.*") ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "172.17.*") ||
        shExpMatch(host, "172.18.*") ||
        shExpMatch(host, "172.19.*") ||
        shExpMatch(host, "172.20.*") ||
        shExpMatch(host, "172.21.*") ||
        shExpMatch(host, "172.22.*") ||
        shExpMatch(host, "172.23.*") ||
        shExpMatch(host, "172.24.*") ||
        shExpMatch(host, "172.25.*") ||
        shExpMatch(host, "172.26.*") ||
        shExpMatch(host, "172.27.*") ||
        shExpMatch(host, "172.28.*") ||
        shExpMatch(host, "172.29.*") ||
        shExpMatch(host, "172.30.*") ||
        shExpMatch(host, "172.31.*")) {
        return "DIRECT";
    }
    
    // Check if domain should be proxied
    for (var i = 0; i < proxiedDomains.length; i++) {
        if (shExpMatch(host, proxiedDomains[i])) {
            return PROXY;
        }
    }
    
    // Default: direct connection
    return "DIRECT";
}`;

const server = http.createServer((req, res) => {
    console.log(`PAC request from: ${req.socket.remoteAddress}`);
    
    res.writeHead(200, {
        'Content-Type': 'application/x-ns-proxy-autoconfig',
        'Content-Length': PAC_FILE.length,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    });
    
    res.end(PAC_FILE);
});

const PORT = 9000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`PAC file server running on port ${PORT}`);
    console.log(`PAC URL: http://localhost:${PORT}/proxy.pac`);
    console.log(`Configure browsers to use: http://localhost:${PORT}/proxy.pac`);
});
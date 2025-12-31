const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const net = require('net');
const path = require('path');

// PAC file content
const PAC_FILE = `function FindProxyForURL(url, host) {
    var PROXY = "PROXY localhost:3128";
    var proxiedDomains = [
        "*.cloud.sap",
        //"*.github.com",
    ];
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "localhost") ||
        shExpMatch(host, "127.*") ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "172.16.*")) {
        return "DIRECT";
    }
    for (var i = 0; i < proxiedDomains.length; i++) {
        if (shExpMatch(host, proxiedDomains[i])) {
            return PROXY;
        }
    }
    return "DIRECT";
}`;

class ForwardProxy {
    constructor(config = {}) {
        this.config = {
            port: config.port || 3128,
            host: config.host || '0.0.0.0',
            maxConnections: config.maxConnections || 100,
            timeout: config.timeout || 30000,
            sslConnect: config.sslConnect || true,
            logFile: config.logFile || './proxy.log',
            auth: config.auth || null, // { username: 'password' }
            whitelist: config.whitelist || [], // Array of allowed domains/regex
            blacklist: config.blacklist || [], // Array of blocked domains/regex
            debug: config.debug || false
        };

        this.activeConnections = new Set();
        this.requestCounts = new Map();
        this.rateLimitWindow = 60000; // 1 minute
        this.maxRequestsPerMinute = 100;

        this.setupLogging();
    }

    setupLogging() {
        const logStream = fs.createWriteStream(this.config.logFile, { flags: 'a' });
        this.logger = {
            info: (msg) => {
                const logMsg = `[INFO] ${new Date().toISOString()} - ${msg}\n`;
                logStream.write(logMsg);
                if (this.config.debug) console.log(logMsg.trim());
            },
            warn: (msg) => {
                const logMsg = `[WARN] ${new Date().toISOString()} - ${msg}\n`;
                logStream.write(logMsg);
                console.warn(logMsg.trim());
            },
            error: (msg) => {
                const logMsg = `[ERROR] ${new Date().toISOString()} - ${msg}\n`;
                logStream.write(logMsg);
                console.error(logMsg.trim());
            }
        };
    }

    isAllowed(clientIp, targetUrl) {
        // Check rate limiting
        const now = Date.now();
        const clientStats = this.requestCounts.get(clientIp) || { count: 0, resetTime: now + this.rateLimitWindow };
        
        if (now > clientStats.resetTime) {
            clientStats.count = 0;
            clientStats.resetTime = now + this.rateLimitWindow;
        }
        
        if (clientStats.count >= this.maxRequestsPerMinute) {
            this.logger.warn(`Rate limit exceeded for ${clientIp}`);
            return false;
        }
        
        clientStats.count++;
        this.requestCounts.set(clientIp, clientStats);

        // Parse URL
        const parsedUrl = url.parse(targetUrl);
        const hostname = parsedUrl.hostname;

        // Check blacklist
        for (const pattern of this.config.blacklist) {
            if (pattern instanceof RegExp) {
                if (pattern.test(hostname)) {
                    this.logger.warn(`Blocked ${hostname} (blacklist pattern: ${pattern})`);
                    return false;
                }
            } else if (hostname.includes(pattern) || hostname === pattern) {
                this.logger.warn(`Blocked ${hostname} (blacklist: ${pattern})`);
                return false;
            }
        }

        // Check whitelist (if whitelist exists, only allow listed domains)
        if (this.config.whitelist.length > 0) {
            let allowed = false;
            for (const pattern of this.config.whitelist) {
                if (pattern instanceof RegExp) {
                    if (pattern.test(hostname)) {
                        allowed = true;
                        break;
                    }
                } else if (hostname.includes(pattern) || hostname === pattern) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                this.logger.warn(`Blocked ${hostname} (not in whitelist)`);
                return false;
            }
        }

        return true;
    }

    authenticate(req) {
        if (!this.config.auth) return true;

        const authHeader = req.headers['proxy-authorization'];
        if (!authHeader) return false;

        const authType = authHeader.split(' ')[0];
        const credentials = authHeader.split(' ')[1];

        if (authType.toLowerCase() !== 'basic') return false;

        const decoded = Buffer.from(credentials, 'base64').toString();
        const [username, password] = decoded.split(':');

        return this.config.auth[username] === password;
    }

    handleConnect(req, socket, head) {
        const clientIp = req.socket.remoteAddress;
        const target = req.url;

        // Authentication
        if (!this.authenticate(req)) {
            this.logger.warn(`Authentication failed for ${clientIp}`);
            this.logger.info(`Client Info: IP=${clientIp}, Target=${req.url}, User-Agent=${req.headers['user-agent'] || 'Unknown'}`);
            socket.write('HTTP/1.1 407 Proxy Authentication Required\r\n');
            socket.write('Proxy-Authenticate: Basic realm="Proxy Server"\r\n\r\n');
            socket.end();
            return;
        }

        // Check if allowed
        if (!this.isAllowed(clientIp, `https://${target}`)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end();
            return;
        }

        this.logger.info(`HTTPS CONNECT: ${clientIp} -> ${target}`);

        const [hostname, port] = target.split(':');
        const proxyPort = port || 443;

        const proxySocket = net.connect(proxyPort, hostname, () => {
            socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            proxySocket.write(head);
            socket.pipe(proxySocket);
            proxySocket.pipe(socket);
        });

        proxySocket.on('error', (err) => {
            this.logger.error(`Proxy socket error for ${target}: ${err.message}`);
            socket.end();
        });

        socket.on('error', (err) => {
            this.logger.error(`Client socket error: ${err.message}`);
            proxySocket.end();
        });

        const connectionId = `${clientIp}-${Date.now()}`;
        this.activeConnections.add(connectionId);

        socket.on('close', () => {
            this.activeConnections.delete(connectionId);
        });
    }

    handleHttpRequest(clientReq, clientRes) {
        try {
            const clientIp = clientReq.socket.remoteAddress;
            const targetUrl = clientReq.url;

            // Authentication
            if (!this.authenticate(clientReq)) {
                this.logger.warn(`Authentication failed for ${clientIp}`);
                clientRes.writeHead(407, {
                    'Proxy-Authenticate': 'Basic realm="Proxy Server"'
                });
                clientRes.end('Proxy Authentication Required');
                return;
            }

            // Check if allowed
            if (!this.isAllowed(clientIp, targetUrl)) {
                clientRes.writeHead(403, { 'Content-Type': 'text/plain' });
                clientRes.end('Access Denied');
                return;
            }

            this.logger.info(`HTTP ${clientReq.method}: ${clientIp} -> ${targetUrl}`);

            const parsedUrl = url.parse(targetUrl);
            const options = {
                hostname: parsedUrl.hostname,
                port: parsedUrl.port || 80,
                path: parsedUrl.path,
                method: clientReq.method,
                headers: { ...clientReq.headers }
            };

            // Remove proxy-specific headers
            delete options.headers['proxy-connection'];
            delete options.headers['proxy-authorization'];
            delete options.headers['connection'];
            delete options.headers['host'];

            const proxyReq = http.request(options, (proxyRes) => {
                const responseHeaders = { ...proxyRes.headers };

                // Handle chunked transfer encoding
                if (responseHeaders['transfer-encoding'] === 'chunked') {
                    delete responseHeaders['content-length'];
                }

                clientRes.writeHead(proxyRes.statusCode, responseHeaders);
                proxyRes.pipe(clientRes);
            });

            proxyReq.on('error', (err) => {
                this.logger.error(`Proxy request error for ${targetUrl}: ${err.message}`);
                clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
                clientRes.end('Bad Gateway');
            });

            clientReq.pipe(proxyReq);

            clientReq.on('error', (err) => {
                this.logger.error(`Client request error: ${err.message}`);
                proxyReq.end();
            });

        } catch (err) {
            this.logger.error(`Unexpected error: ${err.message}`);
            clientRes.writeHead(500, { 'Content-Type': 'text/plain' });
            clientRes.end('Internal Server Error');
        }
    }

    start() {
        const server = http.createServer((req, res) => {
            const parsedUrl = url.parse(req.url, true);

            this.logger.info(`Get PAC: Target=${req.url}, User-Agent=${req.headers['user-agent'] || 'Unknown'}`);

            // Serve PAC file at /proxy.pac
            if (parsedUrl.pathname === '/proxy.pac') {
                res.writeHead(200, {
                    'Content-Type': 'application/x-ns-proxy-autoconfig',
                    'Content-Length': PAC_FILE.length,
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                });
                res.end(PAC_FILE);
                return;
            }

            // Handle other HTTP requests
            this.handleHttpRequest(req, res);
        });

        server.on('connect', (req, socket, head) => {
            this.handleConnect(req, socket, head);
        });

        server.on('error', (err) => {
            this.logger.error(`Server error: ${err.message}`);
        });

        server.maxConnections = this.config.maxConnections;

        server.listen(this.config.port, this.config.host, () => {
            this.logger.info(`Forward proxy server started on ${this.config.host}:${this.config.port}`);
            console.log(`Forward Proxy Server running at http://${this.config.host}:${this.config.port}`);
            console.log(`PAC file available at: http://${this.config.host}:${this.config.port}/proxy.pac`);
            
            if (this.config.auth) {
                console.log('Authentication: REQUIRED');
            }
            if (this.config.whitelist.length > 0) {
                console.log('Whitelist mode: ACTIVE');
            }
        });

        // Graceful shutdown
        process.on('SIGINT', () => {
            this.logger.info('Shutting down proxy server...');
            console.log('\nShutting down...');
            server.close(() => {
                this.logger.info('Proxy server stopped');
                process.exit(0);
            });
        });

        return server;
    }

    getStats() {
        return {
            activeConnections: this.activeConnections.size,
            config: this.config
        };
    }
}

// Configuration
const proxyConfig = {
    port: 3128,
    host: '0.0.0.0',
    maxConnections: 100,
    timeout: 30000,
    logFile: './proxy.log',
    
    // Optional authentication (comment out to disable)
    auth: {
        'uol': 'pass123'
    },
    
    // Optional whitelist (empty array = allow all)
    whitelist: [],
    
    // Optional blacklist
    blacklist: [],
    
    debug: true
};

// Create and start proxy
const proxy = new ForwardProxy(proxyConfig);
proxy.start();

// Export for testing/module usage
module.exports = { ForwardProxy };
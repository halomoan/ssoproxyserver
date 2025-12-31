// test-proxy.js
const http = require('http');

// Proxy credentials
const proxyUser = 'uol';
const proxyPass = 'pass123';
const auth = 'Basic ' + Buffer.from(proxyUser + ':' + proxyPass).toString('base64');


const proxyOptions = {
    host: 'localhost',
    port: 3128,
    path: 'http://httpbin.org/ip',
    headers: {
        Host: 'httpbin.org',
        'Proxy-Authorization': auth
    }
};

// Test without authentication
const req = http.request(proxyOptions, (res) => {
    console.log(`Status: ${res.statusCode}`);
    let data = '';
    res.on('data', (chunk) => {
        data += chunk;
    });
    res.on('end', () => {
        console.log('Response:', data);
    });
});

req.on('error', (err) => {
    console.error('Error:', err.message);
});

req.end();
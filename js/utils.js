// Utility Functions Module
const Utils = {
    parseJSON(jsonText) {
        const data = JSON.parse(jsonText);
        if (data.connections && Array.isArray(data.connections)) return data.connections;
        if (Array.isArray(data)) return data;
        const possibleKeys = ['packets', 'flows', 'events', 'records', 'logs'];
        for (const key of possibleKeys) {
            if (data[key] && Array.isArray(data[key])) return data[key];
        }
        throw new Error('Unrecognized JSON format');
    },

    validateConnections(connections) {
        if (!Array.isArray(connections)) {
            return { isValid: false, errors: ['Data must be an array'] };
        }
        if (connections.length < 2) {
            return { isValid: false, errors: [`Need at least 2 connections, found ${connections.length}`] };
        }
        
        const sampleSize = Math.min(5, connections.length);
        let hasTimestamp = false;
        for (let i = 0; i < sampleSize; i++) {
            if (connections[i].timestamp || connections[i].time || connections[i].ts) {
                hasTimestamp = true;
                break;
            }
        }
        if (!hasTimestamp) {
            return { isValid: false, errors: ['No timestamp field found'] };
        }
        return { isValid: true, errors: [] };
    },

    getTimestamp(conn) {
        const ts = conn.timestamp || conn.time || conn.ts || conn.epoch;
        if (!ts) throw new Error('No timestamp found');
        return ts < 10000000000 ? ts * 1000 : ts;
    },

    getBytes(conn) {
        return conn.bytes || conn.size || conn.length || 0;
    },

    getDestIP(conn) {
        return conn.dest_ip || conn.dst || conn.destination || conn.dst_ip || 'unknown';
    },

    getSrcIP(conn) {
        return conn.src_ip || conn.src || conn.source || 'unknown';
    },

    getSrcPort(conn) {
        return conn.src_port || conn.sport || 0;
    },

    getDestPort(conn) {
        return conn.dest_port || conn.dport || 0;
    },

    calculateStats(values) {
        if (values.length === 0) {
            return { mean: 0, median: 0, std: 0, min: 0, max: 0 };
        }
        const sorted = [...values].sort((a, b) => a - b);
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
        return {
            mean,
            median: sorted[Math.floor(sorted.length / 2)],
            std: Math.sqrt(variance),
            min: sorted[0],
            max: sorted[sorted.length - 1]
        };
    },

    formatDuration(minutes) {
        if (minutes < 1) return `${Math.round(minutes * 60)} seconds`;
        if (minutes < 60) return `${Math.round(minutes)} minutes`;
        const hours = Math.floor(minutes / 60);
        const mins = Math.round(minutes % 60);
        return `${hours}h ${mins}m`;
    },

    formatBytes(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
        return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    },

    formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString();
    },

    downloadJSON(data, filename) {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    },

    generateSampleData(beaconType) {
        const now = Date.now();
        const connections = [];
        let interval, jitter, count, destIP;

        if (beaconType === 'cobalt-strike') {
            interval = 60000;
            jitter = 0.05;
            count = 50;
            destIP = '185.220.101.15'; // Known malicious IP
        } else if (beaconType === 'metasploit') {
            interval = 120000;
            jitter = 0.10;
            count = 40;
            destIP = '45.142.214.99'; // Known malicious IP
        } else {
            interval = 2000;
            jitter = 0.60;
            count = 100;
            destIP = '8.8.8.8'; // Benign
        }

        for (let i = 0; i < count; i++) {
            const variance = interval * jitter * (Math.random() - 0.5) * 2;
            const timestamp = now + (i * interval) + variance;
            const bytes = beaconType === 'benign' ?
                Math.floor(Math.random() * 5000) + 500 :
                Math.floor(1024 + (Math.random() * 100));

            connections.push({
                timestamp: timestamp,
                bytes: bytes,
                dest_ip: destIP,
                src_ip: '192.168.1.100',
                src_port: 49152 + i,
                dest_port: 443
            });
        }

        return connections;
    },

    extractUniqueIPs(connections) {
        const destIPs = new Set();
        const srcIPs = new Set();
        
        connections.forEach(conn => {
            const dest = this.getDestIP(conn);
            const src = this.getSrcIP(conn);
            if (dest !== 'unknown') destIPs.add(dest);
            if (src !== 'unknown') srcIPs.add(src);
        });

        return {
            destIPs: Array.from(destIPs),
            srcIPs: Array.from(srcIPs),
            allIPs: Array.from(new Set([...destIPs, ...srcIPs]))
        };
    },

    isPrivateIP(ip) {
        if (ip === 'unknown') return true;
        
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return true;
        
        // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if (parts[0] === 10) return true;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 127) return true; // Loopback
        
        return false;
    }
};

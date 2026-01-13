// utils.js - Core Utility Functions
// Version 2.1.1

const Utils = {
    // JSON Validation
    validateJSON(data) {
        try {
            // Check for connections array
            if (!data || typeof data !== 'object') {
                return { valid: false, error: 'Invalid JSON structure' };
            }

            let connections = data.connections || data.data || data;
            
            if (!Array.isArray(connections)) {
                return { valid: false, error: 'No connections array found' };
            }

            if (connections.length < 2) {
                return { valid: false, error: 'At least 2 connections required' };
            }

            // Normalize connections
            connections = connections.map(conn => this.normalizeConnection(conn));

            // Validate each connection
            for (let i = 0; i < connections.length; i++) {
                const conn = connections[i];
                
                if (!conn.timestamp) {
                    return { valid: false, error: `Connection ${i}: Missing timestamp` };
                }

                if (!conn.dest_ip) {
                    return { valid: false, error: `Connection ${i}: Missing dest_ip` };
                }
            }

            return { valid: true, data: connections };
        } catch (error) {
            return { valid: false, error: error.message };
        }
    },

    normalizeConnection(conn) {
        // Normalize field names to standard format
        return {
            timestamp: conn.timestamp || conn.time || conn.ts || conn.epoch,
            bytes: conn.bytes || conn.size || conn.length || 0,
            dest_ip: conn.dest_ip || conn.dst || conn.destination || conn.dst_ip,
            src_ip: conn.src_ip || conn.src || conn.source,
            dest_port: conn.dest_port || conn.dport,
            src_port: conn.src_port || conn.sport
        };
    },

    // Statistical Functions
    mean(arr) {
        if (!arr || arr.length === 0) return 0;
        return arr.reduce((sum, val) => sum + val, 0) / arr.length;
    },

    median(arr) {
        if (!arr || arr.length === 0) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    },

    stdDev(arr) {
        if (!arr || arr.length === 0) return 0;
        const avg = this.mean(arr);
        const squareDiffs = arr.map(val => Math.pow(val - avg, 2));
        return Math.sqrt(this.mean(squareDiffs));
    },

    variance(arr) {
        if (!arr || arr.length === 0) return 0;
        const avg = this.mean(arr);
        const squareDiffs = arr.map(val => Math.pow(val - avg, 2));
        return this.mean(squareDiffs);
    },

    percentile(arr, p) {
        if (!arr || arr.length === 0) return 0;
        const sorted = [...arr].sort((a, b) => a - b);
        const index = (p / 100) * (sorted.length - 1);
        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        const weight = index - lower;
        return sorted[lower] * (1 - weight) + sorted[upper] * weight;
    },

    // Entropy calculation
    calculateEntropy(arr) {
        if (!arr || arr.length === 0) return 0;
        
        const counts = {};
        arr.forEach(val => {
            counts[val] = (counts[val] || 0) + 1;
        });

        let entropy = 0;
        const total = arr.length;
        
        Object.values(counts).forEach(count => {
            const p = count / total;
            entropy -= p * Math.log2(p);
        });

        return entropy;
    },

    // IP Address Functions
    extractUniqueIPs(connections) {
        const ips = new Set();
        connections.forEach(conn => {
            if (conn.dest_ip && !this.isPrivateIP(conn.dest_ip)) {
                ips.add(conn.dest_ip);
            }
            if (conn.src_ip && !this.isPrivateIP(conn.src_ip)) {
                ips.add(conn.src_ip);
            }
        });
        return Array.from(ips);
    },

    isPrivateIP(ip) {
        if (!ip) return true;
        
        // RFC1918 private ranges
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return true;
        
        // 10.0.0.0/8
        if (parts[0] === 10) return true;
        
        // 172.16.0.0/12
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        
        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168) return true;
        
        // 127.0.0.0/8 (loopback)
        if (parts[0] === 127) return true;
        
        // 169.254.0.0/16 (link-local)
        if (parts[0] === 169 && parts[1] === 254) return true;
        
        return false;
    },

    // Formatting Functions
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    },

    formatDuration(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days}d ${hours % 24}h`;
        if (hours > 0) return `${hours}h ${minutes % 60}m`;
        if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
        return `${seconds}s`;
    },

    formatTimestamp(timestamp) {
        // Handle both seconds and milliseconds
        const ts = timestamp > 10000000000 ? timestamp : timestamp * 1000;
        const date = new Date(ts);
        return date.toLocaleString();
    },

    formatNumber(num, decimals = 2) {
        return Number(num).toFixed(decimals);
    },

    formatPercentage(num) {
        return (num * 100).toFixed(1) + '%';
    },

    // Sample Data Generators
    generateCobaltStrikeSample() {
        const startTime = Date.now() - (3 * 60 * 60 * 1000); // 3 hours ago
        const connections = [];
        const beaconInterval = 60000; // 60 seconds
        const jitter = 0.05; // 5% jitter
        const maliciousIP = '185.220.101.42'; // Known malicious IP

        for (let i = 0; i < 120; i++) {
            const jitterMs = beaconInterval * jitter * (Math.random() - 0.5) * 2;
            const timestamp = startTime + (i * beaconInterval) + jitterMs;
            
            connections.push({
                timestamp: timestamp,
                bytes: 1024 + Math.floor(Math.random() * 200), // Consistent payload
                dest_ip: maliciousIP,
                src_ip: '10.0.0.50',
                src_port: 49152 + i,
                dest_port: 443
            });
        }

        return { connections };
    },

    generateMetasploitSample() {
        const startTime = Date.now() - (2 * 60 * 60 * 1000); // 2 hours ago
        const connections = [];
        const beaconInterval = 120000; // 120 seconds
        const jitter = 0.15; // 15% jitter
        const c2IP = '198.51.100.42';

        for (let i = 0; i < 60; i++) {
            const jitterMs = beaconInterval * jitter * (Math.random() - 0.5) * 2;
            const timestamp = startTime + (i * beaconInterval) + jitterMs;
            
            connections.push({
                timestamp: timestamp,
                bytes: 512 + Math.floor(Math.random() * 512),
                dest_ip: c2IP,
                src_ip: '10.0.0.75',
                src_port: 50000 + i,
                dest_port: 8080
            });
        }

        return { connections };
    },

    generateBenignSample() {
        const startTime = Date.now() - (1 * 60 * 60 * 1000); // 1 hour ago
        const connections = [];
        const webServers = ['93.184.216.34', '151.101.1.140', '172.217.14.206'];

        for (let i = 0; i < 50; i++) {
            // Random timing - not regular
            const randomDelay = Math.floor(Math.random() * 30000) + 5000;
            const timestamp = startTime + (i * randomDelay);
            
            connections.push({
                timestamp: timestamp,
                bytes: Math.floor(Math.random() * 10000) + 500,
                dest_ip: webServers[Math.floor(Math.random() * webServers.length)],
                src_ip: '10.0.0.100',
                src_port: 55000 + i,
                dest_port: Math.random() > 0.5 ? 443 : 80
            });
        }

        return { connections };
    },

    // Time Analysis
    getTimeIntervals(connections) {
        if (connections.length < 2) return [];
        
        const sorted = [...connections].sort((a, b) => a.timestamp - b.timestamp);
        const intervals = [];
        
        for (let i = 1; i < sorted.length; i++) {
            intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
        }
        
        return intervals;
    },

    calculateJitter(intervals) {
        if (intervals.length === 0) return 0;
        const avg = this.mean(intervals);
        if (avg === 0) return 1;
        return this.stdDev(intervals) / avg;
    },

    calculatePeriodicity(intervals) {
        if (intervals.length < 3) return 0;
        
        // Calculate coefficient of variation
        const avg = this.mean(intervals);
        const stddev = this.stdDev(intervals);
        
        if (avg === 0) return 0;
        
        const cv = stddev / avg;
        // Convert to periodicity score (0-1, where 1 is highly periodic)
        return Math.max(0, 1 - cv);
    },

    // Array utilities
    mode(arr) {
        if (!arr || arr.length === 0) return null;
        
        const counts = {};
        let maxCount = 0;
        let modeValue = arr[0];
        
        arr.forEach(val => {
            counts[val] = (counts[val] || 0) + 1;
            if (counts[val] > maxCount) {
                maxCount = counts[val];
                modeValue = val;
            }
        });
        
        return modeValue;
    },

    unique(arr) {
        return Array.from(new Set(arr));
    },

    // Download helper
    downloadJSON(data, filename) {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        this.downloadBlob(blob, filename);
    },

    downloadText(text, filename) {
        const blob = new Blob([text], { type: 'text/plain' });
        this.downloadBlob(blob, filename);
    },

    downloadHTML(html, filename) {
        const blob = new Blob([html], { type: 'text/html' });
        this.downloadBlob(blob, filename);
    },

    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    // CSV conversion
    arrayToCSV(data) {
        if (!data || data.length === 0) return '';
        
        const keys = Object.keys(data[0]);
        const header = keys.join(',');
        const rows = data.map(row => 
            keys.map(key => {
                const val = row[key];
                // Escape commas and quotes
                if (typeof val === 'string' && (val.includes(',') || val.includes('"'))) {
                    return '"' + val.replace(/"/g, '""') + '"';
                }
                return val;
            }).join(',')
        );
        
        return [header, ...rows].join('\n');
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Utils;
}

// analyzer.js - Behavioral Analysis Engine
// Version 2.1.1

const Analyzer = {
    extractFeatures(connections) {
        console.log(`Extracting features from ${connections.length} connections...`);

        const features = {};

        // Basic stats
        features.connectionCount = connections.length;
        features.uniqueDestinations = this.countUniqueDestinations(connections);
        features.uniqueSources = this.countUniqueSources(connections);

        // Timing analysis
        const timingFeatures = this.analyzeTimingPatterns(connections);
        Object.assign(features, timingFeatures);

        // Payload analysis
        const payloadFeatures = this.analyzePayloads(connections);
        Object.assign(features, payloadFeatures);

        // Network analysis
        const networkFeatures = this.analyzeNetwork(connections);
        Object.assign(features, networkFeatures);

        // Duration analysis
        const durationFeatures = this.analyzeDuration(connections);
        Object.assign(features, durationFeatures);

        // Framework signatures
        features.frameworkSignatures = this.detectFrameworks(features, connections);

        // MITRE ATT&CK mapping
        features.mitreAttack = this.mapMITRE(features);

        console.log(`✓ Extracted ${Object.keys(features).length} features`);
        return features;
    },

    countUniqueDestinations(connections) {
        const dests = new Set();
        connections.forEach(conn => {
            if (conn.dest_ip) dests.add(conn.dest_ip);
        });
        return dests.size;
    },

    countUniqueSources(connections) {
        const srcs = new Set();
        connections.forEach(conn => {
            if (conn.src_ip) srcs.add(conn.src_ip);
        });
        return srcs.size;
    },

    analyzeTimingPatterns(connections) {
        if (!Utils) return {};

        // Sort by timestamp
        const sorted = [...connections].sort((a, b) => a.timestamp - b.timestamp);
        
        // Calculate intervals
        const intervals = Utils.getTimeIntervals(sorted);
        
        if (intervals.length === 0) {
            return {
                meanInterval: 0,
                medianInterval: 0,
                stdDevInterval: 0,
                jitter: 1,
                periodicity: 0,
                timingEntropy: 0
            };
        }

        return {
            meanInterval: Utils.mean(intervals),
            medianInterval: Utils.median(intervals),
            stdDevInterval: Utils.stdDev(intervals),
            minInterval: Math.min(...intervals),
            maxInterval: Math.max(...intervals),
            jitter: Utils.calculateJitter(intervals),
            periodicity: Utils.calculatePeriodicity(intervals),
            timingEntropy: Utils.calculateEntropy(
                intervals.map(i => Math.round(i / 1000)) // Round to seconds
            )
        };
    },

    analyzePayloads(connections) {
        const sizes = connections
            .map(c => c.bytes)
            .filter(b => b !== undefined && b > 0);

        if (sizes.length === 0) {
            return {
                meanPayload: 0,
                medianPayload: 0,
                stdDevPayload: 0,
                payloadConsistency: 0,
                payloadEntropy: 0
            };
        }

        if (!Utils) return {};

        const mean = Utils.mean(sizes);
        const stdDev = Utils.stdDev(sizes);
        
        // Consistency = 1 - (stdDev / mean)
        const consistency = mean > 0 ? Math.max(0, 1 - (stdDev / mean)) : 0;

        return {
            meanPayload: mean,
            medianPayload: Utils.median(sizes),
            stdDevPayload: stdDev,
            minPayload: Math.min(...sizes),
            maxPayload: Math.max(...sizes),
            payloadConsistency: consistency,
            payloadEntropy: Utils.calculateEntropy(
                sizes.map(s => Math.round(s / 100) * 100) // Round to nearest 100
            )
        };
    },

    analyzeNetwork(connections) {
        const destPorts = connections
            .map(c => c.dest_port)
            .filter(p => p !== undefined);

        const srcPorts = connections
            .map(c => c.src_port)
            .filter(p => p !== undefined);

        const uniqueDestPorts = new Set(destPorts).size;
        const uniqueSrcPorts = new Set(srcPorts).size;

        // Port diversity (0 = single port, 1 = many ports)
        const portDiversity = destPorts.length > 0 ?
            uniqueDestPorts / Math.sqrt(destPorts.length) : 0;

        // Get most common port
        const portCounts = {};
        destPorts.forEach(p => {
            portCounts[p] = (portCounts[p] || 0) + 1;
        });
        
        const mostCommonPort = Object.keys(portCounts).reduce((a, b) => 
            portCounts[a] > portCounts[b] ? a : b, null
        );

        return {
            uniqueDestPorts,
            uniqueSrcPorts,
            portDiversity,
            mostCommonPort: mostCommonPort ? parseInt(mostCommonPort) : null,
            portConcentration: mostCommonPort ? 
                portCounts[mostCommonPort] / destPorts.length : 0
        };
    },

    analyzeDuration(connections) {
        if (connections.length === 0) {
            return {
                startTime: 0,
                endTime: 0,
                durationMs: 0,
                durationHours: 0
            };
        }

        const timestamps = connections.map(c => c.timestamp);
        const startTime = Math.min(...timestamps);
        const endTime = Math.max(...timestamps);
        const durationMs = endTime - startTime;

        return {
            startTime,
            endTime,
            durationMs,
            durationHours: durationMs / (1000 * 60 * 60),
            durationMinutes: durationMs / (1000 * 60)
        };
    },

    detectFrameworks(features, connections) {
        const signatures = [];

        // Cobalt Strike: ~60s intervals, low jitter
        if (features.meanInterval >= 55000 && features.meanInterval <= 65000 &&
            features.jitter < 0.10 && features.periodicity > 0.75) {
            signatures.push({
                framework: 'Cobalt Strike',
                confidence: 'high',
                reason: '60-second beacon with low jitter',
                indicators: [
                    `Interval: ${(features.meanInterval / 1000).toFixed(1)}s`,
                    `Jitter: ${(features.jitter * 100).toFixed(1)}%`,
                    `Periodicity: ${(features.periodicity * 100).toFixed(1)}%`
                ]
            });
        }

        // Metasploit: ~120s intervals
        if (features.meanInterval >= 110000 && features.meanInterval <= 130000 &&
            features.jitter < 0.20 && features.periodicity > 0.65) {
            signatures.push({
                framework: 'Metasploit/Meterpreter',
                confidence: 'medium',
                reason: '120-second beacon pattern',
                indicators: [
                    `Interval: ${(features.meanInterval / 1000).toFixed(1)}s`,
                    `Periodicity: ${(features.periodicity * 100).toFixed(1)}%`
                ]
            });
        }

        // Empire: Short intervals, high periodicity
        if (features.meanInterval < 30000 && features.meanInterval > 5000 &&
            features.periodicity > 0.70) {
            signatures.push({
                framework: 'PowerShell Empire',
                confidence: 'medium',
                reason: 'Short periodic intervals',
                indicators: [
                    `Interval: ${(features.meanInterval / 1000).toFixed(1)}s`,
                    `Periodicity: ${(features.periodicity * 100).toFixed(1)}%`
                ]
            });
        }

        // Sliver: Consistent payloads, moderate timing
        if (features.payloadConsistency > 0.85 &&
            features.periodicity > 0.60 &&
            features.meanInterval > 30000) {
            signatures.push({
                framework: 'Sliver',
                confidence: 'low',
                reason: 'Consistent payload pattern',
                indicators: [
                    `Payload consistency: ${(features.payloadConsistency * 100).toFixed(1)}%`,
                    `Periodicity: ${(features.periodicity * 100).toFixed(1)}%`
                ]
            });
        }

        // Generic C2 pattern
        if (signatures.length === 0 &&
            features.periodicity > 0.65 &&
            features.jitter < 0.30 &&
            features.uniqueDestinations === 1) {
            signatures.push({
                framework: 'Generic C2',
                confidence: 'low',
                reason: 'General beaconing pattern',
                indicators: [
                    'High periodicity',
                    'Low jitter',
                    'Single destination'
                ]
            });
        }

        return signatures;
    },

    mapMITRE(features) {
        const techniques = [];

        // T1071 - Application Layer Protocol
        if (features.mostCommonPort === 80 || features.mostCommonPort === 443 ||
            features.mostCommonPort === 8080) {
            techniques.push({
                id: 'T1071',
                name: 'Application Layer Protocol',
                description: 'Using standard web ports for C2',
                confidence: 'medium'
            });
        }

        // T1573 - Encrypted Channel
        if (features.mostCommonPort === 443) {
            techniques.push({
                id: 'T1573',
                name: 'Encrypted Channel',
                description: 'Likely using HTTPS for encrypted C2',
                confidence: 'medium'
            });
        }

        // T1001 - Data Obfuscation
        if (features.payloadConsistency > 0.80) {
            techniques.push({
                id: 'T1001',
                name: 'Data Obfuscation',
                description: 'Consistent payload sizes suggest structured protocol',
                confidence: 'low'
            });
        }

        // T1095 - Non-Application Layer Protocol
        if (features.mostCommonPort && 
            features.mostCommonPort !== 80 && 
            features.mostCommonPort !== 443 &&
            features.mostCommonPort !== 8080) {
            techniques.push({
                id: 'T1095',
                name: 'Non-Application Layer Protocol',
                description: `Using non-standard port ${features.mostCommonPort}`,
                confidence: 'low'
            });
        }

        return techniques;
    },

    // Helper to get human-readable summary
    getSummary(features) {
        return {
            timing: {
                avgInterval: Utils.formatDuration(features.meanInterval),
                jitter: (features.jitter * 100).toFixed(1) + '%',
                periodicity: (features.periodicity * 100).toFixed(1) + '%'
            },
            payload: {
                avgSize: Utils.formatBytes(features.meanPayload),
                consistency: (features.payloadConsistency * 100).toFixed(1) + '%'
            },
            network: {
                destinations: features.uniqueDestinations,
                sources: features.uniqueSources,
                primaryPort: features.mostCommonPort || 'N/A'
            },
            duration: {
                total: Utils.formatDuration(features.durationMs),
                connections: features.connectionCount
            }
        };
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Analyzer;
}

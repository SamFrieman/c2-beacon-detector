// Behavioral Analysis Module
const Analyzer = {
    extractFeatures(connections) {
        const timestamps = connections.map(c => Utils.getTimestamp(c)).sort((a, b) => a - b);
        const intervals = timestamps.slice(1).map((t, i) => t - timestamps[i]);

        const timingStats = Utils.calculateStats(intervals);
        const cv = timingStats.mean > 0 ? timingStats.std / timingStats.mean : 0;

        const periodicity = this.calculatePeriodicity(intervals, timingStats.median);
        const entropy = this.calculateEntropy(intervals);

        const byteSizes = connections.map(c => Utils.getBytes(c)).filter(b => b > 0);
        const byteStats = Utils.calculateStats(byteSizes);
        const bytesCV = byteSizes.length > 0 && byteStats.mean > 0 ? byteStats.std / byteStats.mean : 1;

        const destIPs = [...new Set(connections.map(c => Utils.getDestIP(c)))];
        const destPorts = [...new Set(connections.map(c => Utils.getDestPort(c)).filter(p => p > 0))];
        const srcPorts = [...new Set(connections.map(c => Utils.getSrcPort(c)).filter(p => p > 0))];

        const durationMs = timestamps[timestamps.length - 1] - timestamps[0];

        // Calculate port patterns
        const portEntropy = this.calculatePortEntropy(connections);
        
        // Time of day analysis
        const timePatterns = this.analyzeTimePatterns(timestamps);

        return {
            // Timing features
            mean_interval: timingStats.mean / 1000,
            median_interval: timingStats.median / 1000,
            std_interval: timingStats.std / 1000,
            min_interval: timingStats.min / 1000,
            max_interval: timingStats.max / 1000,
            cv_interval: cv,
            jitter: cv,
            periodicity: periodicity,
            entropy: entropy,
            regularity_score: cv > 0 ? 1 / (1 + cv) : 0,
            
            // Payload features
            avg_bytes: byteStats.mean,
            median_bytes: byteStats.median,
            min_bytes: byteStats.min,
            max_bytes: byteStats.max,
            bytes_cv: bytesCV,
            bytes_consistency: 1 - Math.min(bytesCV, 1),
            total_bytes: byteSizes.reduce((a, b) => a + b, 0),
            
            // Network features
            connection_count: connections.length,
            duration_minutes: durationMs / 1000 / 60,
            unique_dest_ips: destIPs.length,
            unique_dest_ports: destPorts.length,
            unique_src_ports: srcPorts.length,
            connections_per_minute: connections.length / Math.max(durationMs / 1000 / 60, 1),
            port_entropy: portEntropy,
            
            // Time patterns
            time_diversity: timePatterns.diversity,
            night_ratio: timePatterns.nightRatio
        };
    },

    calculatePeriodicity(intervals, median) {
        if (intervals.length === 0 || median === 0) return 0;
        const tolerance = 0.15;
        const closeToMedian = intervals.filter(i => Math.abs(i - median) / median < tolerance).length;
        return closeToMedian / intervals.length;
    },

    calculateEntropy(intervals) {
        if (intervals.length === 0) return 0;
        
        // Bucket intervals for entropy calculation
        const bucketSize = 1000; // 1 second buckets
        const buckets = {};
        
        intervals.forEach(interval => {
            const bucket = Math.floor(interval / bucketSize);
            buckets[bucket] = (buckets[bucket] || 0) + 1;
        });

        const total = intervals.length;
        let entropy = 0;

        Object.values(buckets).forEach(count => {
            const p = count / total;
            entropy -= p * Math.log2(p);
        });

        return entropy;
    },

    calculatePortEntropy(connections) {
        const ports = connections.map(c => Utils.getDestPort(c)).filter(p => p > 0);
        if (ports.length === 0) return 0;

        const portCounts = {};
        ports.forEach(port => {
            portCounts[port] = (portCounts[port] || 0) + 1;
        });

        const total = ports.length;
        let entropy = 0;

        Object.values(portCounts).forEach(count => {
            const p = count / total;
            entropy -= p * Math.log2(p);
        });

        return entropy;
    },

    analyzeTimePatterns(timestamps) {
        const hours = timestamps.map(ts => new Date(ts).getHours());
        const uniqueHours = new Set(hours).size;
        
        // Count connections during night hours (10 PM - 6 AM)
        const nightConnections = hours.filter(h => h >= 22 || h < 6).length;
        
        return {
            diversity: uniqueHours / 24,
            nightRatio: nightConnections / timestamps.length
        };
    },

    identifyFramework(features, threatIntelMatches) {
        const frameworks = [];
        const interval = features.mean_interval;

        // Threat intel based identification
        if (threatIntelMatches && threatIntelMatches.length > 0) {
            threatIntelMatches.forEach(match => {
                const familyInfo = ThreatIntel.getMalwareFamilyInfo(match.malware);
                if (familyInfo) {
                    frameworks.push({
                        name: familyInfo.framework,
                        confidence: 'High',
                        reason: `Matched known ${match.malware} IOC`,
                        source: 'threat_intel'
                    });
                }
            });
        }

        // Behavioral signatures
        if (interval >= 55 && interval <= 65 && features.jitter < 0.10) {
            frameworks.push({
                name: 'Cobalt Strike',
                confidence: 'High',
                reason: '60-second beacon interval with low jitter',
                source: 'behavioral'
            });
        }

        if (interval >= 110 && interval <= 130 && features.jitter < 0.15) {
            frameworks.push({
                name: 'Metasploit/Meterpreter',
                confidence: 'Medium',
                reason: '120-second beacon pattern',
                source: 'behavioral'
            });
        }

        if (interval >= 4 && interval <= 12 && features.periodicity > 0.6) {
            frameworks.push({
                name: 'PowerShell Empire',
                confidence: 'Medium',
                reason: 'Short interval with moderate periodicity',
                source: 'behavioral'
            });
        }

        if (interval >= 55 && interval <= 65 && features.bytes_consistency > 0.85) {
            frameworks.push({
                name: 'Sliver',
                confidence: 'Medium',
                reason: '60s interval with consistent payloads',
                source: 'behavioral'
            });
        }

        // Advanced patterns
        if (features.port_entropy < 0.5 && features.unique_dest_ports === 1) {
            frameworks.push({
                name: 'Generic C2',
                confidence: 'Medium',
                reason: 'Single port with consistent pattern',
                source: 'behavioral'
            });
        }

        // Deduplicate frameworks
        const unique = [];
        const seen = new Set();
        
        frameworks.forEach(fw => {
            if (!seen.has(fw.name)) {
                seen.add(fw.name);
                unique.push(fw);
            }
        });

        return unique.length > 0 ? unique : [{
            name: 'Unknown/Custom',
            confidence: 'N/A',
            reason: 'Does not match known framework signatures',
            source: 'behavioral'
        }];
    },

    getMITREMapping(features) {
        const techniques = [];

        if (features.periodicity > 0.7) {
            techniques.push({
                id: 'T1071',
                name: 'Application Layer Protocol',
                tactic: 'Command and Control',
                description: 'Regular beaconing pattern detected'
            });
        }

        if (features.unique_dest_ips === 1 && features.duration_minutes > 60) {
            techniques.push({
                id: 'T1573',
                name: 'Encrypted Channel',
                tactic: 'Command and Control',
                description: 'Sustained communication with single endpoint'
            });
        }

        if (features.bytes_consistency > 0.85) {
            techniques.push({
                id: 'T1001',
                name: 'Data Obfuscation',
                tactic: 'Command and Control',
                description: 'Consistent payload sizes may indicate obfuscation'
            });
        }

        return techniques;
    }
};

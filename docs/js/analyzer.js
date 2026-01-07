/**
 * Feature Extraction and Analysis Module
 * Extracts behavioral features from network connection data
 */

const Analyzer = {
    /**
     * Extract all behavioral features from connections
     * @param {Array} connections - Array of connection objects
     * @returns {Object} Extracted features
     */
    extractFeatures: function(connections) {
        if (!connections || connections.length < 2) {
            throw new Error('Insufficient connection data. Need at least 2 connections.');
        }

        // Extract timestamps and sort
        const timestamps = connections
            .map(c => Utils.getTimestamp(c))
            .sort((a, b) => a - b);

        // Calculate inter-arrival times (intervals between connections)
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i-1]);
        }

        // Timing statistics
        const timingStats = Utils.calculateStats(intervals);
        const coefficientOfVariation = timingStats.std / timingStats.mean;

        // Periodicity analysis
        const periodicity = this.calculatePeriodicity(intervals, timingStats.median);

        // Byte size analysis
        const byteSizes = connections
            .map(c => Utils.getBytes(c))
            .filter(b => b > 0);
        
        const byteStats = Utils.calculateStats(byteSizes);
        const bytesCV = byteSizes.length > 0 ? byteStats.std / byteStats.mean : 1;
        const bytesConsistency = 1 - Math.min(bytesCV, 1);

        // Connection metadata
        const destIPs = [...new Set(connections.map(c => Utils.getDestIP(c)))];
        const srcPorts = [...new Set(connections.map(c => Utils.getSrcPort(c)).filter(p => p > 0))];
        const destPorts = [...new Set(connections.map(c => Utils.getDestPort(c)).filter(p => p > 0))];

        // Duration calculation
        const durationMs = timestamps[timestamps.length - 1] - timestamps[0];
        const durationMinutes = durationMs / 1000 / 60;

        return {
            // Timing features
            mean_interval: timingStats.mean / 1000, // Convert to seconds
            median_interval: timingStats.median / 1000,
            std_interval: timingStats.std / 1000,
            min_interval: timingStats.min / 1000,
            max_interval: timingStats.max / 1000,
            
            // Variability metrics
            cv_interval: coefficientOfVariation,
            jitter: coefficientOfVariation,
            periodicity: periodicity,
            regularity_score: 1 / (1 + coefficientOfVariation),
            
            // Byte metrics
            avg_bytes: byteStats.mean,
            median_bytes: byteStats.median,
            std_bytes: byteStats.std,
            bytes_cv: bytesCV,
            bytes_consistency: bytesConsistency,
            
            // Connection metadata
            connection_count: connections.length,
            duration_minutes: durationMinutes,
            unique_dest_ips: destIPs.length,
            unique_src_ports: srcPorts.length,
            unique_dest_ports: destPorts.length,
            
            // Derived metrics
            connections_per_minute: connections.length / Math.max(durationMinutes, 1),
            avg_bytes_per_connection: byteStats.mean
        };
    },

    /**
     * Calculate periodicity score (how regular are the intervals)
     * @param {Array} intervals - Array of time intervals
     * @param {number} median - Median interval
     * @returns {number} Periodicity score (0-1)
     */
    calculatePeriodicity: function(intervals, median) {
        if (intervals.length === 0 || median === 0) {
            return 0;
        }

        // Count how many intervals are within 15% of the median
        const tolerance = 0.15;
        const closeToMedian = intervals.filter(interval => {
            const deviation = Math.abs(interval - median) / median;
            return deviation < tolerance;
        }).length;

        return closeToMedian / intervals.length;
    },

    /**
     * Identify the most likely C2 framework based on features
     * @param {Object} features - Extracted features
     * @returns {Object} Framework identification
     */
    identifyFramework: function(features) {
        const frameworks = [];

        // Cobalt Strike: 60s beacon, very consistent
        if (features.mean_interval >= 55 && features.mean_interval <= 65 && features.jitter < 0.10) {
            frameworks.push({
                name: 'Cobalt Strike',
                confidence: 'High',
                reason: '60-second beacon interval with low jitter'
            });
        }

        // Metasploit: 60-120s beacon, moderate jitter
        if (features.mean_interval >= 55 && features.mean_interval <= 125 && features.jitter < 0.15) {
            frameworks.push({
                name: 'Metasploit/Meterpreter',
                confidence: 'Medium',
                reason: 'Timing consistent with Meterpreter default configuration'
            });
        }

        // Empire: Variable but often 5-10s
        if (features.mean_interval >= 4 && features.mean_interval <= 12 && features.periodicity > 0.6) {
            frameworks.push({
                name: 'PowerShell Empire',
                confidence: 'Medium',
                reason: 'Short interval with moderate periodicity'
            });
        }

        // Covenant: Often 10-30s
        if (features.mean_interval >= 8 && features.mean_interval <= 35 && features.jitter < 0.20) {
            frameworks.push({
                name: 'Covenant C2',
                confidence: 'Low',
                reason: 'Timing pattern consistent with Covenant defaults'
            });
        }

        // Sliver: Variable timing, often encrypted
        if (features.mean_interval >= 20 && features.mean_interval <= 90 && features.bytes_consistency > 0.7) {
            frameworks.push({
                name: 'Sliver',
                confidence: 'Low',
                reason: 'Consistent payload sizes with moderate timing'
            });
        }

        return frameworks.length > 0 ? frameworks : [{
            name: 'Unknown/Custom',
            confidence: 'N/A',
            reason: 'Does not match known framework signatures'
        }];
    },

    /**
     * Generate human-readable feature explanations
     * @param {Object} features - Extracted features
     * @returns {Array} Array of explanation strings
     */
    explainFeatures: function(features) {
        const explanations = [];

        // Timing explanations
        if (features.mean_interval < 5) {
            explanations.push(`Very frequent connections (${features.mean_interval.toFixed(1)}s average) - typical of legitimate apps or aggressive C2`);
        } else if (features.mean_interval >= 30 && features.mean_interval <= 300) {
            explanations.push(`Interval (${features.mean_interval.toFixed(1)}s) falls within common C2 beacon range (30-300 seconds)`);
        } else if (features.mean_interval > 300) {
            explanations.push(`Long intervals (${features.mean_interval.toFixed(1)}s) - could be stealthy C2 or scheduled task`);
        }

        // Periodicity explanations
        if (features.periodicity > 0.8) {
            explanations.push(`Extremely regular timing (${(features.periodicity * 100).toFixed(1)}% periodicity) - strong indicator of automation`);
        } else if (features.periodicity > 0.6) {
            explanations.push(`Moderately regular timing (${(features.periodicity * 100).toFixed(1)}% periodicity)`);
        }

        // Jitter explanations
        if (features.jitter < 0.10) {
            explanations.push(`Very low jitter (${(features.jitter * 100).toFixed(2)}%) - consistent with automated beaconing`);
        } else if (features.jitter > 0.50) {
            explanations.push(`High jitter (${(features.jitter * 100).toFixed(2)}%) - suggests human interaction or organic traffic`);
        }

        // Duration explanations
        if (features.duration_minutes > 60) {
            explanations.push(`Long-running connection pattern over ${Utils.formatDuration(features.duration_minutes)}`);
        }

        // Destination explanations
        if (features.unique_dest_ips === 1) {
            explanations.push(`All connections target single IP address - common in C2 communication`);
        } else if (features.unique_dest_ips > 10) {
            explanations.push(`Multiple destinations (${features.unique_dest_ips} unique IPs) - less typical of C2`);
        }

        return explanations;
    }
};

// Make Analyzer available globally
window.Analyzer = Analyzer;

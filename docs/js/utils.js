/**
 * Utility Functions for C2 Beacon Detector
 * Contains helper functions for data processing and validation
 */

const Utils = {
    /**
     * Parse various JSON formats into standardized connection array
     * @param {string} jsonText - Raw JSON text from uploaded file
     * @returns {Array} Array of connection objects
     */
    parseJSON: function(jsonText) {
        try {
            const data = JSON.parse(jsonText);
            
            // Handle various JSON formats
            if (data.connections && Array.isArray(data.connections)) {
                return data.connections;
            }
            
            if (Array.isArray(data)) {
                return data;
            }
            
            // Try common alternative keys
            const possibleKeys = ['packets', 'flows', 'events', 'records', 'logs'];
            for (const key of possibleKeys) {
                if (data[key] && Array.isArray(data[key])) {
                    return data[key];
                }
            }
            
            throw new Error('Unrecognized JSON format. Expected: {connections: [...]} or [...] array');
        } catch (error) {
            throw new Error(`JSON parsing failed: ${error.message}`);
        }
    },

    /**
     * Validate connection data has required fields
     * @param {Array} connections - Array of connection objects
     * @returns {Object} Validation result with isValid and errors
     */
    validateConnections: function(connections) {
        const errors = [];
        
        if (!Array.isArray(connections)) {
            return { isValid: false, errors: ['Data must be an array'] };
        }
        
        if (connections.length < 2) {
            return { 
                isValid: false, 
                errors: [`Insufficient data: ${connections.length} connection(s). Need at least 2.`] 
            };
        }
        
        // Check for timestamp field in first few records
        const sampleSize = Math.min(5, connections.length);
        let hasTimestamp = false;
        
        for (let i = 0; i < sampleSize; i++) {
            const conn = connections[i];
            if (conn.timestamp || conn.time || conn.ts) {
                hasTimestamp = true;
                break;
            }
        }
        
        if (!hasTimestamp) {
            errors.push('No timestamp field found. Required field: timestamp, time, or ts');
        }
        
        return { 
            isValid: errors.length === 0, 
            errors 
        };
    },

    /**
     * Extract timestamp from connection object (handles multiple field names)
     * @param {Object} connection - Connection object
     * @returns {number} Timestamp in milliseconds
     */
    getTimestamp: function(connection) {
        // Try various timestamp field names
        const timestamp = connection.timestamp || 
                         connection.time || 
                         connection.ts || 
                         connection.epoch ||
                         connection.time_unix;
        
        if (!timestamp) {
            throw new Error('No timestamp field found in connection object');
        }
        
        // Convert to milliseconds if in seconds
        return timestamp < 10000000000 ? timestamp * 1000 : timestamp;
    },

    /**
     * Extract byte size from connection object
     * @param {Object} connection - Connection object
     * @returns {number} Byte size
     */
    getBytes: function(connection) {
        return connection.bytes || 
               connection.size || 
               connection.length || 
               connection.data_len ||
               connection.frame_len ||
               0;
    },

    /**
     * Extract destination IP from connection object
     * @param {Object} connection - Connection object
     * @returns {string} Destination IP
     */
    getDestIP: function(connection) {
        return connection.dest_ip || 
               connection.dst || 
               connection.destination || 
               connection.dst_ip ||
               connection.ip_dst ||
               'unknown';
    },

    /**
     * Extract source port from connection object
     * @param {Object} connection - Connection object
     * @returns {number} Source port
     */
    getSrcPort: function(connection) {
        return connection.src_port || 
               connection.sport || 
               connection.source_port ||
               connection.tcp_srcport ||
               0;
    },

    /**
     * Extract destination port from connection object
     * @param {Object} connection - Connection object
     * @returns {number} Destination port
     */
    getDestPort: function(connection) {
        return connection.dest_port || 
               connection.dport || 
               connection.destination_port ||
               connection.tcp_dstport ||
               0;
    },

    /**
     * Calculate statistical metrics
     * @param {Array} values - Array of numbers
     * @returns {Object} Statistical metrics
     */
    calculateStats: function(values) {
        if (values.length === 0) {
            return { mean: 0, median: 0, std: 0, variance: 0, min: 0, max: 0 };
        }
        
        const sorted = [...values].sort((a, b) => a - b);
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
        const std = Math.sqrt(variance);
        const median = sorted[Math.floor(sorted.length / 2)];
        const min = sorted[0];
        const max = sorted[sorted.length - 1];
        
        return { mean, median, std, variance, min, max };
    },

    /**
     * Format timestamp for display
     * @param {number} timestamp - Unix timestamp in milliseconds
     * @returns {string} Formatted date string
     */
    formatTimestamp: function(timestamp) {
        return new Date(timestamp).toISOString();
    },

    /**
     * Format duration in human-readable format
     * @param {number} minutes - Duration in minutes
     * @returns {string} Formatted duration
     */
    formatDuration: function(minutes) {
        if (minutes < 1) {
            return `${Math.round(minutes * 60)} seconds`;
        } else if (minutes < 60) {
            return `${Math.round(minutes)} minutes`;
        } else {
            const hours = Math.floor(minutes / 60);
            const mins = Math.round(minutes % 60);
            return `${hours}h ${mins}m`;
        }
    },

    /**
     * Generate downloadable report
     * @param {Object} analysisResult - Analysis result object
     * @param {string} fileName - Original uploaded file name
     * @returns {Object} Report object
     */
    generateReport: function(analysisResult, fileName) {
        return {
            metadata: {
                tool: 'C2 Beacon Detector',
                version: '1.0.0',
                timestamp: new Date().toISOString(),
                analyzed_file: fileName
            },
            summary: {
                classification: analysisResult.classification,
                threat_score: analysisResult.score,
                recommendation: analysisResult.recommendation
            },
            features: analysisResult.features,
            detection_factors: analysisResult.reasons,
            technical_details: analysisResult.technicalDetails || []
        };
    },

    /**
     * Download data as JSON file
     * @param {Object} data - Data to download
     * @param {string} filename - Output filename
     */
    downloadJSON: function(data, filename) {
        const blob = new Blob([JSON.stringify(data, null, 2)], { 
            type: 'application/json' 
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};

// Make Utils available globally
window.Utils = Utils;

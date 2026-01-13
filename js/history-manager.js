// history-manager.js - Historical Analysis Management
// Version 2.1.1

const HistoryManager = {
    maxHistorySize: 100,
    storageKey: 'c2detector_history',
    history: [],

    initialize() {
        this.loadHistory();
        console.log(`History: ${this.history.length} analyses loaded`);
        return this.history.length;
    },

    loadHistory() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            if (stored) {
                this.history = JSON.parse(stored);
                
                // Sort by timestamp (newest first)
                this.history.sort((a, b) => 
                    new Date(b.timestamp) - new Date(a.timestamp)
                );
            }
        } catch (error) {
            console.error('Failed to load history:', error);
            this.history = [];
        }
    },

    saveHistory() {
        try {
            // Keep only maxHistorySize most recent
            if (this.history.length > this.maxHistorySize) {
                this.history = this.history.slice(0, this.maxHistorySize);
            }
            
            localStorage.setItem(this.storageKey, JSON.stringify(this.history));
        } catch (error) {
            console.error('Failed to save history:', error);
            
            // If quota exceeded, remove oldest entries
            if (error.name === 'QuotaExceededError') {
                this.history = this.history.slice(0, 50);
                this.saveHistory();
            }
        }
    },

    addAnalysis(analysis) {
        // Add ID if not present
        if (!analysis.id) {
            analysis.id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
        }

        // Ensure timestamp
        if (!analysis.timestamp) {
            analysis.timestamp = new Date().toISOString();
        }

        // Add to beginning of array
        this.history.unshift(analysis);
        
        // Save
        this.saveHistory();
        
        console.log(`Added analysis to history: ${analysis.id}`);
        return analysis.id;
    },

    getHistory(limit = null) {
        if (limit) {
            return this.history.slice(0, limit);
        }
        return [...this.history];
    },

    getAnalysis(id) {
        return this.history.find(a => a.id === id);
    },

    deleteAnalysis(id) {
        const index = this.history.findIndex(a => a.id === id);
        if (index !== -1) {
            this.history.splice(index, 1);
            this.saveHistory();
            return true;
        }
        return false;
    },

    clearHistory() {
        this.history = [];
        this.saveHistory();
        console.log('History cleared');
    },

    getStats() {
        if (this.history.length === 0) {
            return null;
        }

        const scores = this.history.map(a => a.score);
        const classifications = this.history.reduce((acc, a) => {
            acc[a.classification] = (acc[a.classification] || 0) + 1;
            return acc;
        }, {});

        return {
            total: this.history.length,
            avgScore: scores.reduce((a, b) => a + b, 0) / scores.length,
            maxScore: Math.max(...scores),
            minScore: Math.min(...scores),
            classifications: classifications
        };
    },

    calculatePercentile(score) {
        if (this.history.length === 0) return null;
        
        const scores = this.history.map(a => a.score).sort((a, b) => a - b);
        const lowerScores = scores.filter(s => s < score).length;
        
        return (lowerScores / scores.length) * 100;
    },

    findSimilar(analysis, limit = 5) {
        if (this.history.length === 0) return [];

        // Calculate similarity scores
        const similarities = this.history
            .filter(a => a.id !== analysis.id)
            .map(a => ({
                analysis: a,
                similarity: this.calculateSimilarity(analysis, a)
            }))
            .sort((a, b) => b.similarity - a.similarity)
            .slice(0, limit);

        return similarities;
    },

    calculateSimilarity(a1, a2) {
        let score = 0;
        let factors = 0;

        // Compare scores (normalized difference)
        const scoreDiff = Math.abs(a1.score - a2.score) / 100;
        score += (1 - scoreDiff);
        factors++;

        // Compare classifications
        if (a1.classification === a2.classification) {
            score += 1;
        }
        factors++;

        // Compare features if available
        if (a1.features && a2.features) {
            const f1 = a1.features;
            const f2 = a2.features;

            // Periodicity similarity
            if (f1.periodicity !== undefined && f2.periodicity !== undefined) {
                score += 1 - Math.abs(f1.periodicity - f2.periodicity);
                factors++;
            }

            // Jitter similarity
            if (f1.jitter !== undefined && f2.jitter !== undefined) {
                score += 1 - Math.abs(f1.jitter - f2.jitter);
                factors++;
            }
        }

        return factors > 0 ? score / factors : 0;
    },

    getTrends(days = 7) {
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - days);

        const recent = this.history.filter(a => 
            new Date(a.timestamp) > cutoff
        );

        if (recent.length === 0) return null;

        // Group by day
        const byDay = {};
        recent.forEach(a => {
            const day = new Date(a.timestamp).toISOString().split('T')[0];
            if (!byDay[day]) {
                byDay[day] = [];
            }
            byDay[day].push(a);
        });

        // Calculate daily stats
        const dailyStats = Object.keys(byDay).map(day => ({
            date: day,
            count: byDay[day].length,
            avgScore: byDay[day].reduce((sum, a) => sum + a.score, 0) / byDay[day].length,
            critical: byDay[day].filter(a => a.classification === 'CRITICAL').length,
            suspicious: byDay[day].filter(a => a.classification === 'SUSPICIOUS').length
        }));

        return {
            period: days,
            total: recent.length,
            daily: dailyStats,
            avgScore: recent.reduce((sum, a) => sum + a.score, 0) / recent.length
        };
    },

    exportHistory(format = 'json') {
        if (format === 'json') {
            return JSON.stringify({
                version: '2.1',
                exported: new Date().toISOString(),
                count: this.history.length,
                analyses: this.history
            }, null, 2);
        } else if (format === 'csv') {
            return this.exportCSV();
        }
        throw new Error('Unknown format: ' + format);
    },

    exportCSV() {
        const headers = [
            'Timestamp',
            'File Name',
            'Score',
            'Classification',
            'Connection Count',
            'Threat Intel Matches',
            'ML Prediction'
        ];

        const rows = this.history.map(a => [
            a.timestamp,
            a.fileName || 'N/A',
            a.score,
            a.classification,
            a.connectionCount || 0,
            a.threatIntel?.matches?.length || 0,
            a.mlPrediction?.ensemble?.prediction || 'N/A'
        ]);

        const csv = [
            headers.join(','),
            ...rows.map(row => row.map(cell => {
                // Escape cells with commas
                if (typeof cell === 'string' && cell.includes(',')) {
                    return `"${cell}"`;
                }
                return cell;
            }).join(','))
        ].join('\n');

        return csv;
    },

    importHistory(jsonString) {
        try {
            const data = JSON.parse(jsonString);
            const analyses = data.analyses || data;

            if (!Array.isArray(analyses)) {
                throw new Error('Invalid history format');
            }

            // Merge with existing history
            analyses.forEach(analysis => {
                // Avoid duplicates
                if (!this.history.find(a => a.id === analysis.id)) {
                    this.history.push(analysis);
                }
            });

            // Sort and save
            this.history.sort((a, b) => 
                new Date(b.timestamp) - new Date(a.timestamp)
            );
            
            this.saveHistory();
            
            console.log(`Imported ${analyses.length} analyses`);
            return true;
        } catch (error) {
            console.error('Import failed:', error);
            throw error;
        }
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HistoryManager;
}

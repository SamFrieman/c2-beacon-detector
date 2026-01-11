// Historical Analysis Manager v2.1
const HistoryManager = {
    history: [],
    maxHistorySize: 100,

    initialize() {
        this.loadHistory();
        console.log(`✓ Loaded ${this.history.length} historical analyses`);
    },

    saveAnalysis(analysis, fileName, connections) {
        const record = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            fileName: fileName,
            summary: {
                score: analysis.score,
                classification: analysis.classification,
                severity: analysis.severity,
                connectionCount: connections.length,
                duration: analysis.features.duration_minutes,
                threatIntelMatches: analysis.threatIntelMatches?.length || 0,
                mlPrediction: analysis.mlResults?.ensemble?.prediction || 'N/A'
            },
            features: analysis.features,
            fullAnalysis: analysis
        };

        this.history.unshift(record); // Add to beginning

        // Limit history size
        if (this.history.length > this.maxHistorySize) {
            this.history = this.history.slice(0, this.maxHistorySize);
        }

        this.persistHistory();
        return record.id;
    },

    loadHistory() {
        try {
            const saved = localStorage.getItem('c2detector_history');
            if (saved) {
                this.history = JSON.parse(saved);
            }
        } catch (err) {
            console.warn('Failed to load history:', err);
            this.history = [];
        }
    },

    persistHistory() {
        try {
            localStorage.setItem('c2detector_history', JSON.stringify(this.history));
        } catch (err) {
            console.error('Failed to save history:', err);
        }
    },

    getHistory(limit = 10) {
        return this.history.slice(0, limit);
    },

    getById(id) {
        return this.history.find(h => h.id === id);
    },

    deleteById(id) {
        this.history = this.history.filter(h => h.id !== id);
        this.persistHistory();
    },

    clearHistory() {
        this.history = [];
        this.persistHistory();
    },

    generateId() {
        return `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    },

    // Statistical comparison
    compareWithHistory(currentAnalysis) {
        if (this.history.length < 5) {
            return {
                hasEnoughData: false,
                message: 'Need at least 5 historical analyses for comparison'
            };
        }

        const historicalScores = this.history.map(h => h.summary.score);
        const historicalJitter = this.history.map(h => h.features.jitter);
        const historicalPeriodicity = this.history.map(h => h.features.periodicity);

        const stats = {
            score: this.calculatePercentile(currentAnalysis.score, historicalScores),
            jitter: this.calculatePercentile(currentAnalysis.features.jitter, historicalJitter),
            periodicity: this.calculatePercentile(currentAnalysis.features.periodicity, historicalPeriodicity)
        };

        return {
            hasEnoughData: true,
            totalHistoricalAnalyses: this.history.length,
            percentiles: stats,
            interpretation: this.interpretComparison(stats),
            similarAnalyses: this.findSimilarAnalyses(currentAnalysis, 3)
        };
    },

    calculatePercentile(value, dataset) {
        const sorted = [...dataset].sort((a, b) => a - b);
        const index = sorted.findIndex(v => v >= value);
        const percentile = index === -1 ? 100 : (index / sorted.length) * 100;
        
        return {
            value: value,
            percentile: Math.round(percentile),
            min: Math.min(...sorted),
            max: Math.max(...sorted),
            median: sorted[Math.floor(sorted.length / 2)],
            mean: sorted.reduce((a, b) => a + b, 0) / sorted.length
        };
    },

    interpretComparison(stats) {
        const interpretations = [];

        if (stats.score.percentile > 90) {
            interpretations.push('🔴 This analysis scored higher than 90% of historical analyses');
        } else if (stats.score.percentile > 70) {
            interpretations.push('🟡 This analysis scored higher than 70% of historical analyses');
        } else {
            interpretations.push('✓ This score is within normal range based on history');
        }

        if (stats.periodicity.percentile > 85) {
            interpretations.push('⚠️ Periodicity is unusually high compared to historical data');
        }

        if (stats.jitter.percentile < 15) {
            interpretations.push('⚠️ Jitter is unusually low compared to historical data');
        }

        return interpretations;
    },

    findSimilarAnalyses(currentAnalysis, count = 3) {
        const similarities = this.history.map(h => ({
            analysis: h,
            similarity: this.calculateSimilarity(currentAnalysis.features, h.features)
        }));

        return similarities
            .sort((a, b) => b.similarity - a.similarity)
            .slice(0, count)
            .map(s => ({
                id: s.analysis.id,
                fileName: s.analysis.fileName,
                timestamp: s.analysis.timestamp,
                score: s.analysis.summary.score,
                classification: s.analysis.summary.classification,
                similarity: Math.round(s.similarity * 100)
            }));
    },

    calculateSimilarity(features1, features2) {
        const importantFeatures = [
            'mean_interval', 'jitter', 'periodicity', 
            'bytes_consistency', 'entropy', 'unique_dest_ips'
        ];

        let similarity = 0;
        let count = 0;

        for (const feature of importantFeatures) {
            if (features1[feature] !== undefined && features2[feature] !== undefined) {
                const diff = Math.abs(features1[feature] - features2[feature]);
                const max = Math.max(features1[feature], features2[feature], 1);
                similarity += 1 - (diff / max);
                count++;
            }
        }

        return count > 0 ? similarity / count : 0;
    },

    // Trend analysis
    getTrends(days = 7) {
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - days);

        const recent = this.history.filter(h => new Date(h.timestamp) > cutoff);

        if (recent.length === 0) {
            return { hasData: false };
        }

        const scoresByDay = {};
        const classificationCounts = {
            CRITICAL: 0,
            SUSPICIOUS: 0,
            MONITOR: 0,
            BENIGN: 0
        };

        recent.forEach(h => {
            const day = h.timestamp.split('T')[0];
            if (!scoresByDay[day]) {
                scoresByDay[day] = [];
            }
            scoresByDay[day].push(h.summary.score);
            classificationCounts[h.summary.classification]++;
        });

        return {
            hasData: true,
            totalAnalyses: recent.length,
            dateRange: {
                start: recent[recent.length - 1].timestamp.split('T')[0],
                end: recent[0].timestamp.split('T')[0]
            },
            averageScore: recent.reduce((sum, h) => sum + h.summary.score, 0) / recent.length,
            classificationBreakdown: classificationCounts,
            dailyAverages: Object.entries(scoresByDay).map(([day, scores]) => ({
                date: day,
                averageScore: scores.reduce((a, b) => a + b, 0) / scores.length,
                count: scores.length
            }))
        };
    },

    exportHistory(format = 'json') {
        if (format === 'json') {
            return JSON.stringify(this.history, null, 2);
        } else if (format === 'csv') {
            return this.convertToCSV();
        }
    },

    convertToCSV() {
        const headers = [
            'Timestamp', 'File Name', 'Score', 'Classification', 
            'Connections', 'Duration (min)', 'Threat Intel Matches',
            'Mean Interval', 'Jitter', 'Periodicity'
        ];

        const rows = this.history.map(h => [
            h.timestamp,
            h.fileName,
            h.summary.score,
            h.summary.classification,
            h.summary.connectionCount,
            h.summary.duration.toFixed(2),
            h.summary.threatIntelMatches,
            h.features.mean_interval.toFixed(2),
            h.features.jitter.toFixed(4),
            h.features.periodicity.toFixed(4)
        ]);

        return [headers, ...rows]
            .map(row => row.map(cell => `"${cell}"`).join(','))
            .join('\n');
    },

    importHistory(jsonString) {
        try {
            const imported = JSON.parse(jsonString);
            if (Array.isArray(imported)) {
                this.history = imported;
                this.persistHistory();
                return { success: true, count: imported.length };
            }
        } catch (err) {
            return { success: false, error: err.message };
        }
    }
};

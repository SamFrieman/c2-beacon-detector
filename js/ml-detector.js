// ml-detector.js - Machine Learning Detection
// Version 2.1.1 - Simplified but effective ML models

const MLDetector = {
    config: {
        enabled: true,
        confidenceThreshold: 0.65,
        useEnsemble: true
    },

    models: {
        beaconClassifier: null,
        anomalyDetector: null
    },

    stats: {
        predictions: 0,
        accuracy: null
    },

    async initialize() {
        console.log('Initializing ML models...');
        
        try {
            // Create beacon classifier
            this.models.beaconClassifier = this.createBeaconClassifier();
            
            // Create anomaly detector
            this.models.anomalyDetector = this.createAnomalyDetector();
            
            console.log('✓ ML models initialized');
            return true;
        } catch (error) {
            console.error('ML initialization error:', error);
            this.config.enabled = false;
            return false;
        }
    },

    createBeaconClassifier() {
        // Rule-based classifier with weighted features
        return {
            predict: (features) => {
                let score = 0;
                let reasons = [];

                // High periodicity is suspicious
                if (features.periodicity > 0.8) {
                    score += 0.35;
                    reasons.push('Very high periodicity');
                } else if (features.periodicity > 0.7) {
                    score += 0.25;
                    reasons.push('High periodicity');
                }

                // Low jitter is suspicious
                if (features.jitter < 0.1) {
                    score += 0.30;
                    reasons.push('Very low jitter');
                } else if (features.jitter < 0.2) {
                    score += 0.20;
                    reasons.push('Low jitter');
                }

                // Consistent payload sizes
                if (features.payloadConsistency > 0.9) {
                    score += 0.20;
                    reasons.push('Very consistent payload');
                } else if (features.payloadConsistency > 0.8) {
                    score += 0.15;
                    reasons.push('Consistent payload');
                }

                // Single destination
                if (features.uniqueDestinations === 1) {
                    score += 0.15;
                    reasons.push('Single destination');
                }

                // Low port diversity
                if (features.portDiversity < 0.1) {
                    score += 0.10;
                    reasons.push('Low port diversity');
                }

                // Duration indicators
                if (features.durationHours > 2) {
                    score += 0.10;
                    reasons.push('Sustained activity');
                }

                // Normalize score
                score = Math.min(1.0, score);

                return {
                    prediction: score >= this.config.confidenceThreshold ? 'malicious' : 'benign',
                    score: score,
                    confidence: this.getConfidenceLevel(score),
                    reasons: reasons
                };
            }
        };
    },

    createAnomalyDetector() {
        // Statistical anomaly detection
        return {
            detect: (features) => {
                const anomalies = [];
                let anomalyScore = 0;

                // Check for unusual patterns
                
                // 1. Extremely regular timing (unlikely in normal traffic)
                if (features.periodicity > 0.85 && features.jitter < 0.15) {
                    anomalies.push({
                        type: 'timing_regularity',
                        severity: 'high',
                        description: 'Unnaturally regular connection timing'
                    });
                    anomalyScore += 0.3;
                }

                // 2. Consistent intervals with specific values
                if (features.meanInterval > 50000 && features.meanInterval < 150000) {
                    // Common beacon intervals (60s, 120s)
                    if (Math.abs(features.meanInterval - 60000) < 5000 ||
                        Math.abs(features.meanInterval - 120000) < 10000) {
                        anomalies.push({
                            type: 'known_beacon_interval',
                            severity: 'high',
                            description: `Interval matches known C2 pattern (${Math.round(features.meanInterval/1000)}s)`
                        });
                        anomalyScore += 0.35;
                    }
                }

                // 3. Very consistent payload sizes
                if (features.payloadConsistency > 0.9) {
                    anomalies.push({
                        type: 'payload_consistency',
                        severity: 'medium',
                        description: 'Unusually consistent payload sizes'
                    });
                    anomalyScore += 0.20;
                }

                // 4. Single destination with many connections
                if (features.uniqueDestinations === 1 && features.connectionCount > 20) {
                    anomalies.push({
                        type: 'single_destination',
                        severity: 'medium',
                        description: 'Many connections to single destination'
                    });
                    anomalyScore += 0.15;
                }

                // 5. Low entropy (automated/scripted behavior)
                if (features.timingEntropy < 2.0) {
                    anomalies.push({
                        type: 'low_entropy',
                        severity: 'medium',
                        description: 'Low timing entropy suggests automation'
                    });
                    anomalyScore += 0.15;
                }

                // 6. Extended duration
                if (features.durationHours > 3) {
                    anomalies.push({
                        type: 'long_duration',
                        severity: 'low',
                        description: `Extended connection pattern (${features.durationHours.toFixed(1)}h)`
                    });
                    anomalyScore += 0.10;
                }

                anomalyScore = Math.min(1.0, anomalyScore);

                return {
                    isAnomaly: anomalyScore >= 0.5,
                    score: anomalyScore,
                    anomalies: anomalies,
                    severity: this.getSeverityLevel(anomalyScore)
                };
            }
        };
    },

    predict(features) {
        if (!this.config.enabled) {
            return {
                enabled: false,
                message: 'ML detection disabled'
            };
        }

        this.stats.predictions++;

        try {
            // Run beacon classifier
            const beaconResult = this.models.beaconClassifier.predict(features);
            
            // Run anomaly detector
            const anomalyResult = this.models.anomalyDetector.detect(features);

            // Combine results (ensemble)
            const ensemble = this.config.useEnsemble ? 
                this.combineResults(beaconResult, anomalyResult) :
                beaconResult;

            return {
                enabled: true,
                beacon: beaconResult,
                anomaly: anomalyResult,
                ensemble: ensemble
            };

        } catch (error) {
            console.error('ML prediction error:', error);
            return {
                enabled: false,
                error: error.message
            };
        }
    },

    combineResults(beaconResult, anomalyResult) {
        // Weighted ensemble
        const beaconWeight = 0.6;
        const anomalyWeight = 0.4;

        const combinedScore = (beaconResult.score * beaconWeight) + 
                             (anomalyResult.score * anomalyWeight);

        // Combine reasons and anomalies
        const allIndicators = [
            ...beaconResult.reasons,
            ...anomalyResult.anomalies.map(a => a.description)
        ];

        return {
            prediction: combinedScore >= this.config.confidenceThreshold ? 'malicious' : 'benign',
            score: combinedScore,
            confidence: this.getConfidenceLevel(combinedScore),
            indicators: allIndicators,
            breakdown: {
                beaconScore: beaconResult.score,
                anomalyScore: anomalyResult.score
            }
        };
    },

    getConfidenceLevel(score) {
        if (score >= 0.85) return 'high';
        if (score >= 0.65) return 'medium';
        if (score >= 0.45) return 'low';
        return 'very low';
    },

    getSeverityLevel(score) {
        if (score >= 0.75) return 'critical';
        if (score >= 0.55) return 'high';
        if (score >= 0.35) return 'medium';
        return 'low';
    },

    explainPrediction(features, prediction) {
        // Provide explanation for the prediction
        const explanation = {
            decision: prediction.ensemble.prediction,
            confidence: prediction.ensemble.confidence,
            score: prediction.ensemble.score,
            keyFactors: []
        };

        // Identify key factors
        if (features.periodicity > 0.7) {
            explanation.keyFactors.push({
                factor: 'High periodicity',
                value: (features.periodicity * 100).toFixed(1) + '%',
                impact: 'Major indicator of beaconing'
            });
        }

        if (features.jitter < 0.15) {
            explanation.keyFactors.push({
                factor: 'Low jitter',
                value: (features.jitter * 100).toFixed(1) + '%',
                impact: 'Indicates automated/regular timing'
            });
        }

        if (features.payloadConsistency > 0.8) {
            explanation.keyFactors.push({
                factor: 'Payload consistency',
                value: (features.payloadConsistency * 100).toFixed(1) + '%',
                impact: 'Suggests automated communication'
            });
        }

        if (prediction.anomaly.anomalies.length > 0) {
            explanation.keyFactors.push({
                factor: 'Anomalies detected',
                value: prediction.anomaly.anomalies.length + ' anomalies',
                impact: 'Multiple unusual patterns found'
            });
        }

        return explanation;
    },

    getStats() {
        return {
            enabled: this.config.enabled,
            predictions: this.stats.predictions,
            threshold: this.config.confidenceThreshold
        };
    },

    // Feature normalization helper
    normalizeFeatures(features) {
        return {
            periodicity: Math.max(0, Math.min(1, features.periodicity)),
            jitter: Math.max(0, Math.min(1, features.jitter)),
            payloadConsistency: Math.max(0, Math.min(1, features.payloadConsistency)),
            portDiversity: Math.max(0, Math.min(1, features.portDiversity)),
            uniqueDestinations: features.uniqueDestinations,
            connectionCount: features.connectionCount,
            durationHours: features.durationHours,
            meanInterval: features.meanInterval,
            timingEntropy: features.timingEntropy
        };
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MLDetector;
}

// Machine Learning Detection Module v2.1
const MLDetector = {
    models: {
        beaconClassifier: null,
        anomalyDetector: null
    },

    config: {
        enabled: true,
        confidenceThreshold: 0.65,
        useEnsemble: true
    },

    // Feature normalization parameters (learned from training data)
    normalization: {
        mean_interval: { mean: 45.2, std: 35.8 },
        jitter: { mean: 0.25, std: 0.18 },
        periodicity: { mean: 0.45, std: 0.28 },
        bytes_cv: { mean: 0.42, std: 0.25 },
        entropy: { mean: 2.8, std: 1.2 },
        connection_count: { mean: 125, std: 95 }
    },

    async initialize() {
        try {
            // In a real implementation, you would load pre-trained models
            // For now, we'll use rule-based ML simulation
            this.models.beaconClassifier = this.createBeaconClassifier();
            this.models.anomalyDetector = this.createAnomalyDetector();
            console.log('✓ ML models initialized');
            return true;
        } catch (err) {
            console.error('ML initialization failed:', err);
            return false;
        }
    },

    // Simulated Random Forest Beacon Classifier
    createBeaconClassifier() {
        return {
            predict: (features) => {
                // Feature importance weights (from simulated training)
                const weights = {
                    periodicity: 0.28,
                    jitter: 0.24,
                    mean_interval: 0.18,
                    bytes_consistency: 0.15,
                    entropy: 0.10,
                    port_entropy: 0.05
                };

                // Normalize features
                const norm = this.normalizeFeatures(features);

                // Simulated decision tree ensemble
                let score = 0;

                // Tree 1: Periodicity-focused
                if (norm.periodicity > 0.7) score += 0.35;
                else if (norm.periodicity > 0.5) score += 0.20;

                // Tree 2: Jitter-focused
                if (norm.jitter < 0.15) score += 0.30;
                else if (norm.jitter < 0.30) score += 0.15;

                // Tree 3: Interval-focused
                if (norm.mean_interval >= 30 && norm.mean_interval <= 180) {
                    score += 0.25;
                }

                // Tree 4: Consistency-focused
                if (norm.bytes_consistency > 0.85) score += 0.20;
                else if (norm.bytes_consistency > 0.70) score += 0.10;

                // Tree 5: Entropy-focused
                if (norm.entropy < 2.0) score += 0.15;

                // Tree 6: Port behavior
                if (norm.port_entropy < 0.5 && features.unique_dest_ports === 1) {
                    score += 0.10;
                }

                return {
                    probability: Math.min(1.0, score),
                    confidence: score > this.config.confidenceThreshold ? 'high' : 'medium',
                    features_used: Object.keys(weights)
                };
            }
        };
    },

    // Simulated Isolation Forest Anomaly Detector
    createAnomalyDetector() {
        return {
            predict: (features) => {
                // Anomaly score based on statistical outliers
                const anomalyFactors = [];

                // Check timing regularity (low variance = anomalous for normal traffic)
                if (features.jitter < 0.10) {
                    anomalyFactors.push({ factor: 'ultra_low_jitter', score: 0.9 });
                } else if (features.jitter < 0.20) {
                    anomalyFactors.push({ factor: 'low_jitter', score: 0.6 });
                }

                // Check extreme periodicity
                if (features.periodicity > 0.80) {
                    anomalyFactors.push({ factor: 'extreme_periodicity', score: 0.95 });
                } else if (features.periodicity > 0.65) {
                    anomalyFactors.push({ factor: 'high_periodicity', score: 0.7 });
                }

                // Check payload consistency
                if (features.bytes_consistency > 0.90) {
                    anomalyFactors.push({ factor: 'identical_payloads', score: 0.85 });
                }

                // Check connection pattern
                if (features.unique_dest_ips === 1 && features.connection_count > 30) {
                    anomalyFactors.push({ factor: 'single_destination', score: 0.75 });
                }

                // Check entropy
                if (features.entropy < 1.5) {
                    anomalyFactors.push({ factor: 'low_entropy', score: 0.80 });
                }

                // Calculate anomaly score
                const anomalyScore = anomalyFactors.length > 0 
                    ? anomalyFactors.reduce((sum, f) => sum + f.score, 0) / anomalyFactors.length
                    : 0;

                return {
                    is_anomaly: anomalyScore > 0.6,
                    anomaly_score: anomalyScore,
                    anomaly_factors: anomalyFactors,
                    confidence: anomalyScore > 0.8 ? 'high' : anomalyScore > 0.6 ? 'medium' : 'low'
                };
            }
        };
    },

    normalizeFeatures(features) {
        const normalized = {};
        
        for (const [key, value] of Object.entries(features)) {
            if (this.normalization[key]) {
                const { mean, std } = this.normalization[key];
                normalized[key] = (value - mean) / std;
            } else {
                normalized[key] = value;
            }
        }
        
        return normalized;
    },

    async predict(features) {
        if (!this.config.enabled) {
            return null;
        }

        const results = {
            ml_enabled: true,
            models: {}
        };

        // Beacon classification
        if (this.models.beaconClassifier) {
            results.models.beacon_classifier = this.models.beaconClassifier.predict(features);
        }

        // Anomaly detection
        if (this.models.anomalyDetector) {
            results.models.anomaly_detector = this.models.anomalyDetector.predict(features);
        }

        // Ensemble prediction
        if (this.config.useEnsemble) {
            results.ensemble = this.ensemblePrediction(results.models);
        }

        return results;
    },

    ensemblePrediction(models) {
        const predictions = [];

        if (models.beacon_classifier) {
            predictions.push({
                model: 'beacon_classifier',
                score: models.beacon_classifier.probability,
                weight: 0.6
            });
        }

        if (models.anomaly_detector) {
            predictions.push({
                model: 'anomaly_detector',
                score: models.anomaly_detector.anomaly_score,
                weight: 0.4
            });
        }

        // Weighted average
        const totalWeight = predictions.reduce((sum, p) => sum + p.weight, 0);
        const ensembleScore = predictions.reduce((sum, p) => sum + (p.score * p.weight), 0) / totalWeight;

        return {
            score: ensembleScore,
            prediction: ensembleScore > 0.65 ? 'malicious' : ensembleScore > 0.45 ? 'suspicious' : 'benign',
            confidence: ensembleScore > 0.75 ? 'high' : ensembleScore > 0.55 ? 'medium' : 'low',
            contributing_models: predictions
        };
    },

    // Feature importance explanation
    explainPrediction(features, prediction) {
        const explanations = [];

        // Analyze which features contributed most
        if (features.periodicity > 0.7) {
            explanations.push({
                feature: 'periodicity',
                value: features.periodicity,
                impact: 'high',
                reason: 'Extremely regular timing pattern detected'
            });
        }

        if (features.jitter < 0.15) {
            explanations.push({
                feature: 'jitter',
                value: features.jitter,
                impact: 'high',
                reason: 'Very low timing variance indicates automated beaconing'
            });
        }

        if (features.bytes_consistency > 0.85) {
            explanations.push({
                feature: 'bytes_consistency',
                value: features.bytes_consistency,
                impact: 'medium',
                reason: 'Highly consistent payload sizes'
            });
        }

        if (features.entropy < 2.0) {
            explanations.push({
                feature: 'entropy',
                value: features.entropy,
                impact: 'medium',
                reason: 'Low entropy suggests predictable pattern'
            });
        }

        return {
            top_features: explanations,
            prediction_confidence: prediction.ensemble?.confidence || 'unknown'
        };
    },

    // Train on historical data (simulation)
    async trainOnHistory(historicalAnalyses) {
        console.log(`Training on ${historicalAnalyses.length} historical analyses...`);
        
        // In a real implementation, this would retrain the models
        // For now, we'll update normalization parameters
        
        const allFeatures = historicalAnalyses.map(a => a.features);
        
        // Update normalization stats
        for (const key of ['mean_interval', 'jitter', 'periodicity', 'bytes_cv', 'entropy']) {
            const values = allFeatures.map(f => f[key]).filter(v => v !== undefined);
            if (values.length > 0) {
                const mean = values.reduce((a, b) => a + b, 0) / values.length;
                const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
                
                this.normalization[key] = {
                    mean: mean,
                    std: Math.sqrt(variance)
                };
            }
        }

        console.log('✓ ML models updated with historical data');
        return true;
    }
};

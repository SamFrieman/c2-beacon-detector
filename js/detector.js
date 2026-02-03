// detector.js - Detection & Scoring Engine
// Version 2.1.1

const Detector = {
    async analyze(features, connections) {
        console.log('Running detection analysis...');

        const result = {
            score: 0,
            classification: 'BENIGN',
            severity: 'info',
            detectionFactors: [],
            features: features,
            threatIntel: null,
            mlPrediction: null,
            recommendation: ''
        };

        // 1. Threat Intelligence Lookup
        if (typeof ThreatIntel !== 'undefined') {
            result.threatIntel = await this.checkThreatIntel(connections);
            if (result.threatIntel.matches.length > 0) {
                const tiScore = this.scoreThreatIntel(result.threatIntel);
                result.score += tiScore;
                result.detectionFactors.push({
                    factor: 'Threat Intelligence Match',
                    points: tiScore,
                    details: `${result.threatIntel.matches.length} IOC(s) matched`
                });
            }
        }

        // 2. Machine Learning Prediction
        if (typeof MLDetector !== 'undefined' && MLDetector.config.enabled) {
            result.mlPrediction = MLDetector.predict(features);
            if (result.mlPrediction.enabled) {
                const mlScore = this.scoreMLPrediction(result.mlPrediction);
                result.score += mlScore;
                if (mlScore > 0) {
                    result.detectionFactors.push({
                        factor: 'Machine Learning Detection',
                        points: mlScore,
                        details: `Prediction: ${result.mlPrediction.ensemble.prediction}`
                    });
                }
            }
        }

        // 3. Behavioral Scoring
        const behavioralScore = this.scoreBehavioral(features);
        result.score += behavioralScore.total;
        result.detectionFactors.push(...behavioralScore.factors);

        // 4. Apply benign indicators (negative scoring)
        const benignScore = this.scoreBenignIndicators(features);
        if (benignScore < 0) {
            result.score += benignScore;
            result.detectionFactors.push({
                factor: 'Benign Indicators',
                points: benignScore,
                details: 'Traffic shows characteristics of normal behavior'
            });
        }

        // Ensure score is within bounds
        result.score = Math.max(0, Math.min(100, result.score));

        // Classify based on score
        result.classification = this.classify(result.score);
        result.severity = this.getSeverity(result.score);
        result.recommendation = this.getRecommendation(result.score, result.classification);

        console.log(`Detection complete: ${result.classification} (${result.score})`);
        return result;
    },

   // Optimized checkThreatIntel in detector.js
async checkThreatIntel(connections) {
    const ips = Utils.extractUniqueIPs(connections).slice(0, ThreatIntel.config.maxIPs);
    
    // Launch all lookups simultaneously
    const lookupPromises = ips.map(ip => ThreatIntel.lookupIP(ip));
    const allResults = await Promise.all(lookupPromises);
    
    const matches = allResults.flat().filter(Boolean);
    return { checked: ips.length, matches };
},

    scoreThreatIntel(threatIntel) {
        if (!threatIntel.matches || threatIntel.matches.length === 0) {
            return 0;
        }

        let score = 0;

        threatIntel.matches.forEach(match => {
            // Base score from match
            score += 30;

            // Bonus for high confidence
            if (match.confidence >= 80) {
                score += 20;
            } else if (match.confidence >= 60) {
                score += 10;
            }

            // Bonus for known malware family
            if (match.malware && match.malware !== 'Unknown') {
                score += 10;
            }

            // Bonus for multiple sources
            if (match.source === 'ThreatFox') {
                score += 10;
            }
        });

        // Cap at 70 points
        return Math.min(70, score);
    },

    scoreMLPrediction(mlPrediction) {
        if (!mlPrediction.enabled || !mlPrediction.ensemble) {
            return 0;
        }

        const ensemble = mlPrediction.ensemble;
        
        if (ensemble.prediction === 'malicious') {
            // Base score
            let score = 20;

            // Add based on confidence
            if (ensemble.confidence === 'high') {
                score += 15;
            } else if (ensemble.confidence === 'medium') {
                score += 10;
            } else {
                score += 5;
            }

            return score;
        }

        return 0;
    },

    scoreBehavioral(features) {
        const factors = [];
        let total = 0;

        // Periodicity scoring
        if (features.periodicity > 0.80) {
            const points = 35;
            total += points;
            factors.push({
                factor: 'Extreme Periodicity',
                points: points,
                details: `${(features.periodicity * 100).toFixed(1)}% - Highly regular timing`
            });
        } else if (features.periodicity > 0.70) {
            const points = 25;
            total += points;
            factors.push({
                factor: 'High Periodicity',
                points: points,
                details: `${(features.periodicity * 100).toFixed(1)}% - Regular intervals`
            });
        } else if (features.periodicity > 0.60) {
            const points = 15;
            total += points;
            factors.push({
                factor: 'Moderate Periodicity',
                points: points,
                details: `${(features.periodicity * 100).toFixed(1)}%`
            });
        }

        // Jitter scoring
        if (features.jitter < 0.08) {
            const points = 30;
            total += points;
            factors.push({
                factor: 'Extremely Low Jitter',
                points: points,
                details: `${(features.jitter * 100).toFixed(1)}% - Consistent timing`
            });
        } else if (features.jitter < 0.15) {
            const points = 20;
            total += points;
            factors.push({
                factor: 'Low Jitter',
                points: points,
                details: `${(features.jitter * 100).toFixed(1)}%`
            });
        } else if (features.jitter < 0.25) {
            const points = 10;
            total += points;
            factors.push({
                factor: 'Consistent Timing',
                points: points,
                details: `${(features.jitter * 100).toFixed(1)}% jitter`
            });
        }

        // Payload consistency
        if (features.payloadConsistency > 0.90) {
            const points = 20;
            total += points;
            factors.push({
                factor: 'Very Consistent Payloads',
                points: points,
                details: `${(features.payloadConsistency * 100).toFixed(1)}% similarity`
            });
        } else if (features.payloadConsistency > 0.80) {
            const points = 15;
            total += points;
            factors.push({
                factor: 'Consistent Payloads',
                points: points,
                details: `${(features.payloadConsistency * 100).toFixed(1)}% similarity`
            });
        }

        // Known beacon signatures
        if (features.frameworkSignatures && features.frameworkSignatures.length > 0) {
            const sig = features.frameworkSignatures[0];
            const points = sig.confidence === 'high' ? 20 : sig.confidence === 'medium' ? 15 : 10;
            total += points;
            factors.push({
                factor: `${sig.framework} Signature`,
                points: points,
                details: sig.reason
            });
        }

        // Persistence
        if (features.durationHours > 2) {
            const points = 15;
            total += points;
            factors.push({
                factor: 'Sustained Activity',
                points: points,
                details: `${features.durationHours.toFixed(1)} hours of activity`
            });
        } else if (features.durationHours > 1) {
            const points = 10;
            total += points;
            factors.push({
                factor: 'Extended Activity',
                points: points,
                details: `${features.durationHours.toFixed(1)} hours`
            });
        }

        // Network patterns
        if (features.uniqueDestinations === 1) {
            const points = 12;
            total += points;
            factors.push({
                factor: 'Single Destination',
                points: points,
                details: 'All connections to one IP'
            });
        }

        if (features.portDiversity < 0.15) {
            const points = 10;
            total += points;
            factors.push({
                factor: 'Low Port Diversity',
                points: points,
                details: 'Consistent port usage'
            });
        }

        // Low entropy
        if (features.timingEntropy < 2.5) {
            const points = 10;
            total += points;
            factors.push({
                factor: 'Low Timing Entropy',
                points: points,
                details: 'Predictable timing pattern'
            });
        }

        return { total, factors };
    },

    scoreBenignIndicators(features) {
        let penalty = 0;

        // High jitter (inconsistent timing)
        if (features.jitter > 0.60) {
            penalty -= 15;
        } else if (features.jitter > 0.45) {
            penalty -= 10;
        }

        // Multiple destinations
        if (features.uniqueDestinations > 5) {
            penalty -= 15;
        } else if (features.uniqueDestinations > 3) {
            penalty -= 10;
        }

        // Very short intervals (< 5s) - might be normal web browsing
        if (features.meanInterval < 5000) {
            penalty -= 10;
        }

        // High time diversity
        if (features.timingEntropy > 4.0) {
            penalty -= 10;
        }

        // Very high port diversity
        if (features.portDiversity > 0.7) {
            penalty -= 10;
        }

        return penalty;
    },

    classify(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 65) return 'SUSPICIOUS';
        if (score >= 45) return 'MONITOR';
        return 'BENIGN';
    },

    getSeverity(score) {
        if (score >= 80) return 'critical';
        if (score >= 65) return 'high';
        if (score >= 45) return 'medium';
        return 'info';
    },

    getRecommendation(score, classification) {
        const recommendations = {
            'CRITICAL': '🚨 IMMEDIATE ACTION REQUIRED: This traffic shows strong indicators of C2 beaconing. Recommend immediate isolation of the host, full incident response procedures, and forensic analysis.',
            'SUSPICIOUS': '⚠️ URGENT INVESTIGATION NEEDED: Multiple indicators suggest potential C2 activity. Recommend enhanced monitoring, packet capture, and investigation by security team.',
            'MONITOR': '👁️ ENHANCED MONITORING RECOMMENDED: Some suspicious patterns detected. Consider increased logging and continued observation to determine if this is malicious or benign.',
            'BENIGN': '✅ APPEARS BENIGN: Traffic patterns are consistent with normal network activity. No immediate action required, but continue standard monitoring.'
        };

        return recommendations[classification] || 'No recommendation available.';
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Detector;
}

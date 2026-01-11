// Detection Engine Module
const Detector = {
    detect(features, threatIntelMatches) {
        let score = 0;
        const reasons = [];
        const technicalDetails = [];

        // THREAT INTELLIGENCE MATCHES - Highest priority
        if (threatIntelMatches && threatIntelMatches.length > 0) {
            const highestConfidence = Math.max(...threatIntelMatches.map(m => m.confidence_level));
            
            score += 45; // Base score for any threat intel match
            
            if (highestConfidence >= 75) {
                score += 25;
                reasons.push(`🔴 CRITICAL: Matched ${threatIntelMatches.length} known malicious IOC(s) - HIGH CONFIDENCE`);
            } else {
                score += 15;
                reasons.push(`🟡 HIGH: Matched ${threatIntelMatches.length} known malicious IOC(s)`);
            }

            threatIntelMatches.forEach(match => {
                reasons.push(`   • ${match.malware} (${match.threat_type}) - ${match.connection_count} connections`);
                technicalDetails.push(`IOC: ${match.ip} | Malware: ${match.malware} | First seen: ${match.first_seen}`);
            });
        }

        // PERIODICITY ANALYSIS
        if (features.periodicity > 0.80) {
            score += 35;
            reasons.push(`🔴 CRITICAL: Extreme periodicity (${(features.periodicity * 100).toFixed(1)}%)`);
            technicalDetails.push(`Periodicity: ${features.periodicity.toFixed(3)} (threshold: >0.80)`);
        } else if (features.periodicity > 0.70) {
            score += 25;
            reasons.push(`🟡 HIGH: Strong periodicity (${(features.periodicity * 100).toFixed(1)}%)`);
        } else if (features.periodicity > 0.60) {
            score += 15;
            reasons.push(`⚠️ MODERATE: Notable periodicity (${(features.periodicity * 100).toFixed(1)}%)`);
        }

        // JITTER ANALYSIS
        if (features.jitter < 0.08) {
            score += 30;
            reasons.push(`🔴 CRITICAL: Extremely low jitter (${(features.jitter * 100).toFixed(2)}%)`);
            technicalDetails.push(`Jitter (CV): ${features.jitter.toFixed(4)} (threshold: <0.08)`);
        } else if (features.jitter < 0.15) {
            score += 20;
            reasons.push(`🟡 HIGH: Low jitter (${(features.jitter * 100).toFixed(2)}%)`);
        } else if (features.jitter < 0.25) {
            score += 10;
            reasons.push(`⚠️ MODERATE: Consistent timing (${(features.jitter * 100).toFixed(2)}%)`);
        }

        // PAYLOAD CONSISTENCY
        if (features.bytes_consistency > 0.90) {
            score += 20;
            reasons.push(`🔴 Very consistent payload sizes (${(features.bytes_consistency * 100).toFixed(1)}%)`);
            technicalDetails.push(`Bytes CV: ${features.bytes_cv.toFixed(4)} | Avg: ${Utils.formatBytes(features.avg_bytes)}`);
        } else if (features.bytes_consistency > 0.80) {
            score += 15;
            reasons.push(`🟡 Consistent payloads (${(features.bytes_consistency * 100).toFixed(1)}%)`);
        }

        // INTERVAL RANGE ANALYSIS
        const interval = features.mean_interval;
        if (interval >= 30 && interval <= 300) {
            score += 15;
            reasons.push(`⚠️ Interval (${interval.toFixed(1)}s) in common C2 range (30-300s)`);
        }

        // SPECIFIC C2 SIGNATURES
        if (interval >= 58 && interval <= 62 && features.jitter < 0.10) {
            score += 20;
            reasons.push(`🔴 CRITICAL: 60s beacon - COBALT STRIKE signature`);
        }

        if (interval >= 115 && interval <= 125 && features.jitter < 0.12) {
            score += 18;
            reasons.push(`🔴 HIGH: 120s beacon - METASPLOIT signature`);
        }

        // DURATION AND PERSISTENCE
        if (features.duration_minutes > 120 && features.connection_count > 50) {
            score += 15;
            reasons.push(`🔴 Sustained beaconing: ${Utils.formatDuration(features.duration_minutes)}`);
        } else if (features.duration_minutes > 60 && features.connection_count > 30) {
            score += 12;
            reasons.push(`🟡 Extended pattern: ${Utils.formatDuration(features.duration_minutes)}`);
        }

        // NETWORK PATTERNS
        if (features.unique_dest_ips === 1 && features.connection_count > 20) {
            score += 12;
            reasons.push(`⚠️ Single destination IP with ${features.connection_count} connections`);
        }

        if (features.port_entropy < 0.5 && features.unique_dest_ports === 1) {
            score += 10;
            reasons.push(`⚠️ Single destination port (low port diversity)`);
            technicalDetails.push(`Port entropy: ${features.port_entropy.toFixed(3)}`);
        }

        // ENTROPY ANALYSIS
        if (features.entropy < 1.5 && features.connection_count > 20) {
            score += 12;
            reasons.push(`🟡 Low entropy (${features.entropy.toFixed(2)}) suggests automated pattern`);
        }

        // TIME PATTERNS
        if (features.night_ratio > 0.7 && features.connection_count > 30) {
            score += 8;
            reasons.push(`⚠️ High ratio of night activity (${(features.night_ratio * 100).toFixed(0)}%)`);
        }

        // BENIGN INDICATORS (reduce score)
        if (interval < 3) {
            score -= 25;
            reasons.push(`✓ Very short intervals suggest legitimate traffic`);
        } else if (features.cv_interval > 0.70) {
            score -= 20;
            reasons.push(`✓ High variability suggests organic behavior`);
        }

        if (features.unique_dest_ips > 10) {
            score -= 15;
            reasons.push(`✓ Multiple destinations (${features.unique_dest_ips})`);
        }

        if (features.time_diversity > 0.7) {
            score -= 10;
            reasons.push(`✓ Activity spread across day (${(features.time_diversity * 100).toFixed(0)}% hour coverage)`);
        }

        // Calculate final score
        const finalScore = Math.max(0, Math.min(100, score));

        // Determine classification
        let classification, severity, recommendation;
        if (finalScore >= 80) {
            classification = 'CRITICAL';
            severity = 'critical';
            recommendation = '🚨 IMMEDIATE ACTION: High confidence C2 detected. Isolate host, capture memory/disk, escalate to IR team immediately.';
        } else if (finalScore >= 65) {
            classification = 'SUSPICIOUS';
            severity = 'high';
            recommendation = '⚠️ INVESTIGATE IMMEDIATELY: Strong C2 indicators. Correlate with SIEM/EDR logs, check process tree, inspect network traffic.';
        } else if (finalScore >= 45) {
            classification = 'MONITOR';
            severity = 'medium';
            recommendation = '👁️ ENHANCED MONITORING: Moderate indicators. Continue observation, correlate with threat intel, review endpoint telemetry.';
        } else {
            classification = 'BENIGN';
            severity = 'info';
            recommendation = '✓ APPEARS BENIGN: Patterns consistent with legitimate traffic. Continue normal monitoring.';
        }

        // Get framework identification
        const frameworks = Analyzer.identifyFramework(features, threatIntelMatches);
        
        // Get MITRE ATT&CK mapping
        const mitreTechniques = Analyzer.getMITREMapping(features);

        return {
            score: finalScore,
            classification,
            severity,
            recommendation,
            reasons,
            technicalDetails,
            features,
            identifiedFrameworks: frameworks,
            mitreTechniques: mitreTechniques,
            threatIntelMatches: threatIntelMatches || [],
            timestamp: new Date().toISOString()
        };
    },

    generateReport(result, fileName, connections) {
        const ips = Utils.extractUniqueIPs(connections);
        
        return {
            metadata: {
                tool: 'C2 Beacon Detector',
                version: '2.0.0',
                timestamp: result.timestamp,
                analyzed_file: fileName,
                threat_intel_enabled: result.threatIntelMatches.length > 0
            },
            summary: {
                score: result.score,
                classification: result.classification,
                severity: result.severity,
                recommendation: result.recommendation
            },
            threat_intelligence: {
                matches: result.threatIntelMatches,
                total_iocs_matched: result.threatIntelMatches.length
            },
            behavioral_analysis: {
                frameworks: result.identifiedFrameworks,
                mitre_techniques: result.mitreTechniques,
                detection_factors: result.reasons,
                technical_details: result.technicalDetails
            },
            network_data: {
                total_connections: connections.length,
                unique_dest_ips: ips.destIPs,
                unique_src_ips: ips.srcIPs,
                duration: Utils.formatDuration(result.features.duration_minutes),
                total_bytes: Utils.formatBytes(result.features.total_bytes)
            },
            features: result.features
        };
    }
};

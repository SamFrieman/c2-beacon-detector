
/**
 * C2 Beacon Detection Engine
 * Implements the behavioral detection algorithm
 */

const Detector = {
    /**
     * Main detection function - analyzes features and produces threat assessment
     * @param {Object} features - Extracted features from Analyzer
     * @returns {Object} Detection results with score, classification, and recommendations
     */
    detect: function(features) {
        let suspicionScore = 0;
        const reasons = [];
        const technicalDetails = [];

        // === CRITICAL INDICATORS ===
        
        // 1. Extreme Periodicity (35 points)
        if (features.periodicity > 0.80) {
            suspicionScore += 35;
            reasons.push(`🔴 CRITICAL: Extreme periodicity (${(features.periodicity * 100).toFixed(1)}%) - connections follow highly regular pattern`);
            technicalDetails.push(`Periodicity: ${features.periodicity.toFixed(3)} (threshold: >0.80)`);
        } else if (features.periodicity > 0.70) {
            suspicionScore += 25;
            reasons.push(`🟡 HIGH: Strong periodicity (${(features.periodicity * 100).toFixed(1)}%) detected`);
            technicalDetails.push(`Periodicity: ${features.periodicity.toFixed(3)} (threshold: >0.70)`);
        } else if (features.periodicity > 0.60) {
            suspicionScore += 15;
            reasons.push(`⚠️ MODERATE: Notable periodicity (${(features.periodicity * 100).toFixed(1)}%)`);
        }

        // 2. Very Low Jitter (30 points)
        if (features.jitter < 0.08) {
            suspicionScore += 30;
            reasons.push(`🔴 CRITICAL: Extremely low jitter (${(features.jitter * 100).toFixed(2)}%) - automated timing signature`);
            technicalDetails.push(`Jitter (CV): ${features.jitter.toFixed(4)} (threshold: <0.08)`);
        } else if (features.jitter < 0.15) {
            suspicionScore += 20;
            reasons.push(`🟡 HIGH: Low jitter (${(features.jitter * 100).toFixed(2)}%) indicates automated process`);
            technicalDetails.push(`Jitter (CV): ${features.jitter.toFixed(4)} (threshold: <0.15)`);
        } else if (features.jitter < 0.25) {
            suspicionScore += 10;
            reasons.push(`⚠️ MODERATE: Relatively consistent timing (jitter: ${(features.jitter * 100).toFixed(2)}%)`);
        }

        // 3. Payload Consistency (20 points)
        if (features.bytes_consistency > 0.90) {
            suspicionScore += 20;
            reasons.push(`🔴 HIGH: Very consistent payload sizes (${(features.bytes_consistency * 100).toFixed(1)}%) - typical of C2 beaconing`);
            technicalDetails.push(`Byte size CV: ${features.bytes_cv.toFixed(3)} (consistency: ${features.bytes_consistency.toFixed(3)})`);
        } else if (features.bytes_consistency > 0.80) {
            suspicionScore += 15;
            reasons.push(`🟡 MODERATE: Consistent payload sizes (${(features.bytes_consistency * 100).toFixed(1)}%)`);
        }

        // === TIMING ANALYSIS ===

        // 4. Suspicious Interval Range (15 points)
        const interval = features.mean_interval;
        if (interval >= 30 && interval <= 300) {
            suspicionScore += 15;
            reasons.push(`⚠️ Mean interval (${interval.toFixed(1)}s) within common C2 range (30-300s)`);
            technicalDetails.push(`Common C2 frameworks: Cobalt Strike (~60s), Metasploit (60-120s), Empire (variable)`);
        } else if (interval >= 10 && interval < 30) {
            suspicionScore += 10;
            reasons.push(`⚠️ Short interval (${interval.toFixed(1)}s) - possible aggressive C2 configuration`);
        } else if (interval > 300 && interval <= 600) {
            suspicionScore += 8;
            reasons.push(`⚠️ Long interval (${interval.toFixed(1)}s) - possible stealthy C2`);
        }

        // 5. Specific Framework Signatures
        if (interval >= 58 && interval <= 62 && features.jitter < 0.10) {
            suspicionScore += 20;
            reasons.push(`🔴 CRITICAL: 60-second beacon with low jitter - COBALT STRIKE signature`);
            technicalDetails.push(`Cobalt Strike default beacon: 60s ±5%`);
        }

        if (interval >= 115 && interval <= 125 && features.jitter < 0.12) {
            suspicionScore += 18;
            reasons.push(`🔴 HIGH: 120-second beacon pattern - METASPLOIT/METERPRETER signature`);
            technicalDetails.push(`Meterpreter default sleep: 120s`);
        }

        // === PERSISTENCE INDICATORS ===

        // 6. Long-Running Connection Pattern (15 points)
        if (features.duration_minutes > 120 && features.connection_count > 50) {
            suspicionScore += 15;
            reasons.push(`🔴 Sustained beaconing over ${Utils.formatDuration(features.duration_minutes)} with ${features.connection_count} connections`);
        } else if (features.duration_minutes > 60 && features.connection_count > 30) {
            suspicionScore += 12;
            reasons.push(`🟡 Extended connection pattern: ${Utils.formatDuration(features.duration_minutes)}, ${features.connection_count} connections`);
        } else if (features.duration_minutes > 30 && features.connection_count > 20) {
            suspicionScore += 8;
            reasons.push(`⚠️ Moderate duration: ${Utils.formatDuration(features.duration_minutes)}, ${features.connection_count} connections`);
        }

        // === DESTINATION ANALYSIS ===

        // 7. Single Destination (10 points)
        if (features.unique_dest_ips === 1 && features.connection_count > 10) {
            suspicionScore += 10;
            reasons.push(`⚠️ All ${features.connection_count} connections target single IP (common C2 behavior)`);
        }

        if (features.unique_dest_ports === 1) {
            suspicionScore += 5;
            reasons.push(`⚠️ Consistent destination port usage`);
        }

        // 8. High Connection Rate
        if (features.connections_per_minute > 5 && features.duration_minutes > 10) {
            suspicionScore += 5;
            reasons.push(`⚠️ High connection rate: ${features.connections_per_minute.toFixed(1)} connections/minute`);
        }

        // === BENIGN INDICATORS (Reduce Score) ===

        // Very short intervals suggest legitimate app
        if (interval < 3) {
            suspicionScore -= 25;
            reasons.push(`✓ Very short intervals (<3s) more typical of legitimate real-time applications`);
        } else if (interval < 5) {
            suspicionScore -= 15;
            reasons.push(`✓ Short intervals suggest legitimate application traffic`);
        }

        // High variability suggests human behavior
        if (features.cv_interval > 0.70) {
            suspicionScore -= 20;
            reasons.push(`✓ High timing variability (${(features.cv_interval * 100).toFixed(1)}%) suggests organic/human behavior`);
        } else if (features.cv_interval > 0.50)

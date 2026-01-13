// threat-intel.js - Fixed version with proper error handling

const ThreatIntel = {
    config: {
        threatfoxAPI: 'https://threatfox-api.abuse.ch/api/v1/',
        cacheExpiry: 3600000, // 1 hour
        maxIPs: 20,
        enabledSources: {
            threatfox: true,
            customRules: true
        },
        timeout: 10000, // 10 second timeout
        retryAttempts: 2
    },

    cache: new Map(),
    customRules: [],
    stats: {
        threatfoxIOCs: 0,
        customRules: 0,
        lastUpdate: null,
        status: 'initializing',
        error: null
    },

    async initialize() {
        console.log('Initializing Threat Intelligence...');
        
        // Load custom rules from storage
        this.loadCustomRules();
        
        // Try to initialize ThreatFox with error handling
        if (this.config.enabledSources.threatfox) {
            try {
                await this.initializeThreatFox();
            } catch (error) {
                console.warn('ThreatFox initialization failed:', error);
                this.stats.status = 'threatfox-offline';
                this.stats.error = error.message;
                // Continue anyway - custom rules can still work
            }
        }

        this.stats.lastUpdate = new Date().toISOString();
        console.log('✓ Threat Intel initialized:', this.stats);
        return this.stats;
    },

    async initializeThreatFox() {
        try {
            // Test API connectivity with timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
            
            const response = await fetch(this.config.threatfoxAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: 'get_iocs', days: 1 }),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`ThreatFox API returned ${response.status}`);
            }

            const data = await response.json();
            
            if (data.query_status === 'ok' && data.data) {
                this.stats.threatfoxIOCs = data.data.length;
                this.stats.status = 'online';
                console.log(`✓ ThreatFox: Loaded ${data.data.length} IOCs`);
            } else {
                throw new Error('Invalid ThreatFox response format');
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('ThreatFox API timeout');
            }
            throw error;
        }
    },

    loadCustomRules() {
        try {
            const stored = localStorage.getItem('c2detector_custom_rules');
            if (stored) {
                this.customRules = JSON.parse(stored);
                this.stats.customRules = this.customRules.length;
                console.log(`✓ Loaded ${this.customRules.length} custom rules`);
            }
        } catch (error) {
            console.error('Failed to load custom rules:', error);
            this.customRules = [];
        }
    },

    saveCustomRules() {
        try {
            localStorage.setItem('c2detector_custom_rules', JSON.stringify(this.customRules));
        } catch (error) {
            console.error('Failed to save custom rules:', error);
        }
    },

    async lookupIP(ip) {
        console.log(`Looking up IP: ${ip}`);
        const results = [];

        // Check custom rules first (always works offline)
        const customMatch = this.checkCustomRules(ip);
        if (customMatch) {
            results.push(customMatch);
        }

        // Check ThreatFox only if online
        if (this.config.enabledSources.threatfox && this.stats.status === 'online') {
            try {
                const threatfoxMatch = await this.lookupThreatFox(ip);
                if (threatfoxMatch) {
                    results.push(threatfoxMatch);
                }
            } catch (error) {
                console.warn(`ThreatFox lookup failed for ${ip}:`, error);
                // Don't fail the entire lookup if ThreatFox is down
            }
        }

        return results;
    },

    async lookupThreatFox(ip) {
        // Check cache first
        const cacheKey = `threatfox_${ip}`;
        const cached = this.cache.get(cacheKey);
        if (cached && (Date.now() - cached.timestamp < this.config.cacheExpiry)) {
            return cached.data;
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

            const response = await fetch(this.config.threatfoxAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: 'search_ioc',
                    search_term: ip
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`API returned ${response.status}`);
            }

            const data = await response.json();

            if (data.query_status === 'ok' && data.data && data.data.length > 0) {
                const ioc = data.data[0];
                const result = {
                    source: 'ThreatFox',
                    ip: ip,
                    malware: ioc.malware_printable || 'Unknown',
                    confidence: ioc.confidence_level || 50,
                    threat_type: ioc.threat_type || 'unknown',
                    tags: ioc.tags || [],
                    first_seen: ioc.first_seen,
                    reference: ioc.reference || null
                };

                // Cache the result
                this.cache.set(cacheKey, {
                    data: result,
                    timestamp: Date.now()
                });

                return result;
            }

            // Cache negative result to avoid repeated lookups
            this.cache.set(cacheKey, {
                data: null,
                timestamp: Date.now()
            });

            return null;
        } catch (error) {
            if (error.name === 'AbortError') {
                console.warn(`ThreatFox lookup timeout for ${ip}`);
            } else {
                console.warn(`ThreatFox lookup error for ${ip}:`, error);
            }
            return null;
        }
    },

    checkCustomRules(ip) {
        for (const rule of this.customRules) {
            if (rule.type === 'ip' && rule.value === ip) {
                return {
                    source: 'Custom Rules',
                    ip: ip,
                    malware: rule.malware || 'Custom Detection',
                    confidence: rule.confidence || 70,
                    threat_type: rule.threat_type || 'custom',
                    tags: rule.tags || [],
                    description: rule.description
                };
            } else if (rule.type === 'cidr' && this.matchCIDR(ip, rule.value)) {
                return {
                    source: 'Custom Rules',
                    ip: ip,
                    malware: rule.malware || 'Custom Detection',
                    confidence: rule.confidence || 70,
                    threat_type: rule.threat_type || 'custom',
                    tags: rule.tags || [],
                    description: rule.description,
                    cidr: rule.value
                };
            }
        }
        return null;
    },

    matchCIDR(ip, cidr) {
        const [range, bits] = cidr.split('/');
        const mask = -1 << (32 - parseInt(bits));
        
        const ip2long = (ip) => {
            return ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct), 0) >>> 0;
        };
        
        return (ip2long(ip) & mask) === (ip2long(range) & mask);
    },

    addCustomRule(rule) {
        // Validate rule
        if (!rule.type || !rule.value) {
            throw new Error('Rule must have type and value');
        }

        // Add default values
        rule.id = Date.now().toString();
        rule.created = new Date().toISOString();
        rule.confidence = rule.confidence || 70;
        rule.tags = rule.tags || [];

        this.customRules.push(rule);
        this.saveCustomRules();
        this.stats.customRules = this.customRules.length;
        
        console.log('Added custom rule:', rule);
        return rule;
    },

    removeCustomRule(ruleId) {
        const index = this.customRules.findIndex(r => r.id === ruleId);
        if (index !== -1) {
            this.customRules.splice(index, 1);
            this.saveCustomRules();
            this.stats.customRules = this.customRules.length;
            return true;
        }
        return false;
    },

    exportRules() {
        return JSON.stringify(this.customRules, null, 2);
    },

    importRules(jsonString) {
        try {
            const rules = JSON.parse(jsonString);
            if (Array.isArray(rules)) {
                this.customRules = rules;
                this.saveCustomRules();
                this.stats.customRules = this.customRules.length;
                return true;
            }
            throw new Error('Invalid rules format');
        } catch (error) {
            console.error('Failed to import rules:', error);
            return false;
        }
    },

    getStats() {
        return {
            ...this.stats,
            sources: {
                threatfox: {
                    enabled: this.config.enabledSources.threatfox,
                    status: this.stats.status === 'online' ? 'active' : 'offline',
                    iocs: this.stats.threatfoxIOCs
                },
                customRules: {
                    enabled: this.config.enabledSources.customRules,
                    status: 'active',
                    count: this.stats.customRules
                }
            }
        };
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThreatIntel;
}

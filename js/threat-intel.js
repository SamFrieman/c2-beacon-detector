// threat-intel.js - Multi-Source Threat Intelligence
// Version 2.1.1 - Enhanced error handling and CORS support

const ThreatIntel = {
    config: {
        // Use CORS proxy for browser compatibility
        threatfoxAPI: 'https://api.allorigins.win/raw?url=https://threatfox-api.abuse.ch/api/v1/',
        cacheExpiry: 3600000, // 1 hour
        maxIPs: 20,
        enabledSources: {
            threatfox: true,
            customRules: true
        },
        timeout: 10000,
        retryAttempts: 2,
        // Fallback to direct API if proxy fails
        directAPI: 'https://threatfox-api.abuse.ch/api/v1/'
    },

    cache: new Map(),
    customRules: [],
    stats: {
        threatfoxIOCs: 0,
        customRules: 0,
        lastUpdate: null,
        status: 'initializing',
        error: null,
        lookupCount: 0,
        cacheHits: 0
    },

    async initialize() {
        console.log('Initializing Threat Intelligence...');
        
        // Load custom rules
        this.loadCustomRules();
        
        // Try to initialize ThreatFox
        if (this.config.enabledSources.threatfox) {
            try {
                await this.testThreatFoxConnection();
            } catch (error) {
                console.warn('ThreatFox unavailable:', error.message);
                this.stats.status = 'offline';
                this.stats.error = 'ThreatFox API unavailable (CORS or network issue)';
            }
        }

        this.stats.lastUpdate = new Date().toISOString();
        console.log('✓ Threat Intel initialized');
        console.log(`  - ThreatFox: ${this.stats.status}`);
        console.log(`  - Custom Rules: ${this.stats.customRules}`);
        
        return this.getStats();
    },

    async testThreatFoxConnection() {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

        try {
            // Try with CORS proxy first
            const response = await fetch(this.config.threatfoxAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: 'get_iocs', days: 1 }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            
            if (data.query_status === 'ok') {
                this.stats.threatfoxIOCs = data.data ? data.data.length : 0;
                this.stats.status = 'online';
                console.log(`✓ ThreatFox connected: ${this.stats.threatfoxIOCs} IOCs`);
                return true;
            }

            throw new Error('Invalid response format');

        } catch (error) {
            clearTimeout(timeoutId);
            
            // Try direct API as fallback
            try {
                console.log('Trying direct ThreatFox API...');
                return await this.testDirectAPI();
            } catch (fallbackError) {
                throw new Error('Both proxy and direct API failed');
            }
        }
    },

    async testDirectAPI() {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

        try {
            const response = await fetch(this.config.directAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: 'get_iocs', days: 1 }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                const data = await response.json();
                if (data.query_status === 'ok') {
                    this.stats.threatfoxIOCs = data.data ? data.data.length : 0;
                    this.stats.status = 'online';
                    // Use direct API from now on
                    this.config.threatfoxAPI = this.config.directAPI;
                    return true;
                }
            }

            throw new Error('Direct API failed');
        } catch (error) {
            clearTimeout(timeoutId);
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
        this.stats.lookupCount++;
        
        const results = [];

        // Check custom rules first (always works)
        const customMatch = this.checkCustomRules(ip);
        if (customMatch) {
            results.push(customMatch);
        }

        // Check ThreatFox if online
        if (this.config.enabledSources.threatfox && this.stats.status === 'online') {
            try {
                const threatfoxMatch = await this.lookupThreatFox(ip);
                if (threatfoxMatch) {
                    results.push(threatfoxMatch);
                }
            } catch (error) {
                console.warn(`ThreatFox lookup failed for ${ip}:`, error.message);
            }
        }

        return results;
    },

    async lookupThreatFox(ip) {
        // Check cache first
        const cacheKey = `threatfox_${ip}`;
        const cached = this.cache.get(cacheKey);
        
        if (cached && (Date.now() - cached.timestamp < this.config.cacheExpiry)) {
            this.stats.cacheHits++;
            console.log(`  Cache hit for ${ip}`);
            return cached.data;
        }

        // Query API
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
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();

            if (data.query_status === 'ok' && data.data && data.data.length > 0) {
                const ioc = data.data[0];
                const result = {
                    source: 'ThreatFox',
                    ip: ip,
                    malware: ioc.malware_printable || 'Unknown',
                    confidence: this.mapConfidence(ioc.confidence_level),
                    threat_type: ioc.threat_type || 'c2',
                    tags: ioc.tags || [],
                    first_seen: ioc.first_seen,
                    last_seen: ioc.last_seen,
                    reference: ioc.reference || null
                };

                // Cache result
                this.cache.set(cacheKey, {
                    data: result,
                    timestamp: Date.now()
                });

                return result;
            }

            // Cache negative result
            this.cache.set(cacheKey, {
                data: null,
                timestamp: Date.now()
            });

            return null;

        } catch (error) {
            console.warn(`ThreatFox API error for ${ip}:`, error.message);
            return null;
        }
    },

    mapConfidence(level) {
        // Map ThreatFox confidence to numeric value
        const mapping = {
            'high': 90,
            'medium': 70,
            'low': 50
        };
        return mapping[level] || 60;
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
                    description: rule.description,
                    rule_id: rule.id
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
                    cidr: rule.value,
                    rule_id: rule.id
                };
            }
        }
        return null;
    },

    matchCIDR(ip, cidr) {
        try {
            const [range, bits] = cidr.split('/');
            const mask = -1 << (32 - parseInt(bits));
            
            const ip2long = (ip) => {
                return ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct), 0) >>> 0;
            };
            
            return (ip2long(ip) & mask) === (ip2long(range) & mask);
        } catch (error) {
            console.error('CIDR match error:', error);
            return false;
        }
    },

    addCustomRule(rule) {
        if (!rule.type || !rule.value) {
            throw new Error('Rule must have type and value');
        }

        // Validate IP or CIDR
        if (rule.type === 'ip' && !this.isValidIP(rule.value)) {
            throw new Error('Invalid IP address');
        }

        if (rule.type === 'cidr' && !this.isValidCIDR(rule.value)) {
            throw new Error('Invalid CIDR notation');
        }

        rule.id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
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

    isValidIP(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        return parts.every(part => {
            const num = parseInt(part);
            return num >= 0 && num <= 255;
        });
    },

    isValidCIDR(cidr) {
        const [ip, bits] = cidr.split('/');
        if (!this.isValidIP(ip)) return false;
        const bitsNum = parseInt(bits);
        return bitsNum >= 0 && bitsNum <= 32;
    },

    exportRules() {
        return JSON.stringify({
            version: '2.1',
            exported: new Date().toISOString(),
            rules: this.customRules
        }, null, 2);
    },

    importRules(jsonString) {
        try {
            const data = JSON.parse(jsonString);
            const rules = data.rules || data;
            
            if (!Array.isArray(rules)) {
                throw new Error('Invalid rules format');
            }

            // Validate each rule
            rules.forEach(rule => {
                if (!rule.type || !rule.value) {
                    throw new Error('Invalid rule structure');
                }
            });

            this.customRules = rules;
            this.saveCustomRules();
            this.stats.customRules = this.customRules.length;
            
            console.log(`Imported ${rules.length} rules`);
            return true;
        } catch (error) {
            console.error('Import failed:', error);
            throw error;
        }
    },

    getCustomRules() {
        return [...this.customRules];
    },

    clearCache() {
        this.cache.clear();
        console.log('Cache cleared');
    },

    getStats() {
        return {
            ...this.stats,
            cacheSize: this.cache.size,
            sources: {
                threatfox: {
                    enabled: this.config.enabledSources.threatfox,
                    status: this.stats.status === 'online' ? 'active' : 'offline',
                    iocs: this.stats.threatfoxIOCs,
                    error: this.stats.error
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

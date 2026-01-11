// Threat Intelligence Module v2.1 - Multi-Source Integration
const ThreatIntel = {
    cache: {
        threatfox: null,
        alienvault: null,
        localRules: null,
        lastUpdate: null,
        status: 'inactive'
    },

    config: { 
        threatfoxAPI: 'https://threatfox-api.abuse.ch/api/v1/',
        alienvaultAPI: 'https://otx.alienvault.com/api/v1/indicators',
        cacheExpiry: 3600000, // 1 hour
        maxIPs: 20,
        enabledSources: {
            threatfox: true,
            alienvault: true,
            customRules: true
        }
    },

    // Custom detection rules storage
    customRules: [],

   async initialize() {
        try {
            // Add timeout wrapper
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Initialization timeout')), 5000)
            );
            
            const initPromise = this.updateThreatFox();
            
            await Promise.race([initPromise, timeoutPromise])
                .catch(err => {
                    console.warn('ThreatFox unavailable, continuing without:', err);
                });
            
            this.loadCustomRules();
            this.cache.status = 'active';
            return true;
        } catch (err) {
            console.warn('Partial initialization:', err);
            this.cache.status = 'partial';
            return true; // Continue anyway
        }
    },

    async updateThreatFox() {
        try {
            const response = await fetch(this.config.threatfoxAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: 'get_iocs', days: 7 })
            });

            if (!response.ok) throw new Error(`ThreatFox API returned ${response.status}`);

            const data = await response.json();
            
            if (data.query_status === 'ok' && data.data) {
                this.cache.threatfox = data.data;
                this.cache.lastUpdate = Date.now();
                console.log(`✓ ThreatFox: Loaded ${data.data.length} IOCs`);
            }

            return true;
        } catch (err) {
            console.error('ThreatFox update failed:', err);
            return false;
        }
    },

    async lookupIPMultiSource(ip) {
        if (Utils.isPrivateIP(ip)) return null;

        const results = {
            ip: ip,
            sources: [],
            highestConfidence: 0,
            combinedThreatScore: 0
        };

        // ThreatFox lookup
        if (this.config.enabledSources.threatfox) {
            const tfResult = await this.lookupThreatFox(ip);
            if (tfResult) {
                results.sources.push({ source: 'ThreatFox', ...tfResult });
                results.highestConfidence = Math.max(results.highestConfidence, tfResult.confidence_level || 0);
            }
        }

        // Custom rules check
        if (this.config.enabledSources.customRules) {
            const customResult = this.checkCustomRules(ip);
            if (customResult) {
                results.sources.push({ source: 'Custom Rules', ...customResult });
                results.highestConfidence = Math.max(results.highestConfidence, customResult.confidence_level || 0);
            }
        }

        // Calculate combined threat score
        if (results.sources.length > 0) {
            results.combinedThreatScore = this.calculateCombinedScore(results.sources);
            return results;
        }

        return null;
    },

    async lookupThreatFox(ip) {
        try {
            const response = await fetch(this.config.threatfoxAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: 'search_ioc',
                    search_term: ip
                })
            });

            if (!response.ok) return null;
            const data = await response.json();
            
            if (data.query_status === 'ok' && data.data && data.data.length > 0) {
                return this.processIOCData(data.data[0], ip);
            }

            return null;
        } catch (err) {
            console.error('ThreatFox lookup failed:', err);
            return null;
        }
    },

    processIOCData(ioc, ip) {
        return {
            ip: ip,
            ioc_type: ioc.ioc_type,
            threat_type: ioc.threat_type,
            malware: ioc.malware || 'Unknown',
            malware_alias: ioc.malware_alias || null,
            confidence_level: ioc.confidence_level || 50,
            first_seen: ioc.first_seen,
            last_seen: ioc.last_seen || ioc.first_seen,
            tags: ioc.tags || [],
            reference: ioc.reference || null,
            reporter: ioc.reporter || 'abuse.ch'
        };
    },

    checkCustomRules(ip) {
        for (const rule of this.customRules) {
            if (rule.type === 'ip' && rule.value === ip) {
                return {
                    ip: ip,
                    threat_type: rule.threat_type || 'custom',
                    malware: rule.malware || 'Custom Detection',
                    confidence_level: rule.confidence || 75,
                    first_seen: rule.created || new Date().toISOString(),
                    tags: rule.tags || ['custom'],
                    description: rule.description || 'Custom rule match'
                };
            }
            
            // CIDR range matching
            if (rule.type === 'cidr' && this.ipInCIDR(ip, rule.value)) {
                return {
                    ip: ip,
                    threat_type: rule.threat_type || 'custom',
                    malware: rule.malware || 'Custom Detection',
                    confidence_level: rule.confidence || 70,
                    first_seen: rule.created || new Date().toISOString(),
                    tags: rule.tags || ['custom', 'cidr'],
                    description: rule.description || `Matched CIDR range ${rule.value}`
                };
            }
        }
        return null;
    },

    ipInCIDR(ip, cidr) {
        const [range, bits] = cidr.split('/');
        const mask = ~(2 ** (32 - parseInt(bits)) - 1);
        
        const ipNum = this.ipToNumber(ip);
        const rangeNum = this.ipToNumber(range);
        
        return (ipNum & mask) === (rangeNum & mask);
    },

    ipToNumber(ip) {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    },

    calculateCombinedScore(sources) {
        if (sources.length === 0) return 0;
        
        // Weight by source reliability
        const weights = {
            'ThreatFox': 1.0,
            'AlienVault OTX': 0.9,
            'Custom Rules': 0.85
        };

        let totalScore = 0;
        let totalWeight = 0;

        sources.forEach(src => {
            const weight = weights[src.source] || 0.5;
            const confidence = src.confidence_level || 50;
            totalScore += confidence * weight;
            totalWeight += weight;
        });

        // Bonus for multiple source agreement
        if (sources.length > 1) {
            totalScore *= 1.2;
        }

        return Math.min(100, Math.round(totalScore / totalWeight));
    },

    async checkConnections(connections) {
        const ips = Utils.extractUniqueIPs(connections);
        const publicDestIPs = ips.destIPs.filter(ip => !Utils.isPrivateIP(ip));
        const ipsToCheck = publicDestIPs.slice(0, this.config.maxIPs);
        
        const matches = [];
        
        for (const ip of ipsToCheck) {
            const result = await this.lookupIPMultiSource(ip);
            if (result && result.sources.length > 0) {
                const connCount = connections.filter(c => Utils.getDestIP(c) === ip).length;
                result.connection_count = connCount;
                matches.push(result);
            }
            
            await new Promise(resolve => setTimeout(resolve, 500));
        }

        return matches;
    },

    // Custom Rules Management
    addCustomRule(rule) {
        const newRule = {
            id: Date.now(),
            created: new Date().toISOString(),
            enabled: true,
            ...rule
        };
        
        this.customRules.push(newRule);
        this.saveCustomRules();
        return newRule;
    },

    removeCustomRule(ruleId) {
        this.customRules = this.customRules.filter(r => r.id !== ruleId);
        this.saveCustomRules();
    },

    updateCustomRule(ruleId, updates) {
        const rule = this.customRules.find(r => r.id === ruleId);
        if (rule) {
            Object.assign(rule, updates);
            this.saveCustomRules();
        }
    },

    loadCustomRules() {
        try {
            const saved = localStorage.getItem('c2detector_custom_rules');
            if (saved) {
                this.customRules = JSON.parse(saved);
                console.log(`✓ Loaded ${this.customRules.length} custom rules`);
            }
        } catch (err) {
            console.warn('Failed to load custom rules:', err);
        }
    },

    saveCustomRules() {
        try {
            localStorage.setItem('c2detector_custom_rules', JSON.stringify(this.customRules));
        } catch (err) {
            console.error('Failed to save custom rules:', err);
        }
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
                return true;
            }
        } catch (err) {
            console.error('Failed to import rules:', err);
        }
        return false;
    },

    getStatus() {
        return {
            active: this.cache.status === 'active',
            iocCount: this.cache.threatfox ? this.cache.threatfox.length : 0,
            customRuleCount: this.customRules.length,
            lastUpdate: this.cache.lastUpdate,
            sources: Object.entries(this.config.enabledSources)
                .filter(([_, enabled]) => enabled)
                .map(([source]) => source)
        };
    },

    getMalwareFamilyInfo(malware) {
        const families = {
            'cobalt strike': {
                framework: 'Cobalt Strike',
                description: 'Commercial adversary simulation toolkit',
                typical_interval: '60s',
                typical_ports: [80, 443, 8080]
            },
            'meterpreter': {
                framework: 'Metasploit Framework',
                description: 'Post-exploitation payload',
                typical_interval: '60-120s',
                typical_ports: [443, 4444]
            },
            'empire': {
                framework: 'PowerShell Empire',
                description: 'Post-exploitation framework',
                typical_interval: '5-30s',
                typical_ports: [80, 443]
            },
            'sliver': {
                framework: 'Sliver',
                description: 'Open-source C2 framework',
                typical_interval: '60s',
                typical_ports: [443, 8443]
            },
            'covenant': {
                framework: 'Covenant',
                description: '.NET C2 framework',
                typical_interval: '60s',
                typical_ports: [80, 443, 7443]
            }
        };

        const key = malware.toLowerCase();
        for (const [family, info] of Object.entries(families)) {
            if (key.includes(family)) {
                return info;
            }
        }

        return null;
    }
};

// Threat Intelligence Module
const ThreatIntel = {
    cache: {
        threatfox: null,
        lastUpdate: null,
        status: 'inactive'
    },

    config: {
        threatfoxAPI: 'https://threatfox-api.abuse.ch/api/v1/',
        cacheExpiry: 3600000, // 1 hour
        maxIPs: 20 // Limit API calls
    },

    async initialize() {
        try {
            // Load recent IOCs on initialization
            await this.updateThreatFeed();
            this.cache.status = 'active';
            return true;
        } catch (err) {
            console.warn('Failed to initialize threat intel:', err);
            this.cache.status = 'inactive';
            return false;
        }
    },

    async updateThreatFeed() {
        try {
            // Get recent IOCs from ThreatFox
            const response = await fetch(this.config.threatfoxAPI, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: 'get_iocs', days: 7 })
            });

            if (!response.ok) {
                throw new Error(`ThreatFox API returned ${response.status}`);
            }

            const data = await response.json();
            
            if (data.query_status === 'ok' && data.data) {
                this.cache.threatfox = data.data;
                this.cache.lastUpdate = Date.now();
                console.log(`Loaded ${data.data.length} IOCs from ThreatFox`);
            }

            return true;
        } catch (err) {
            console.error('ThreatFox update failed:', err);
            return false;
        }
    },

    async lookupIP(ip) {
        // Don't lookup private IPs
        if (Utils.isPrivateIP(ip)) {
            return null;
        }

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
                return this.processIOCData(data.data, ip);
            }

            return null;
        } catch (err) {
            console.error('ThreatFox lookup failed:', err);
            return null;
        }
    },

    processIOCData(iocs, ip) {
        // Take the most recent/relevant IOC
        const ioc = iocs[0];
        
        return {
            ip: ip,
            ioc_type: ioc.ioc_type,
            threat_type: ioc.threat_type,
            malware: ioc.malware || 'Unknown',
            malware_alias: ioc.malware_alias || null,
            confidence_level: ioc.confidence_level || 0,
            first_seen: ioc.first_seen,
            last_seen: ioc.last_seen || ioc.first_seen,
            tags: ioc.tags || [],
            reference: ioc.reference || null,
            reporter: ioc.reporter || 'abuse.ch'
        };
    },

    async checkConnections(connections) {
        const ips = Utils.extractUniqueIPs(connections);
        const publicDestIPs = ips.destIPs.filter(ip => !Utils.isPrivateIP(ip));
        
        // Limit number of lookups
        const ipsToCheck = publicDestIPs.slice(0, this.config.maxIPs);
        
        const matches = [];
        
        for (const ip of ipsToCheck) {
            const result = await this.lookupIP(ip);
            if (result) {
                // Count how many connections to this IP
                const connCount = connections.filter(c => 
                    Utils.getDestIP(c) === ip
                ).length;
                
                result.connection_count = connCount;
                matches.push(result);
            }
            
            // Small delay to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, 500));
        }

        return matches;
    },

    checkCachedIOCs(ip) {
        if (!this.cache.threatfox) return null;

        const match = this.cache.threatfox.find(ioc => 
            ioc.ioc === ip || ioc.ioc_value === ip
        );

        if (match) {
            return this.processIOCData([match], ip);
        }

        return null;
    },

    getStatus() {
        return {
            active: this.cache.status === 'active',
            iocCount: this.cache.threatfox ? this.cache.threatfox.length : 0,
            lastUpdate: this.cache.lastUpdate,
            source: 'ThreatFox by Abuse.ch'
        };
    },

    getMalwareFamilyInfo(malware) {
        // Map malware families to common C2 frameworks
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

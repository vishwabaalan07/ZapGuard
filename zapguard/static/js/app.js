/**
 * ZapGuard Web Application - Frontend JavaScript
 */

class ZapGuardApp {
    constructor() {
        this.sessionId = null;
        this.reportPath = null;
        this.results = [];
        this.filteredResults = [];
        this.sortColumn = null;
        this.sortAsc = true;
        this.pollingInterval = null;
        this.isDarkTheme = true;
        this.nmapAvailable = false;
        this.nmapResults = null;
        this.nmapAlertShown = false;

        this.initElements();
        this.initEventListeners();
        this.checkNmapStatus();
        this.log('ZapGuard Web ready.');
    }

    initElements() {
        // Config inputs
        this.schemeSelect = document.getElementById('schemeSelect');
        this.urlInput = document.getElementById('urlInput');
        this.urlStatus = document.getElementById('urlStatus');
        this.reportPathInput = document.getElementById('reportPath');
        this.reportFile = document.getElementById('reportFile');
        this.browseBtn = document.getElementById('browseBtn');

        // Action buttons
        this.startBtn = document.getElementById('startBtn');
        this.stopBtn = document.getElementById('stopBtn');
        this.clearBtn = document.getElementById('clearBtn');
        this.exportHtmlBtn = document.getElementById('exportHtmlBtn');
        this.exportPdfBtn = document.getElementById('exportPdfBtn');
        this.exportCsvBtn = document.getElementById('exportCsvBtn');
        this.exportNmapBtn = document.getElementById('exportNmapBtn');

        // Nmap
        this.nmapCheckbox = document.getElementById('nmapCheckbox');
        this.nmapOnlyCheckbox = document.getElementById('nmapOnlyCheckbox');
        this.nmapStatus = document.getElementById('nmapStatus');
        this.nmapScanPanel = document.getElementById('nmapScanPanel');
        this.nmapScanGrid = document.getElementById('nmapScanGrid');
        this.selectedScansCount = document.getElementById('selectedScansCount');
        this.nmapProgressSection = document.getElementById('nmapProgressSection');
        this.nmapProgressBar = document.getElementById('nmapProgressBar');
        this.nmapProgressStatus = document.getElementById('nmapProgressStatus');
        this.nmapProgressDetail = document.getElementById('nmapProgressDetail');
        this.nmapProfiles = [];
        this.nmapScanning = false;

        // Progress
        this.progressBar = document.getElementById('progressBar');
        this.progressText = document.getElementById('progressText');
        this.progressDetail = document.getElementById('progressDetail');

        // Status
        this.statusDot = document.getElementById('statusDot');
        this.statusText = document.getElementById('statusText');

        // Stats
        this.statTotal = document.getElementById('statTotal');
        this.statPassed = document.getElementById('statPassed');
        this.statFailed = document.getElementById('statFailed');
        this.statSkipped = document.getElementById('statSkipped');
        this.statErrors = document.getElementById('statErrors');
        this.statRate = document.getElementById('statRate');

        // Results
        this.resultsTable = document.getElementById('resultsTable');
        this.resultsBody = document.getElementById('resultsBody');
        this.statusFilter = document.getElementById('statusFilter');
        this.riskFilter = document.getElementById('riskFilter');
        this.searchInput = document.getElementById('searchInput');
        this.resultsCount = document.getElementById('resultsCount');

        // Details panel
        this.detailStatus = document.getElementById('detailStatus');
        this.detailRisk = document.getElementById('detailRisk');
        this.detailMethod = document.getElementById('detailMethod');
        this.detailPluginId = document.getElementById('detailPluginId');
        this.detailVulnName = document.getElementById('detailVulnName');
        this.detailEndpoint = document.getElementById('detailEndpoint');
        this.detailEvidence = document.getElementById('detailEvidence');

        // Theme
        this.themeToggle = document.getElementById('themeToggle');

        // Log
        this.logContainer = document.getElementById('logContainer');
    }

    initEventListeners() {
        // URL validation
        this.urlInput.addEventListener('input', () => this.validateUrl());
        this.schemeSelect.addEventListener('change', () => this.validateUrl());

        // File upload
        this.browseBtn.addEventListener('click', () => this.reportFile.click());
        this.reportFile.addEventListener('change', (e) => this.handleFileUpload(e));

        // Actions
        this.startBtn.addEventListener('click', () => this.startValidation());
        this.stopBtn.addEventListener('click', () => this.stopValidation());
        this.clearBtn.addEventListener('click', () => this.clearResults());

        // Exports
        this.exportHtmlBtn.addEventListener('click', () => this.exportReport('html'));
        this.exportPdfBtn.addEventListener('click', () => this.exportReport('pdf'));
        this.exportCsvBtn.addEventListener('click', () => this.exportReport('csv'));
        this.exportNmapBtn.addEventListener('click', () => this.exportNmapReport());

        // Filters
        this.statusFilter.addEventListener('change', () => this.applyFilters());
        this.riskFilter.addEventListener('change', () => this.applyFilters());
        this.searchInput.addEventListener('input', () => this.applyFilters());

        // Table sorting
        this.resultsTable.querySelectorAll('th[data-sort]').forEach(th => {
            th.addEventListener('click', () => this.sortResults(th.dataset.sort));
            th.style.cursor = 'pointer';
        });

        // Theme toggle
        this.themeToggle.addEventListener('click', () => this.toggleTheme());

        // Nmap controls
        if (this.nmapCheckbox) {
            this.nmapCheckbox.addEventListener('change', () => this.handleNmapCheckboxChange());
        }
        if (this.nmapOnlyCheckbox) {
            this.nmapOnlyCheckbox.addEventListener('change', () => this.handleNmapOnlyChange());
        }
        if (this.nmapScanSelect) {
            this.nmapScanSelect.addEventListener('change', () => this.updateSelectedScansCount());
        }
    }

    validateUrl() {
        const scheme = this.schemeSelect.value;
        const host = this.urlInput.value.trim();
        const fullUrl = scheme + host;

        if (!host) {
            this.urlStatus.textContent = '';
            this.urlStatus.className = 'url-status';
            return;
        }

        fetch('/api/validate-url', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: fullUrl})
        })
        .then(res => res.json())
        .then(data => {
            if (data.valid) {
                this.urlStatus.textContent = '✓';
                this.urlStatus.className = 'url-status valid';
            } else {
                this.urlStatus.textContent = '✗';
                this.urlStatus.className = 'url-status invalid';
            }
        })
        .catch(() => {
            this.urlStatus.textContent = '?';
            this.urlStatus.className = 'url-status';
        });
    }

    async handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        this.log(`Uploading report: ${file.name}...`);
        this.reportPathInput.value = 'Uploading...';

        try {
            const response = await fetch('/api/upload-report', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            if (data.error) {
                this.reportPathInput.value = '';
                this.reportPath = null;
                this.showError(data.error);
                return;
            }

            this.reportPath = data.filepath;
            this.reportPathInput.value = `${file.name} (${data.alert_count} alerts, ${data.instance_count} instances)`;
            this.log(`Loaded: ${data.alert_count} alerts, ${data.instance_count} instances`);
        } catch (err) {
            this.reportPathInput.value = '';
            this.reportPath = null;
            this.showError('Failed to upload report: ' + err.message);
        }
    }

    async startValidation() {
        const scheme = this.schemeSelect.value;
        const host = this.urlInput.value.trim();
        const fullUrl = scheme + host;

        if (!host) {
            this.showError('Please enter a target URL');
            return;
        }

        const nmapEnabled = this.nmapCheckbox && this.nmapCheckbox.checked;
        const nmapOnly = this.nmapOnlyCheckbox && this.nmapOnlyCheckbox.checked;

        // ZAP report required unless Nmap-only mode
        if (!this.reportPath && !nmapOnly) {
            this.showError('Please upload a ZAP report first');
            return;
        }

        this.log('Checking device connection...');
        this.setStatus('running', 'Connecting...');
        this.startBtn.disabled = true;
        this.stopBtn.disabled = false;
        this.clearBtn.disabled = true;

        const nmapScanTypes = this.getSelectedNmapScanTypes();
        if (nmapEnabled) {
            // Get human-readable scan names
            const scanNames = nmapScanTypes.map(id => {
                const profile = this.nmapProfiles.find(p => p.id === id);
                return profile ? profile.name : id;
            }).join(', ');

            if (nmapOnly) {
                this.log(`Nmap-only mode - Selected: ${scanNames}`);
            } else {
                this.log(`Nmap scan enabled - Selected: ${scanNames}`);
            }

            // Reset Nmap progress UI
            this.nmapScanning = false;
            this.showNmapProgress(false);
            if (this.nmapProgressBar) {
                this.nmapProgressBar.classList.remove('indeterminate');
                this.nmapProgressBar.style.width = '0%';
            }
            if (this.nmapProgressStatus) {
                this.nmapProgressStatus.classList.remove('completed');
            }
        }

        try {
            const response = await fetch('/api/start-validation', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    url: fullUrl,
                    report_path: this.reportPath || '',
                    nmap_enabled: nmapEnabled,
                    nmap_scan_types: nmapScanTypes,
                    nmap_only: nmapOnly
                })
            });
            const data = await response.json();

            if (data.error) {
                // Check if it's a connection error
                if (data.connection_error) {
                    this.setStatus('error', 'Connection Failed');
                    this.log(`ERROR: ${data.error}`);
                    this.showConnectionError(data.error, data.details);
                } else {
                    this.setStatus('error', 'Error');
                    this.showError(data.error);
                }
                this.startBtn.disabled = false;
                this.stopBtn.disabled = true;
                this.clearBtn.disabled = false;
                return;
            }

            this.log('Device is reachable. Starting validation...');
            this.setStatus('running', 'Validating...');

            this.sessionId = data.session_id;
            this.startPolling();
        } catch (err) {
            this.setStatus('error', 'Error');
            this.showError('Failed to start validation: ' + err.message);
            this.startBtn.disabled = false;
            this.stopBtn.disabled = true;
            this.clearBtn.disabled = false;
        }
    }

    async stopValidation() {
        if (!this.sessionId) return;

        this.log('Stopping validation...');
        this.stopBtn.disabled = true;

        try {
            await fetch('/api/stop-validation', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: this.sessionId})
            });
        } catch (err) {
            console.error('Stop error:', err);
        }
    }

    startPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }

        this.pollingInterval = setInterval(() => this.pollStatus(), 500);
    }

    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }
    }

    async pollStatus() {
        if (!this.sessionId) return;

        try {
            const response = await fetch(`/api/status/${this.sessionId}`);
            const data = await response.json();

            if (data.error) {
                console.error('Status error:', data.error);
                return;
            }

            // Update progress
            const percent = data.total > 0 ? Math.round((data.progress / data.total) * 100) : 0;
            this.progressBar.style.width = `${percent}%`;
            this.progressText.textContent = `${percent}%`;
            this.progressDetail.textContent = data.current_endpoint || '';

            // Update stats
            const stats = data.stats;
            this.statTotal.textContent = stats.total;
            this.statPassed.textContent = stats.passed;
            this.statFailed.textContent = stats.failed;
            this.statSkipped.textContent = stats.not_testable;
            this.statErrors.textContent = stats.errors;
            this.statRate.textContent = `${stats.pass_rate}%`;

            // Update results
            this.results = data.results;
            this.applyFilters();

            // Update logs
            this.updateLogs(data.logs);

            // Handle Nmap progress via logs
            if (data.logs) {
                // Detect Nmap scan starting
                if (data.logs.some(log => log.includes('NMAP SCAN INITIATED')) && !this.nmapScanning) {
                    this.nmapScanning = true;
                    this.nmapAlertShown = true;
                    this.setStatus('running', 'Nmap Scanning...');
                    this.showNmapProgress(true);
                    this.updateNmapProgress('Initializing scan...', 'Preparing Nmap scanner');
                }

                // Update Nmap progress based on log messages
                if (this.nmapScanning) {
                    const lastLogs = data.logs.slice(-5);
                    for (const log of lastLogs) {
                        if (log.includes('Running port scan')) {
                            this.updateNmapProgress('Scanning ports...', 'Detecting open ports and services');
                        } else if (log.includes('Running SSL scan')) {
                            this.updateNmapProgress('SSL/TLS Analysis...', 'Checking for vulnerabilities');
                        } else if (log.includes('Found') && log.includes('open ports')) {
                            const match = log.match(/Found (\d+) open ports/);
                            if (match) {
                                this.updateNmapProgress('Port scan complete', `${match[1]} open ports found`);
                            }
                        } else if (log.includes('Starting') && log.includes('Scan')) {
                            const scanName = log.match(/Starting (.+?)\.\.\./)?.[1] || 'scan';
                            this.updateNmapProgress(`Running ${scanName}...`, 'This may take a few minutes');
                        }
                    }
                }
            }

            // Store Nmap results if available
            if (data.nmap_results && !this.nmapResults) {
                this.nmapResults = data.nmap_results;
                this.completeNmapProgress();
                this.log(`Nmap scan complete: ${data.nmap_results.ports.length} ports, ${data.nmap_results.ssl_findings.length} SSL findings`);
            }

            // Check if completed
            if (data.status === 'completed' || data.status === 'stopped') {
                this.nmapScanning = false;
                this.nmapAlertShown = false;
                this.stopPolling();
                this.setStatus(data.status === 'completed' ? 'success' : 'stopped',
                              data.status === 'completed' ? 'Completed' : 'Stopped');
                this.startBtn.disabled = false;
                this.stopBtn.disabled = true;
                this.clearBtn.disabled = false;
                this.enableExports();

                // Enable Nmap export if results available
                if (this.nmapResults && this.exportNmapBtn) {
                    this.exportNmapBtn.disabled = false;
                }
            }
        } catch (err) {
            console.error('Polling error:', err);
        }
    }

    applyFilters() {
        const statusFilter = this.statusFilter.value;
        const riskFilter = this.riskFilter.value;
        const search = this.searchInput.value.toLowerCase();

        this.filteredResults = this.results.filter(r => {
            if (statusFilter && r.status !== statusFilter) return false;
            if (riskFilter && r.risk_level !== riskFilter) return false;
            if (search) {
                const searchable = `${r.alert_name} ${r.endpoint} ${r.details}`.toLowerCase();
                if (!searchable.includes(search)) return false;
            }
            return true;
        });

        this.renderResults();
    }

    sortResults(column) {
        if (this.sortColumn === column) {
            this.sortAsc = !this.sortAsc;
        } else {
            this.sortColumn = column;
            this.sortAsc = true;
        }

        this.filteredResults.sort((a, b) => {
            let valA = a[column] || '';
            let valB = b[column] || '';
            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();

            if (valA < valB) return this.sortAsc ? -1 : 1;
            if (valA > valB) return this.sortAsc ? 1 : -1;
            return 0;
        });

        // Update sort indicators
        this.resultsTable.querySelectorAll('th[data-sort]').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.sort === column) {
                th.classList.add(this.sortAsc ? 'sort-asc' : 'sort-desc');
            }
        });

        this.renderResults();
    }

    renderResults() {
        this.resultsBody.innerHTML = '';
        this.resultsCount.textContent = `${this.filteredResults.length} items`;

        this.filteredResults.forEach((r, index) => {
            const tr = document.createElement('tr');
            tr.dataset.index = index;
            tr.addEventListener('click', () => this.showDetails(r));

            tr.innerHTML = `
                <td><span class="status-badge status-${r.status.toLowerCase()}">${r.status}</span></td>
                <td><span class="risk-badge risk-${r.risk_level.toLowerCase()}">${r.risk_level}</span></td>
                <td class="vuln-name">${this.escapeHtml(r.alert_name)}</td>
                <td>${r.method}</td>
                <td class="endpoint">${this.escapeHtml(r.endpoint.substring(0, 60))}${r.endpoint.length > 60 ? '...' : ''}</td>
                <td class="details-cell">${this.escapeHtml(r.details.substring(0, 50))}${r.details.length > 50 ? '...' : ''}</td>
            `;
            this.resultsBody.appendChild(tr);
        });
    }

    showDetails(result) {
        this.detailStatus.textContent = result.status;
        this.detailStatus.className = `detail-value status-text status-${result.status.toLowerCase()}`;

        this.detailRisk.textContent = result.risk_level;
        this.detailRisk.className = `detail-value risk-text risk-${result.risk_level.toLowerCase()}`;

        this.detailMethod.textContent = result.method;
        this.detailPluginId.textContent = result.plugin_id;
        this.detailVulnName.textContent = result.alert_name;
        this.detailEndpoint.value = result.endpoint;
        this.detailEvidence.value = result.details;

        // Highlight selected row
        this.resultsBody.querySelectorAll('tr').forEach(tr => tr.classList.remove('selected'));
        event.currentTarget.classList.add('selected');
    }

    async clearResults() {
        if (this.sessionId) {
            try {
                await fetch(`/api/clear/${this.sessionId}`, {method: 'POST'});
            } catch (err) {
                console.error('Clear error:', err);
            }
        }

        this.sessionId = null;
        this.reportPath = null;
        this.results = [];
        this.filteredResults = [];

        // Reset UI
        this.reportPathInput.value = '';
        this.reportFile.value = '';
        this.progressBar.style.width = '0%';
        this.progressText.textContent = '0%';
        this.progressDetail.textContent = '';
        this.statTotal.textContent = '0';
        this.statPassed.textContent = '0';
        this.statFailed.textContent = '0';
        this.statSkipped.textContent = '0';
        this.statErrors.textContent = '0';
        this.statRate.textContent = '0%';
        this.resultsBody.innerHTML = '';
        this.resultsCount.textContent = '0 items';
        this.logContainer.innerHTML = '';

        // Reset details panel
        this.detailStatus.textContent = '-';
        this.detailStatus.className = 'detail-value';
        this.detailRisk.textContent = '-';
        this.detailRisk.className = 'detail-value';
        this.detailMethod.textContent = '-';
        this.detailPluginId.textContent = '-';
        this.detailVulnName.textContent = '-';
        this.detailEndpoint.value = '-';
        this.detailEvidence.value = '-';

        // Reset Nmap data
        this.nmapResults = null;
        this.nmapAlertShown = false;
        this.nmapScanning = false;

        // Reset Nmap UI
        if (this.nmapOnlyCheckbox) {
            this.nmapOnlyCheckbox.checked = false;
            this.handleNmapOnlyChange();
        }
        if (this.nmapScanPanel && this.nmapCheckbox && !this.nmapCheckbox.checked) {
            this.nmapScanPanel.style.display = 'none';
        }
        // Hide and reset Nmap progress
        this.showNmapProgress(false);
        if (this.nmapProgressBar) {
            this.nmapProgressBar.classList.remove('indeterminate');
            this.nmapProgressBar.style.width = '0%';
        }
        if (this.nmapProgressStatus) {
            this.nmapProgressStatus.classList.remove('completed');
        }

        // Reset buttons
        this.startBtn.disabled = false;
        this.stopBtn.disabled = true;
        this.clearBtn.disabled = false;
        this.disableExports();
        if (this.exportNmapBtn) {
            this.exportNmapBtn.disabled = true;
        }

        this.setStatus('ready', 'Ready');
        this.log('Cleared all results.');
    }

    exportReport(format) {
        if (!this.sessionId || this.results.length === 0) {
            this.showError('No results to export');
            return;
        }

        this.log(`Exporting ${format.toUpperCase()} report...`);

        // Trigger download
        window.location.href = `/api/export/${this.sessionId}/${format}`;
    }

    enableExports() {
        this.exportHtmlBtn.disabled = false;
        this.exportPdfBtn.disabled = false;
        this.exportCsvBtn.disabled = false;
    }

    disableExports() {
        this.exportHtmlBtn.disabled = true;
        this.exportPdfBtn.disabled = true;
        this.exportCsvBtn.disabled = true;
    }

    setStatus(status, text) {
        this.statusDot.className = `status-dot ${status}`;
        this.statusText.textContent = text;
    }

    updateLogs(logs) {
        const currentCount = this.logContainer.children.length;
        for (let i = currentCount; i < logs.length; i++) {
            const div = document.createElement('div');
            div.className = 'log-entry';
            div.textContent = logs[i];
            this.logContainer.appendChild(div);
        }
        this.logContainer.scrollTop = this.logContainer.scrollHeight;
    }

    log(message) {
        const timestamp = new Date().toLocaleTimeString();
        const div = document.createElement('div');
        div.className = 'log-entry';
        div.textContent = `[${timestamp}] ${message}`;
        this.logContainer.appendChild(div);
        this.logContainer.scrollTop = this.logContainer.scrollHeight;
    }

    showError(message) {
        this.log(`ERROR: ${message}`);
        alert(message);
    }

    showConnectionError(error, details) {
        const message = `${error}\n\n${details}`;
        alert(message);
    }

    toggleTheme() {
        this.isDarkTheme = !this.isDarkTheme;
        document.body.className = this.isDarkTheme ? 'dark-theme' : 'light-theme';
        this.themeToggle.textContent = this.isDarkTheme ? 'Light' : 'Dark';
    }

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    async checkNmapStatus() {
        try {
            const response = await fetch('/api/nmap-status');
            const data = await response.json();

            this.nmapAvailable = data.available;

            if (this.nmapCheckbox && this.nmapStatus) {
                if (data.available) {
                    this.nmapCheckbox.disabled = false;
                    this.nmapStatus.textContent = '(Available)';
                    this.nmapStatus.className = 'nmap-status available';
                    // Load scan profiles
                    this.loadNmapProfiles();
                } else {
                    this.nmapCheckbox.disabled = true;
                    this.nmapCheckbox.checked = false;
                    this.nmapStatus.textContent = `(${data.reason})`;
                    this.nmapStatus.className = 'nmap-status unavailable';
                    if (this.nmapOnlyCheckbox) {
                        this.nmapOnlyCheckbox.disabled = true;
                    }
                }
            }
        } catch (err) {
            console.error('Failed to check Nmap status:', err);
            if (this.nmapCheckbox && this.nmapStatus) {
                this.nmapCheckbox.disabled = true;
                this.nmapStatus.textContent = '(Status unknown)';
                this.nmapStatus.className = 'nmap-status unavailable';
            }
        }
    }

    async loadNmapProfiles() {
        console.log('Loading Nmap profiles...');
        try {
            const response = await fetch('/api/nmap-profiles');
            const data = await response.json();
            console.log('Nmap profiles response:', data);
            console.log('nmapScanGrid element:', this.nmapScanGrid);

            if (data.error) {
                console.error('API error:', data.error);
                return;
            }

            if (data.profiles && this.nmapScanGrid) {
                this.nmapProfiles = data.profiles;
                console.log('Populating', data.profiles.length, 'scan types');
                this.nmapScanGrid.innerHTML = '';

                data.profiles.forEach(profile => {
                    const item = document.createElement('div');
                    item.className = 'nmap-scan-item';
                    item.dataset.scanId = profile.id;

                    item.innerHTML = `
                        <input type="checkbox" id="scan_${profile.id}" value="${profile.id}">
                        <div class="nmap-scan-item-content">
                            <div class="nmap-scan-item-name">${profile.name}</div>
                            <div class="nmap-scan-item-desc" title="${profile.description}">${profile.description}</div>
                            <span class="nmap-scan-item-time">${profile.estimated_time}</span>
                        </div>
                    `;

                    const checkbox = item.querySelector('input[type="checkbox"]');

                    // Click on item toggles checkbox
                    item.addEventListener('click', (e) => {
                        if (e.target !== checkbox) {
                            checkbox.checked = !checkbox.checked;
                        }
                        item.classList.toggle('selected', checkbox.checked);
                        this.updateSelectedScansCount();
                    });

                    checkbox.addEventListener('change', () => {
                        item.classList.toggle('selected', checkbox.checked);
                        this.updateSelectedScansCount();
                    });

                    this.nmapScanGrid.appendChild(item);
                });

                // Select "quick" by default
                const quickItem = this.nmapScanGrid.querySelector('[data-scan-id="quick"]');
                if (quickItem) {
                    const checkbox = quickItem.querySelector('input[type="checkbox"]');
                    checkbox.checked = true;
                    quickItem.classList.add('selected');
                }
                this.updateSelectedScansCount();

                // Initially hide the panel if Nmap is not enabled
                if (this.nmapScanPanel && this.nmapCheckbox && !this.nmapCheckbox.checked) {
                    this.nmapScanPanel.style.display = 'none';
                }
                console.log('Profiles loaded successfully, panel visibility:', this.nmapScanPanel?.style.display);
            } else {
                console.error('No profiles or nmapScanGrid not found. Grid:', this.nmapScanGrid);
            }
        } catch (err) {
            console.error('Failed to load Nmap profiles:', err);
        }
    }

    handleNmapCheckboxChange() {
        const enabled = this.nmapCheckbox.checked;
        console.log('Nmap checkbox changed:', enabled, 'Panel:', this.nmapScanPanel);

        if (this.nmapOnlyCheckbox) {
            this.nmapOnlyCheckbox.disabled = !enabled;
            if (!enabled) {
                this.nmapOnlyCheckbox.checked = false;
            }
        }

        if (this.nmapScanPanel) {
            this.nmapScanPanel.style.display = enabled ? 'block' : 'none';
            console.log('Panel display set to:', this.nmapScanPanel.style.display);
        } else {
            console.error('nmapScanPanel not found!');
        }
    }

    handleNmapOnlyChange() {
        // If Nmap Only is checked, ZAP report becomes optional
        const nmapOnly = this.nmapOnlyCheckbox && this.nmapOnlyCheckbox.checked;
        if (nmapOnly) {
            this.reportPathInput.placeholder = 'ZAP report (optional for Nmap-only mode)';
        } else {
            this.reportPathInput.placeholder = 'Upload ZAP report (.html, .xml, .json)';
        }
    }

    updateSelectedScansCount() {
        if (this.nmapScanGrid && this.selectedScansCount) {
            const selected = this.nmapScanGrid.querySelectorAll('input[type="checkbox"]:checked').length;
            this.selectedScansCount.textContent = `${selected} selected`;
        }
    }

    showNmapProgress(show = true) {
        if (this.nmapProgressSection) {
            this.nmapProgressSection.style.display = show ? 'block' : 'none';
        }
        if (show && this.nmapProgressBar) {
            this.nmapProgressBar.classList.add('indeterminate');
            this.nmapProgressBar.style.width = '30%';
        }
    }

    updateNmapProgress(status, detail = '') {
        if (this.nmapProgressStatus) {
            this.nmapProgressStatus.textContent = status;
        }
        if (this.nmapProgressDetail) {
            this.nmapProgressDetail.textContent = detail;
        }
    }

    completeNmapProgress() {
        if (this.nmapProgressBar) {
            this.nmapProgressBar.classList.remove('indeterminate');
            this.nmapProgressBar.style.width = '100%';
        }
        if (this.nmapProgressStatus) {
            this.nmapProgressStatus.textContent = 'Completed';
            this.nmapProgressStatus.classList.add('completed');
        }
    }

    getSelectedNmapScanTypes() {
        if (!this.nmapScanGrid) return ['quick'];
        const checkboxes = this.nmapScanGrid.querySelectorAll('input[type="checkbox"]:checked');
        const selected = Array.from(checkboxes).map(cb => cb.value);
        return selected.length > 0 ? selected : ['quick'];
    }

    exportNmapReport() {
        if (!this.sessionId || !this.nmapResults) {
            this.showError('No Nmap scan results available');
            return;
        }

        this.log('Exporting Nmap report...');
        window.location.href = `/api/export-nmap/${this.sessionId}/html`;
    }
}

// Resizable Splitter Class
class ResizableSplitter {
    constructor(handle, panel1, panel2, isVertical = false, options = {}) {
        this.handle = handle;
        this.panel1 = panel1;
        this.panel2 = panel2;
        this.isVertical = isVertical;
        this.minSize1 = options.minSize1 || 100;
        this.minSize2 = options.minSize2 || 100;
        this.isDragging = false;

        this.init();
    }

    init() {
        this.handle.addEventListener('mousedown', (e) => this.startDrag(e));
        document.addEventListener('mousemove', (e) => this.drag(e));
        document.addEventListener('mouseup', () => this.stopDrag());
    }

    startDrag(e) {
        e.preventDefault();
        this.isDragging = true;
        this.handle.classList.add('active');
        document.body.style.cursor = this.isVertical ? 'ew-resize' : 'ns-resize';
        document.body.style.userSelect = 'none';
    }

    drag(e) {
        if (!this.isDragging) return;

        const container = this.panel1.parentElement;
        const containerRect = container.getBoundingClientRect();

        if (this.isVertical) {
            const mouseX = e.clientX - containerRect.left;
            const handleWidth = this.handle.offsetWidth;
            const newWidth1 = Math.max(this.minSize1, Math.min(mouseX, containerRect.width - this.minSize2 - handleWidth));
            this.panel1.style.flex = 'none';
            this.panel1.style.width = `${newWidth1}px`;
            this.panel2.style.flex = '1';
        } else {
            const mouseY = e.clientY - containerRect.top;
            const handleHeight = this.handle.offsetHeight;
            const newHeight1 = Math.max(this.minSize1, Math.min(mouseY, containerRect.height - this.minSize2 - handleHeight));
            this.panel1.style.flex = 'none';
            this.panel1.style.height = `${newHeight1}px`;
            this.panel2.style.flex = '1';
        }
    }

    stopDrag() {
        if (!this.isDragging) return;
        this.isDragging = false;
        this.handle.classList.remove('active');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.zapguard = new ZapGuardApp();

    // Initialize resizable splitters
    const resultsLogHandle = document.getElementById('resultsLogHandle');
    const resultsSection = document.getElementById('resultsSection');
    const logSection = document.getElementById('logSection');

    if (resultsLogHandle && resultsSection && logSection) {
        new ResizableSplitter(resultsLogHandle, resultsSection, logSection, false, {
            minSize1: 150,
            minSize2: 80
        });
    }

    const mainSplitterHandle = document.getElementById('mainSplitterHandle');
    const leftPanel = document.querySelector('.left-panel');
    const rightPanel = document.getElementById('rightPanel');

    if (mainSplitterHandle && leftPanel && rightPanel) {
        new ResizableSplitter(mainSplitterHandle, leftPanel, rightPanel, true, {
            minSize1: 500,
            minSize2: 250
        });
    }
});

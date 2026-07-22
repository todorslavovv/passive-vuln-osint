/**
 * OSINT_V3 Web Dashboard Controller
 * Handles application state, API sync, logs SSE connection, and report rendering.
 */
document.addEventListener('DOMContentLoaded', () => {
    // App State
    const state = {
        targets: [],
        reports: [],
        activeReport: null,
        activeReportFilename: null,
        scanRunning: false,
        sseSource: null,
        graphRenderer: null
    };

    // DOM Elements
    const elements = {
        navButtons: document.querySelectorAll('.nav-btn'),
        tabPanes: document.querySelectorAll('.tab-pane'),
        pageTitle: document.getElementById('page-title'),
        pageSubtitle: document.getElementById('page-subtitle'),
        refreshBtn: document.getElementById('refresh-data-btn'),
        
        // Dashboard
        statTargetsCount: document.getElementById('stat-targets-count'),
        statDepsCount: document.getElementById('stat-deps-count'),
        statVulnsCount: document.getElementById('stat-vulns-count'),
        statFindingsCount: document.getElementById('stat-findings-count'),
        dashboardTargetsTable: document.getElementById('dashboard-targets-table').querySelector('tbody'),
        
        // Targets Manager
        targetsListContainer: document.getElementById('targets-list-container'),
        addTargetBtn: document.getElementById('add-target-btn'),
        targetFormCard: document.getElementById('target-form-card'),
        targetFormPlaceholder: document.getElementById('target-form-placeholder'),
        targetForm: document.getElementById('target-form'),
        targetFormTitle: document.getElementById('target-form-title'),
        targetUrlInput: document.getElementById('target-url'),
        cancelTargetFormBtn: document.getElementById('cancel-target-form'),
        
        // Scanner
        scannerTargetsContainer: document.getElementById('scanner-targets-container'),
        scanOptOffline: document.getElementById('scan-opt-offline'),
        scanOptSkipNvd: document.getElementById('scan-opt-skip-nvd'),
        scanOptNvidiaSummary: document.getElementById('scan-opt-nvidia-summary'),
        nvidiaOptionsGroup: document.getElementById('nvidia-options-group'),
        scanOptNvidiaModel: document.getElementById('scan-opt-nvidia-model'),
        scanOptNvidiaApiKey: document.getElementById('scan-opt-nvidia-api-key'),
        scanOptGeminiSummary: document.getElementById('scan-opt-gemini-summary'),
        geminiOptionsGroup: document.getElementById('gemini-options-group'),
        scanOptGeminiModel: document.getElementById('scan-opt-gemini-model'),
        scanOptGeminiApiKey: document.getElementById('scan-opt-gemini-api-key'),
        scanOptRateLimit: document.getElementById('scan-opt-rate-limit'),
        rateLimitVal: document.getElementById('rate-limit-val'),
        scanOptMaxDeps: document.getElementById('scan-opt-max-deps'),
        startScanBtn: document.getElementById('start-scan-btn'),
        clearConsoleBtn: document.getElementById('clear-console-btn'),
        terminalOutput: document.getElementById('terminal-output'),
        
        // Status indicator
        globalStatusDot: document.getElementById('global-status-dot'),
        globalStatusText: document.getElementById('global-status-text'),
        
        // Reports
        reportSearchInput: document.getElementById('report-search-input'),
        reportsListContainer: document.getElementById('reports-list-container'),
        reportDetailsPanel: document.getElementById('report-details-panel'),
        reportDetailsPlaceholder: document.getElementById('report-details-placeholder'),
        reportActiveTitle: document.getElementById('report-active-title'),
        reportActiveTime: document.getElementById('report-active-time'),
        aiSummaryFlags: document.getElementById('ai-summary-flags'),
        viewRawJsonBtn: document.getElementById('view-raw-json-btn'),
        reportArtifactsContainer: document.getElementById('report-artifacts-container'),
        roDepsCount: document.getElementById('ro-deps-count'),
        roDepsConfirmedInferred: document.getElementById('ro-deps-confirmed-inferred'),
        roVulnsCount: document.getElementById('ro-vulns-count'),
        roVulnsFindingCount: document.getElementById('ro-vulns-finding-count'),
        roConfidenceFloor: document.getElementById('ro-confidence-floor'),
        roSourcesContainer: document.getElementById('ro-sources-container'),
        roConfidenceDistribution: document.getElementById('ro-confidence-distribution'),
        roGapsContainer: document.getElementById('ro-gaps-container'),
        roConflictsContainer: document.getElementById('ro-conflicts-container'),
        
        // Findings List
        findingsSearch: document.getElementById('findings-search'),
        findingsSeverityFilter: document.getElementById('findings-severity-filter'),
        roFindingsList: document.getElementById('ro-findings-list'),
        
        // Subtabs
        subTabBtns: document.querySelectorAll('.sub-tab-btn'),
        subTabPanes: document.querySelectorAll('.sub-tab-pane'),
        geminiSummarySubtab: document.getElementById('gemini-summary-subtab'),
        roGeminiSummaryText: document.getElementById('ro-gemini-summary-text'),
        nvidiaSummarySubtab: document.getElementById('nvidia-summary-subtab'),
        roAiSummaryText: document.getElementById('ro-ai-summary-text'),
        graphResetBtn: document.getElementById('graph-reset-btn'),
        
        // Drawer
        nodeDetailsDrawer: document.getElementById('node-details-drawer'),
        nodeDetailsBody: document.getElementById('node-details-body'),
        closeDrawerBtn: document.getElementById('close-drawer-btn'),
        
        // Modal
        jsonModal: document.getElementById('json-modal'),
        closeJsonModalBtn: document.getElementById('close-json-modal-btn'),
        jsonRawContent: document.getElementById('json-raw-content')
    };

    // API Helpers
    async function extractErrorMessage(res, fallback) {
        const raw = await res.text();
        try {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed.detail === 'string') return parsed.detail;
            if (parsed && Array.isArray(parsed.detail)) return parsed.detail.join('; ');
        } catch (_) {}
        return raw || fallback;
    }

    const api = {
        async get(url) {
            const res = await fetch(url);
            if (!res.ok) throw new Error(await extractErrorMessage(res, `Request failed (${res.status})`));
            return res.json();
        },
        async post(url, data) {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (!res.ok) throw new Error(await extractErrorMessage(res, `Request failed (${res.status})`));
            return res.json();
        },
        async put(url, data) {
            const res = await fetch(url, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (!res.ok) throw new Error(await extractErrorMessage(res, `Request failed (${res.status})`));
            return res.json();
        },
        async delete(url) {
            const res = await fetch(url, { method: 'DELETE' });
            if (!res.ok) throw new Error(await extractErrorMessage(res, `Request failed (${res.status})`));
            return res.json();
        }
    };

    // ==========================================================================
    // TAB MANAGEMENT
    // ==========================================================================
    function switchTab(tabId) {
        elements.navButtons.forEach(btn => {
            if (btn.getAttribute('data-tab') === tabId) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        elements.tabPanes.forEach(pane => {
            if (pane.id === `tab-${tabId}`) {
                pane.classList.add('active');
            } else {
                pane.classList.remove('active');
            }
        });

        // Update headers
        const titles = {
            dashboard: { title: 'Dashboard Overview', sub: 'OSINT supply chain vulnerabilities tracking' },
            targets: { title: 'Target Configurations', sub: 'Manage scanned targets scope and artifacts sources' },
            scanner: { title: 'Scan Engine Runner', sub: 'Configure and trigger active/passive discovery pipelines' },
            reports: { title: 'OSINT Reports Explorer', sub: 'Analyze dependency graphs, audit logs, and vulnerabilities' }
        };
        elements.pageTitle.textContent = titles[tabId].title;
        elements.pageSubtitle.textContent = titles[tabId].sub;

        if (tabId === 'reports' && state.activeReport && elements.subTabBtns[2].classList.contains('active')) {
            // Trigger graph resize if active report has graph tab active
            setTimeout(() => {
                if (state.graphRenderer) state.graphRenderer.resize();
            }, 100);
        }
    }

    elements.navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            switchTab(btn.getAttribute('data-tab'));
        });
    });

    // ==========================================================================
    // DATA SYNC & LOADING
    // ==========================================================================
    async function syncData() {
        showLoadingState();
        try {
            await Promise.all([
                fetchTargets(),
                fetchReports(),
                checkScanStatus()
            ]);
            updateDashboardMetrics();
        } catch (err) {
            console.error('Error syncing dashboard data:', err);
            addConsoleLine(`System Sync error: ${err.message}`, 'error');
        } finally {
            hideLoadingState();
        }
    }

    function showLoadingState() {
        elements.refreshBtn.classList.add('loading');
        elements.refreshBtn.disabled = true;
    }

    function hideLoadingState() {
        elements.refreshBtn.classList.remove('loading');
        elements.refreshBtn.disabled = false;
    }

    elements.refreshBtn.addEventListener('click', syncData);

    // ==========================================================================
    // TARGETS MANAGEMENT
    // ==========================================================================
    async function fetchTargets() {
        state.targets = await api.get('/api/targets');
        renderTargetsList();
        renderDashboardTargetsTable();
        renderScannerTargetsCheckboxes();
    }

    function renderTargetsList() {
        elements.targetsListContainer.innerHTML = '';
        if (state.targets.length === 0) {
            elements.targetsListContainer.innerHTML = '<div class="padded text-muted text-center">No targets configured.</div>';
            return;
        }

        state.targets.forEach(target => {
            const item = document.createElement('div');
            item.className = 'target-list-item';
            item.innerHTML = `
                <div class="target-item-info">
                    <h4>${escapeHtml(target.name)}</h4>
                    <p>${escapeHtml(target.url)}</p>
                </div>
                <div class="target-item-actions flex-between" style="gap: 8px;">
                    <button class="btn btn-xs btn-secondary edit-target-btn" data-name="${escapeHtml(target.name)}">Edit</button>
                    <button class="btn btn-xs btn-danger delete-target-btn" data-name="${escapeHtml(target.name)}">Delete</button>
                </div>
            `;
            
            item.querySelector('.edit-target-btn').addEventListener('click', (e) => {
                e.stopPropagation();
                openTargetForm('edit', target);
            });

            item.querySelector('.delete-target-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                if (confirm(`Are you sure you want to delete target '${target.name}'?`)) {
                    try {
                        await api.delete(`/api/targets/${target.name}`);
                        await fetchTargets();
                        closeTargetForm();
                        addConsoleLine(`Target '${target.name}' deleted successfully.`, 'system');
                    } catch (err) {
                        alert(`Failed to delete target: ${err.message}`);
                    }
                }
            });

            item.addEventListener('click', () => {
                openTargetForm('edit', target);
                document.querySelectorAll('.target-list-item').forEach(el => el.classList.remove('active'));
                item.classList.add('active');
            });

            elements.targetsListContainer.appendChild(item);
        });
    }

    function renderDashboardTargetsTable() {
        elements.dashboardTargetsTable.innerHTML = '';
        if (state.targets.length === 0) {
            elements.dashboardTargetsTable.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No targets configured. Add targets to scan.</td></tr>';
            return;
        }

        state.targets.forEach(target => {
            const hasReport = state.reports.some(r => r.target_name === target.name);
            const report = state.reports.find(r => r.target_name === target.name);
            
            let statusBadge = '<span class="badge badge-outline"><span class="badge-status never"></span>Never Scanned</span>';
            if (hasReport) {
                statusBadge = `<span class="badge badge-outline"><span class="badge-status completed"></span>Scanned (${report.dependency_count} deps)</span>`;
            }

            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${escapeHtml(target.name)}</strong></td>
                <td><a href="${escapeHtml(target.url)}" target="_blank" class="text-muted">${escapeHtml(target.url)}</a></td>
                <td>${statusBadge}</td>
                <td class="text-right">
                    <button class="btn btn-sm btn-secondary run-single-scan-btn" data-name="${escapeHtml(target.name)}">Quick Scan</button>
                    ${hasReport ? `<button class="btn btn-sm btn-primary view-target-report-btn" data-name="${escapeHtml(target.name)}">View Results</button>` : ''}
                </td>
            `;

            row.querySelector('.run-single-scan-btn').addEventListener('click', () => {
                switchTab('scanner');
                // Select only this target
                document.querySelectorAll('.scanner-target-radio').forEach(rb => {
                    rb.checked = (rb.value === target.name);
                });
            });

            if (hasReport) {
                row.querySelector('.view-target-report-btn').addEventListener('click', () => {
                    switchTab('reports');
                    loadReport(target.name);
                });
            }

            elements.dashboardTargetsTable.appendChild(row);
        });
    }

    function openTargetForm(mode, target = null) {
        elements.targetFormPlaceholder.style.display = 'none';
        elements.targetFormCard.style.display = 'block';
        elements.targetFormTitle.textContent = mode === 'new' ? 'Add New Target' : `Edit Target: ${target.name}`;
        elements.targetForm.reset();
        if (mode === 'edit' && target) {
            elements.targetUrlInput.value = target.url;
        }
    }

    function closeTargetForm() {
        elements.targetFormCard.style.display = 'none';
        elements.targetFormPlaceholder.style.display = 'flex';
        elements.targetForm.reset();
        document.querySelectorAll('.target-list-item').forEach(el => el.classList.remove('active'));
    }

    elements.addTargetBtn.addEventListener('click', () => openTargetForm('new'));
    elements.cancelTargetFormBtn.addEventListener('click', closeTargetForm);

    elements.targetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = elements.targetUrlInput.value.trim();
        if (!url) return;

        try {
            await api.post('/api/targets', { url });
            addConsoleLine(`Target created from URL: ${url}`, 'system');
            await fetchTargets();
            closeTargetForm();
        } catch (err) {
            const msg = (err && err.message) || 'Unknown error';
            const dupMatch = msg.match(/Target '([^']+)' already exists/);
            if (dupMatch) {
                const existingName = dupMatch[1];
                const existing = state.targets.find(t => t.name === existingName);
                const goEdit = confirm(
                    `Target '${existingName}' already exists.\n\n` +
                    (existing ? `URL: ${existing.url}\n\n` : '') +
                    `Open it for editing instead?`
                );
                if (goEdit && existing) {
                    closeTargetForm();
                    openTargetForm('edit', existing);
                    elements.targetsListContainer.querySelectorAll('.target-list-item').forEach(el => el.classList.remove('active'));
                }
            } else {
                alert(`Error saving target: ${msg}`);
            }
        }
    });

    // ==========================================================================
    // SCANNER & RUNNER
    // ==========================================================================
    function renderScannerTargetsCheckboxes() {
        elements.scannerTargetsContainer.innerHTML = '';
        if (state.targets.length === 0) {
            elements.scannerTargetsContainer.innerHTML = '<div class="text-muted">No targets configured. Configure targets in the Target Manager tab first.</div>';
            return;
        }

        state.targets.forEach(target => {
            const label = document.createElement('label');
            label.className = 'checkbox-label';
            label.innerHTML = `
                <input type="radio" name="scanner-target" class="scanner-target-radio" value="${escapeHtml(target.name)}">
                <span><strong>${escapeHtml(target.name)}</strong> (${escapeHtml(target.url)})</span>
            `;
            elements.scannerTargetsContainer.appendChild(label);
        });
    }

    elements.scanOptNvidiaSummary.addEventListener('change', () => {
        elements.nvidiaOptionsGroup.style.display = elements.scanOptNvidiaSummary.checked ? 'block' : 'none';
    });

    elements.scanOptGeminiSummary.addEventListener('change', () => {
        elements.geminiOptionsGroup.style.display = elements.scanOptGeminiSummary.checked ? 'block' : 'none';
    });

    elements.scanOptRateLimit.addEventListener('input', () => {
        elements.rateLimitVal.textContent = parseFloat(elements.scanOptRateLimit.value).toFixed(1);
    });

    elements.startScanBtn.addEventListener('click', async () => {
        if (state.scanRunning) return;

        const selectedRadio = document.querySelector('.scanner-target-radio:checked');
        const selectedTargets = selectedRadio ? [selectedRadio.value] : [];

        if (selectedTargets.length === 0) {
            alert('Please select a target to scan.');
            return;
        }

        const options = {
            offline: elements.scanOptOffline.checked,
            skip_nvd: elements.scanOptSkipNvd.checked,
            nvidia_summary: elements.scanOptNvidiaSummary.checked,
            nvidia_model: elements.scanOptNvidiaModel.value,
            nvidia_api_key: elements.scanOptNvidiaApiKey.value.trim() || null,
            gemini_summary: elements.scanOptGeminiSummary.checked,
            gemini_model: elements.scanOptGeminiModel.value,
            gemini_api_key: elements.scanOptGeminiApiKey.value.trim() || null,
            rate_limit: parseFloat(elements.scanOptRateLimit.value),
            max_enrich_dependencies: elements.scanOptMaxDeps.value ? parseInt(elements.scanOptMaxDeps.value) : null
        };

        try {
            await api.post('/api/scans/run', {
                targets: selectedTargets,
                options: options
            });
            clearConsole();
            addConsoleLine('Triggering pipeline scan run execution...', 'system');
            checkScanStatus();
            listenToScanLogs();
        } catch (err) {
            alert(`Failed to start scan: ${err.message}`);
        }
    });

    elements.clearConsoleBtn.addEventListener('click', clearConsole);

    function clearConsole() {
        elements.terminalOutput.innerHTML = '<div class="terminal-line text-muted">Console logs cleared.</div>';
    }

    function addConsoleLine(text, level = 'info') {
        const line = document.createElement('div');
        line.className = `terminal-line ${level}`;
        line.textContent = text;
        elements.terminalOutput.appendChild(line);
        elements.terminalOutput.scrollTop = elements.terminalOutput.scrollHeight;
    }

    async function checkScanStatus() {
        const status = await api.get('/api/scans/status');
        state.scanRunning = status.running;
        
        if (status.running) {
            elements.globalStatusDot.className = 'status-dot active';
            elements.globalStatusText.textContent = `Running scan (${status.targets.join(', ')})`;
            elements.startScanBtn.disabled = true;
            elements.startScanBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="loading"><circle cx="12" cy="12" r="10"></circle></svg>
                <span>Analyzing Pipeline...</span>
            `;
            listenToScanLogs();
        } else {
            elements.globalStatusDot.className = 'status-dot idle';
            elements.globalStatusText.textContent = 'System Idle';
            elements.startScanBtn.disabled = false;
            elements.startScanBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                <span>Launch Scan Engine</span>
            `;
            if (state.sseSource) {
                state.sseSource.close();
                state.sseSource = null;
            }
        }
    }

    function listenToScanLogs() {
        if (state.sseSource) return;

        state.sseSource = new EventSource('/api/scans/stream-logs');
        
        state.sseSource.onmessage = (event) => {
            const log = event.data;
            if (log === '[SCAN_COMPLETE]') {
                addConsoleLine('--- Scan completed. ---', 'system');
                checkScanStatus();
                syncData(); // Refresh tables/reports list
            } else {
                // Style line depending on content log-level
                let level = 'info';
                if (log.includes('[ERROR]')) level = 'error';
                else if (log.includes('[WARNING]')) level = 'warning';
                else if (log.includes('[DEBUG]')) level = 'text-muted';
                
                addConsoleLine(log, level);
            }
        };

        state.sseSource.onerror = (err) => {
            console.error('SSE Error:', err);
            state.sseSource.close();
            state.sseSource = null;
        };
    }

    // ==========================================================================
    // REPORTS EXPLORER
    // ==========================================================================
    async function fetchReports() {
        state.reports = await api.get('/api/reports');
        renderReportsSidebar();
    }

    function renderReportsSidebar() {
        elements.reportsListContainer.innerHTML = '';
        
        // Apply text filter
        const filterText = elements.reportSearchInput.value.toLowerCase();
        const filteredReports = state.reports.filter(r => r.target_name.toLowerCase().includes(filterText));

        if (filteredReports.length === 0) {
            elements.reportsListContainer.innerHTML = '<div class="padded text-muted text-center">No reports found.</div>';
            return;
        }

        filteredReports.forEach(report => {
            const card = document.createElement('div');
            const isActive = state.activeReportFilename === report.target_name;
            card.className = `report-list-card ${isActive ? 'active' : ''}`;
            card.innerHTML = `
                <div class="report-card-header">
                    <h4>${escapeHtml(report.target_name)}</h4>
                    <button class="btn btn-xs btn-danger delete-report-btn" data-name="${escapeHtml(report.target_name)}" title="Delete report">×</button>
                </div>
                <div class="report-card-metrics">
                    <span class="metric-badge">${report.dependency_count} deps</span>
                    <span class="metric-badge" style="color: ${report.finding_count > 0 ? 'var(--color-critical)' : 'inherit'}">${report.finding_count} findings</span>
                </div>
                <span class="report-card-date">Scanned: ${formatDate(report.updated_at)}</span>
            `;

            card.addEventListener('click', () => {
                document.querySelectorAll('.report-list-card').forEach(el => el.classList.remove('active'));
                card.classList.add('active');
                loadReport(report.target_name);
            });

            card.querySelector('.delete-report-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                if (!confirm(`Delete report '${report.target_name}' and all its artifacts?`)) return;
                try {
                    await api.delete(`/api/reports/${report.target_name}`);
                    if (state.activeReportFilename === report.target_name) {
                        state.activeReport = null;
                        state.activeReportFilename = null;
                        elements.reportDetailsPanel.style.display = 'none';
                        elements.reportDetailsPlaceholder.style.display = 'flex';
                    }
                    await fetchReports();
                    addConsoleLine(`Report '${report.target_name}' deleted.`, 'system');
                } catch (err) {
                    alert(`Failed to delete report: ${err.message}`);
                }
            });

            elements.reportsListContainer.appendChild(card);
        });
    }

    elements.reportSearchInput.addEventListener('input', renderReportsSidebar);

    async function loadReport(targetName) {
        showLoadingState();
        try {
            state.activeReport = await api.get(`/api/reports/detail/${targetName}`);
            state.activeReportFilename = targetName;
            renderActiveReport();

            // Reset AI summary subtabs
            elements.roAiSummaryText.innerHTML = '';
            elements.nvidiaSummarySubtab.style.display = 'none';
            elements.roGeminiSummaryText.innerHTML = '';
            elements.geminiSummarySubtab.style.display = 'none';

            // Try to load per-target NVIDIA summary if present
            try {
                const nvidiaData = await api.get(`/api/reports/nvidia-summary/${targetName}`);
                elements.roAiSummaryText.innerHTML = formatMarkdown(nvidiaData.summary);
                elements.nvidiaSummarySubtab.style.display = 'block';
            } catch {
                // No NVIDIA summary available
            }

            // Try to load per-target Gemini summary if present
            try {
                const geminiData = await api.get(`/api/reports/gemini-summary/${targetName}`);
                elements.roGeminiSummaryText.innerHTML = formatMarkdown(geminiData.summary);
                elements.geminiSummarySubtab.style.display = 'block';
            } catch {
                // No Gemini summary available
            }

            renderAiSummaryFlags();

        } catch (err) {
            alert(`Failed to load report: ${err.message}`);
        } finally {
            hideLoadingState();
        }
    }

    function renderAiSummaryFlags() {
        const hasNvidia = elements.nvidiaSummarySubtab.style.display !== 'none';
        const hasGemini = elements.geminiSummarySubtab.style.display !== 'none';
        elements.aiSummaryFlags.innerHTML = '';

        if (hasGemini) {
            const geminiFlag = document.createElement('span');
            geminiFlag.className = 'ai-flag ai-flag-blue';
            geminiFlag.textContent = 'Gemini Summary';
            elements.aiSummaryFlags.appendChild(geminiFlag);
        }

        if (hasNvidia) {
            const nvidiaFlag = document.createElement('span');
            nvidiaFlag.className = 'ai-flag ai-flag-green';
            nvidiaFlag.textContent = 'NVIDIA Summary';
            elements.aiSummaryFlags.appendChild(nvidiaFlag);
        }

        if (!hasGemini && !hasNvidia) {
            const noneFlag = document.createElement('span');
            noneFlag.className = 'ai-flag ai-flag-none';
            noneFlag.textContent = 'No AI summary';
            elements.aiSummaryFlags.appendChild(noneFlag);
        }
    }

    async function loadReportArtifacts(targetName) {
        if (!targetName) return;
        try {
            const artifacts = await api.get(`/api/reports/artifacts/${targetName}`);
            elements.reportArtifactsContainer.innerHTML = '';

            // Raw JSON always comes from the in-memory active report
            const rawJsonBtn = document.createElement('button');
            rawJsonBtn.className = 'btn btn-sm btn-secondary';
            rawJsonBtn.textContent = 'Raw JSON';
            rawJsonBtn.addEventListener('click', () => {
                if (!state.activeReport) return;
                elements.jsonRawContent.textContent = JSON.stringify(state.activeReport, null, 2);
                elements.jsonModal.style.display = 'flex';
            });
            elements.reportArtifactsContainer.appendChild(rawJsonBtn);

            artifacts.forEach(artifact => {
                const btn = document.createElement('a');
                btn.className = 'btn btn-sm btn-secondary';
                btn.href = artifact.url;
                btn.download = artifact.download_name;
                btn.textContent = _artifactLabel(artifact.kind);
                elements.reportArtifactsContainer.appendChild(btn);
            });
        } catch (err) {
            console.error('Failed to load report artifacts:', err);
        }
    }

    function _artifactLabel(kind) {
        const labels = {
            'report-json': 'JSON Report',
            'report-text': 'Text Report',
            'graph-dot': 'Graph DOT',
            'cyclonedx': 'CycloneDX SBOM',
            'spdx': 'SPDX SBOM',
            'nvidia-summary': 'NVIDIA Summary',
            'gemini-summary': 'Gemini Summary'
        };
        return labels[kind] || kind;
    }

    function renderActiveReport() {
        const report = state.activeReport;
        if (!report) return;

        // Validate the loaded document is an OSINT target report, not an SBOM or other artifact.
        if (!report.target || !report.summary) {
            elements.reportDetailsPlaceholder.style.display = 'none';
            elements.reportDetailsPanel.style.display = 'flex';
            elements.reportActiveTitle.textContent = 'Invalid Report';
            elements.reportActiveTime.textContent = 'The selected file is not a target intelligence report.';
            elements.reportArtifactsContainer.innerHTML = '';
            return;
        }

        elements.reportDetailsPlaceholder.style.display = 'none';
        elements.reportDetailsPanel.style.display = 'flex';

        // Header details
        elements.reportActiveTitle.textContent = `Target: ${report.target.name || 'unknown'}`;

        // Get date if present in registry or format date
        const time = report.global_registry?.plugin_events?.[0]?.timestamp || report.target.metadata?.scanned_at || '';
        elements.reportActiveTime.textContent = time ? `Scanned: ${time.replace('T', ' ').split('.')[0]}` : 'Offline Run';

        // Overview metrics
        const summary = report.summary || {};
        elements.roDepsCount.textContent = summary.dependency_count ?? 0;
        elements.roDepsConfirmedInferred.textContent = `${summary.confirmed_dependencies ?? 0} confirmed, ${summary.inferred_dependencies ?? 0} inferred`;
        elements.roVulnsCount.textContent = summary.vulnerability_count ?? 0;
        elements.roVulnsFindingCount.textContent = `Linked to ${summary.finding_count ?? 0} ranked findings`;
        elements.roConfidenceFloor.textContent = summary.confidence_floor !== null && summary.confidence_floor !== undefined
            ? summary.confidence_floor.toFixed(2)
            : '1.0';

        // Sources coverage
        elements.roSourcesContainer.innerHTML = '';
        const observedSources = report.source_coverage?.observed_source_types || [];
        if (observedSources.length === 0) {
            elements.roSourcesContainer.innerHTML = '<span class="text-muted">No sources recorded</span>';
        } else {
            observedSources.forEach(src => {
                const tag = document.createElement('span');
                tag.className = 'data-tag';
                tag.textContent = String(src).toUpperCase();
                elements.roSourcesContainer.appendChild(tag);
            });
        }

        // Confidence distribution progress bars
        elements.roConfidenceDistribution.innerHTML = '';
        const dist = report.confidence_distribution || {};
        const total = summary.dependency_count || 1;

        const makeProgressItem = (label, count, colorClass) => {
            const percentage = ((count / total) * 100).toFixed(0);
            return `
                <div class="progress-item">
                    <div class="progress-label-row">
                        <span>${label}</span>
                        <span>${count} (${percentage}%)</span>
                    </div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill ${colorClass}" style="width: ${percentage}%"></div>
                    </div>
                </div>
            `;
        };
        elements.roConfidenceDistribution.innerHTML += makeProgressItem('High (>= 0.8)', dist.high_0_8_to_1_0 || 0, 'purple');
        elements.roConfidenceDistribution.innerHTML += makeProgressItem('Medium (0.6 - 0.79)', dist.medium_0_6_to_0_79 || 0, 'blue');
        elements.roConfidenceDistribution.innerHTML += makeProgressItem('Low (< 0.6)', dist.low_below_0_6 || 0, 'yellow');

        // Gaps & Conflicts
        elements.roGapsContainer.innerHTML = '';
        const gaps = report.collection_gaps || [];
        if (gaps.length === 0) {
            elements.roGapsContainer.innerHTML = '<div class="text-muted">No gaps identified. All passive collectors succeeded.</div>';
        } else {
            gaps.forEach(gap => {
                const div = document.createElement('div');
                div.className = 'gap-item';
                div.innerHTML = `<strong>[${escapeHtml(gap.category)}]</strong> ${escapeHtml(gap.message || gap.evidence || '')}`;
                elements.roGapsContainer.appendChild(div);
            });
        }

        elements.roConflictsContainer.innerHTML = '';
        const conflicts = report.conflict_summary?.conflicts || [];
        if (conflicts.length === 0) {
            elements.roConflictsContainer.innerHTML = '<div class="text-muted">No version or status conflicts detected in the dependency resolution.</div>';
        } else {
            conflicts.forEach(conflict => {
                const div = document.createElement('div');
                div.className = 'conflict-item';

                let desc = '';
                if (conflict.conflict_type === 'dependency_version_claim') {
                    desc = `Version claim conflict resolved on package <strong>${escapeHtml(conflict.package)}</strong>. Winner version: <strong>${escapeHtml(conflict.winner.split('@')[1])}</strong> (${conflict.why_winner}).`;
                } else {
                    desc = JSON.stringify(conflict);
                }
                div.innerHTML = desc;
                elements.roConflictsContainer.appendChild(div);
            });
        }

        // Render findings list
        renderFindingsList();

        // Render dependency graph
        renderGraphTab();

        // Load available report artifacts
        loadReportArtifacts(report.target.name || state.activeReportFilename);
    }

    // ==========================================================================
    // FINDINGS FILTERING & RENDERING
    // ==========================================================================
    function renderFindingsList() {
        elements.roFindingsList.innerHTML = '';
        const report = state.activeReport;
        if (!report) return;

        const findings = report.findings || [];
        const searchText = elements.findingsSearch.value.toLowerCase();
        const severityFilter = elements.findingsSeverityFilter.value;

        const filtered = findings.filter(finding => {
            const vuln = finding.vulnerability || {};
            const packageKey = String(finding.dependency_key || '').toLowerCase();
            const vulnId = String(vuln.vulnerability_id || '').toLowerCase();
            const matchesSearch = packageKey.includes(searchText) || vulnId.includes(searchText);

            const matchesSeverity = !severityFilter || vuln.severity === severityFilter;

            return matchesSearch && matchesSeverity;
        });

        if (filtered.length === 0) {
            elements.roFindingsList.innerHTML = '<div class="padded text-muted text-center">No findings match active filters.</div>';
            return;
        }

        filtered.forEach((finding, idx) => {
            const card = document.createElement('div');
            card.className = 'finding-card';

            const vuln = finding.vulnerability || {};
            const dep = finding.dependency || {};
            const factors = finding.factors || {};
            const hasExploit = (finding.exploit_signals || []).length > 0;
            const exploitBadge = hasExploit ? '<span class="badge badge-sev CRITICAL" style="margin-left: 8px;">Exploit Available</span>' : '';
            const cvss = vuln.cvss_score;
            const confidence = typeof factors.confidence === 'number' ? factors.confidence : (dep.confidence || 0);

            card.innerHTML = `
                <div class="finding-card-summary" id="finding-summary-${idx}">
                    <div class="finding-title-block">
                        <span class="finding-package-key">${escapeHtml(finding.dependency_key)}</span>
                        <span class="finding-vuln-id">${escapeHtml(vuln.vulnerability_id)}</span>
                    </div>
                    <div class="flex-between" style="gap: 16px;">
                        ${exploitBadge}
                        <span class="finding-cvss-score text-muted">CVSS: ${cvss !== null && cvss !== undefined ? cvss.toFixed(1) : 'N/A'}</span>
                        <span class="badge badge-sev ${vuln.severity || 'UNKNOWN'}">${vuln.severity || 'UNKNOWN'}</span>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="arrow-icon"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    </div>
                </div>
                <div class="finding-card-details" id="finding-details-${idx}">
                    <div class="finding-detail-row">
                        <strong>Description:</strong>
                        <p>${escapeHtml(vuln.summary)}</p>
                    </div>
                    <div class="grid-2-col">
                        <div class="finding-detail-row">
                            <strong>Risk Rank Scoring:</strong>
                            <p>${typeof finding.score === 'number' ? finding.score.toFixed(1) : 'N/A'} / 100 (${escapeHtml(finding.rank_reason)})</p>
                        </div>
                        <div class="finding-detail-row">
                            <strong>Exposure Confidence:</strong>
                            <p>${(confidence * 100).toFixed(0)}% (${dep.status || 'unknown'})</p>
                        </div>
                    </div>
                    ${hasExploit ? `
                        <div class="finding-detail-row">
                            <strong>Exploit Intelligence Signals (OSINT):</strong>
                            <div class="gaps-list" style="margin-top: 6px;">
                                ${finding.exploit_signals.map(sig => `
                                    <div class="gap-item" style="border-left-color: var(--color-critical); padding: 8px 12px; font-size: 12.5px;">
                                        <strong>Source: ${escapeHtml(sig.source)}</strong>
                                        <p>${escapeHtml(sig.description)}</p>
                                        <a href="${escapeHtml(sig.reference)}" target="_blank" style="color: var(--accent-cyan); font-size: 11.5px; word-break: break-all;">${escapeHtml(sig.reference)}</a>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                    ${(vuln.references || []).length > 0 ? `
                        <div class="finding-detail-row">
                            <strong>References:</strong>
                            <ul style="padding-left: 20px; font-size: 12.5px; color: var(--text-secondary); margin-top: 4px;">
                                ${vuln.references.slice(0, 5).map(ref => `
                                    <li><a href="${escapeHtml(ref)}" target="_blank" style="color: var(--accent-blue);">${escapeHtml(ref)}</a></li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;

            // Toggle collapse
            card.querySelector('.finding-card-summary').addEventListener('click', () => {
                const details = card.querySelector('.finding-card-details');
                const arrow = card.querySelector('.arrow-icon');
                const isOpen = details.style.display === 'block';

                details.style.display = isOpen ? 'none' : 'block';
                arrow.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
                arrow.style.transition = 'transform 0.2s';
            });

            elements.roFindingsList.appendChild(card);
        });
    }

    elements.findingsSearch.addEventListener('input', renderFindingsList);
    elements.findingsSeverityFilter.addEventListener('change', renderFindingsList);

    // ==========================================================================
    // DEPENDENCY GRAPH RENDERING
    // ==========================================================================
    function renderGraphTab() {
        if (!state.activeReport) return;
        const graph = state.activeReport.graph || {};
        const nodes = graph.nodes || [];
        const edges = graph.edges || [];
        if (!nodes.length && !edges.length) return;

        if (!state.graphRenderer) {
            state.graphRenderer = new window.DependencyGraphRenderer('dependency-graph-canvas', (nodeData) => {
                openNodeDrawer(nodeData);
            });
        }

        state.graphRenderer.setData(nodes, edges);
    }

    elements.graphResetBtn.addEventListener('click', () => {
        if (state.graphRenderer) state.graphRenderer.fitToScreen();
    });

    // Node drawer details selection
    function openNodeDrawer(node) {
        elements.nodeDetailsBody.innerHTML = `
            <div class="drawer-section">
                <h4>General Info</h4>
                <p><strong>Package Name:</strong> ${escapeHtml(node.name)}</p>
                <p><strong>Ecosystem:</strong> ${escapeHtml(node.ecosystem).toUpperCase()}</p>
                <p><strong>Resolved Version:</strong> ${escapeHtml(node.version || 'unknown')}</p>
                <p><strong>Scope Status:</strong> <span class="badge badge-outline">${escapeHtml(node.status)}</span></p>
                <p><strong>Resolution Confidence:</strong> ${(node.confidence * 100).toFixed(0)}%</p>
            </div>
            
            <div class="drawer-section">
                <h4>Provenance Evidence Trail</h4>
                <div class="evidence-list">
                    ${(node.provenance || []).map(prov => `
                        <div class="evidence-item">
                            <p><strong>Type:</strong> ${escapeHtml(prov.source_type)} (${escapeHtml(prov.fetch_method)})</p>
                            <p><strong>Collector:</strong> ${escapeHtml(prov.source_name)}</p>
                            <p><strong>Locator Path:</strong> <span style="word-break: break-all; color: var(--text-secondary);">${escapeHtml(prov.locator)}</span></p>
                            <p><strong>Evidence:</strong> ${escapeHtml(prov.evidence || 'No details provided.')}</p>
                            ${prov.snippet ? `<span class="evidence-snippet">${escapeHtml(prov.snippet)}</span>` : ''}
                            <span class="report-card-date">Collected: ${prov.collected_at ? escapeHtml(prov.collected_at.replace('T', ' ').split('.')[0]) : 'unknown'}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        elements.nodeDetailsDrawer.classList.add('open');
    }

    elements.closeDrawerBtn.addEventListener('click', () => {
        elements.nodeDetailsDrawer.classList.remove('open');
    });

    // ==========================================================================
    // RAW JSON MODAL
    // ==========================================================================
    elements.closeJsonModalBtn.addEventListener('click', () => {
        elements.jsonModal.style.display = 'none';
    });

    elements.jsonModal.addEventListener('click', (e) => {
        if (e.target === elements.jsonModal) {
            elements.jsonModal.style.display = 'none';
        }
    });

    // ==========================================================================
    // REPORT IN-PAGE SUBTABS
    // ==========================================================================
    elements.subTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const subtabId = btn.getAttribute('data-subtab');
            
            elements.subTabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            elements.subTabPanes.forEach(pane => {
                if (pane.id === `subtab-${subtabId}`) {
                    pane.classList.add('active');
                } else {
                    pane.classList.remove('active');
                }
            });

            if (subtabId === 'graph') {
                setTimeout(() => {
                    if (state.graphRenderer) {
                        state.graphRenderer.resize();
                        state.graphRenderer.fitToScreen();
                    }
                }, 50);
            }
        });
    });

    // ==========================================================================
    // DASHBOARD METRICS SUMMARY CARD CALCS
    // ==========================================================================
    function updateDashboardMetrics() {
        elements.statTargetsCount.textContent = state.targets.length;
        
        let deps = 0;
        let vulns = 0;
        let findings = 0;

        // Sum across all loaded target reports
        state.reports.forEach(report => {
            deps += report.dependency_count || 0;
            vulns += report.vulnerability_count || 0;
            findings += report.finding_count || 0;
        });

        elements.statDepsCount.textContent = deps;
        elements.statVulnsCount.textContent = vulns;
        elements.statFindingsCount.textContent = findings;
    }

    // ==========================================================================
    // STRING UTILS
    // ==========================================================================
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function formatDate(unixSecs) {
        const d = new Date(unixSecs * 1000);
        return d.toISOString().replace('T', ' ').split('.')[0];
    }

    function formatMarkdown(text) {
        // Minimal parser for bold/headings/lists in the AI text summary
        return text
            .split('\n')
            .map(line => {
                let formatted = escapeHtml(line);
                
                // Headings
                if (formatted.startsWith('### ')) {
                    return `<h4>${formatted.substring(4)}</h4>`;
                } else if (formatted.startsWith('## ')) {
                    return `<h3>${formatted.substring(3)}</h3>`;
                } else if (formatted.startsWith('# ')) {
                    return `<h2>${formatted.substring(2)}</h2>`;
                }
                
                // Bullet points
                if (formatted.startsWith('- ') || formatted.startsWith('* ')) {
                    return `<li>${formatted.substring(2)}</li>`;
                }

                // Bold markers
                formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
                
                return line.trim() === '' ? '<br>' : `<p>${formatted}</p>`;
            })
            .join('');
    }

    // Initialize Page load
    syncData();
});

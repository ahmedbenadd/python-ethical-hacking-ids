const app = {
    // ─── STATE ───
    socket: null,
    packets: [],
    alerts: [],
    defcon: 5,
    stats: {
        totalPackets: 0,
        totalAlerts: 0,
        trafficHistory: Array(60).fill(0), // 60 seconds
        protoCounts: { TCP: 0, UDP: 0, ICMP: 0, ARP: 0 },
        topTalkers: {}
    },
    charts: { traffic: null, protocol: null },

    // ─── INIT ───
    init: function () {
        console.log("Initializing Guardian IDS...");
        this.socket = io();
        this.setupSocket();
        this.setupFilters();
        this.initCharts();

        // Start Update Loop (1s)
        setInterval(() => this.updateStatsUI(), 1000);
    },

    // ─── SOCKETS ───
    setupSocket: function () {
        this.socket.on('connect', () => console.log("Socket Connected"));

        // Authoritative Totals from Server (Persistence Fix)
        this.socket.on('init_stats', (data) => {
            if (data) {
                this.stats.totalPackets = data.total_packets;
                this.stats.totalAlerts = data.total_alerts;
                this.updateCounterUI();
            }
        });

        // History
        this.socket.on('history_packets', (history) => {
            console.log(`Loaded ${history.length} packets from history`);
            this.packets = history.reverse();
            this.renderTable();

            // Re-process stats (rough approximation)
            history.forEach(p => this.processStats(p));
            this.updateStatsUI();
        });

        this.socket.on('history_alerts', (history) => {
            this.alerts = history;
            this.renderAlerts();
        });

        // Realtime
        this.socket.on('new_packet', (packet) => {
            this.stats.totalPackets++;
            this.packets.unshift(packet);
            if (this.packets.length > 200) this.packets.pop();

            this.processStats(packet);
            this.updateCounterUI();
            this.renderTable();
        });

        this.socket.on('new_alert', (alert) => {
            this.stats.totalAlerts++;
            this.alerts.unshift(alert);
            this.updateCounterUI();
            this.addAlertToFeed(alert);
        });


    },

    // ─── DATA PROCESSING ───
    _packetsThisSecond: 0,
    processStats: function (packet) {
        this._packetsThisSecond++;

        // Protocol
        let p = packet.proto;
        if (p === 6) this.stats.protoCounts.TCP++;
        else if (p === 17) this.stats.protoCounts.UDP++;
        else if (p === 1) this.stats.protoCounts.ICMP++;
        else this.stats.protoCounts.ARP++;

        // Top Talkers
        const src = packet.src_ip || packet.src_mac;
        if (src) {
            this.stats.topTalkers[src] = (this.stats.topTalkers[src] || 0) + 1;
        }
    },

    updateStatsUI: function () {
        // Traffic Rate Logic
        this.stats.trafficHistory.push(this._packetsThisSecond);
        this.stats.trafficHistory.shift();

        const currentRate = this._packetsThisSecond;
        document.getElementById('stat-rate').textContent = `${currentRate} pps`;

        this._packetsThisSecond = 0; // Reset

        // Update Charts
        if (this.charts.traffic) {
            this.charts.traffic.update('none'); // 'none' for performance
        }
        if (this.charts.protocol) {
            const counts = this.stats.protoCounts;
            this.charts.protocol.data.datasets[0].data = [counts.TCP, counts.UDP, counts.ICMP, counts.ARP];
            this.charts.protocol.update();
        }

        // Update Top Talkers Table
        const tbody = document.getElementById('top-talkers-body');
        if (tbody) {
            const sorted = Object.entries(this.stats.topTalkers)
                .sort((a, b) => b[1] - a[1]) // Descending
                .slice(0, 10);

            tbody.innerHTML = sorted.map(([ip, count]) => `
                <tr>
                    <td><span class="addr">${ip}</span></td>
                    <td>${count}</td>
                </tr>
            `).join('');
        }
    },

    updateCounterUI: function () {
        document.getElementById('stat-packets').textContent = this.stats.totalPackets;
        document.getElementById('stat-alerts').textContent = this.stats.totalAlerts;
    },

    // ─── CHARTS ───
    initCharts: function () {
        // Traffic Chart (Line)
        const trafficCtx = document.getElementById('chart-traffic');
        if (trafficCtx) {
            this.charts.traffic = new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: Array(60).fill(''),
                    datasets: [{
                        label: 'PPS',
                        data: this.stats.trafficHistory,
                        borderColor: '#00f3ff',
                        backgroundColor: 'rgba(0, 243, 255, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: {
                            beginAtZero: true,
                            grid: { color: '#222' },
                            ticks: { color: '#666' }
                        }
                    }
                }
            });
        }

        // Protocol Chart (Doughnut)
        const protoCtx = document.getElementById('chart-protocol');
        if (protoCtx) {
            this.charts.protocol = new Chart(protoCtx, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP', 'ARP'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#00f3ff', '#ffae00', '#00ff9d', '#bd00ff'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#999', boxWidth: 10, font: { size: 10 } }
                        }
                    }
                }
            });
        }
    },

    // ─── VIEW LOGIC ───
    switchView: function (viewId) {
        // Tabs
        document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));
        const btn = Array.from(document.querySelectorAll('.nav-item')).find(b => b.onclick.toString().includes(viewId));
        if (btn) btn.classList.add('active');

        // Views
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.getElementById(`view-${viewId}`).classList.add('active');
    },

    // ─── FILTERS & RENDER ───
    setupFilters: function () {
        const ids = ['filter-proto', 'filter-src', 'filter-dst'];
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', () => this.renderTable());
        });
    },

    renderTable: function () {
        const tbody = document.getElementById('traffic-table-body');
        if (!tbody) return;

        // Get Filters
        const fProto = document.getElementById('filter-proto').value;
        const fSrc = document.getElementById('filter-src').value.toLowerCase();
        const fDst = document.getElementById('filter-dst').value.toLowerCase();

        tbody.innerHTML = '';

        // Render top 50 post-filter
        let count = 0;
        for (const packet of this.packets) {
            if (count >= 50) break;

            // Resolve Proto
            let proto = packet.proto;
            if (packet.proto === 6) proto = 'TCP';
            else if (packet.proto === 17) proto = 'UDP';
            else if (packet.proto === 1) proto = 'ICMP';
            else if (!packet.proto || packet.proto === 2054) proto = 'ARP';

            // Filter Logic
            if (fProto !== 'ALL' && proto !== fProto) continue;

            const src = (packet.src_ip || packet.src_mac || '').toString().toLowerCase();
            const dst = (packet.dst_ip || packet.dst_mac || '').toString().toLowerCase();
            const sport = (packet.sport || '').toString();
            const dport = (packet.dport || '').toString();

            if (fSrc && !src.includes(fSrc) && !sport.includes(fSrc)) continue;
            if (fDst && !dst.includes(fDst) && !dport.includes(fDst)) continue;

            // Render
            const row = document.createElement('tr');

            // Info Column
            let info = '';
            if (packet.flags) info += `<span style="color:#888">Flags:</span> <span style="color:#fff">${packet.flags}</span> `;
            if (packet.src_mac && packet.src_ip) info += `<span style="color:#444">MAC: ${packet.src_mac}</span>`;

            row.innerHTML = `
                <td style="color:#666">${packet.time}</td>
                <td>${this.fmtAddr(packet.src_ip || packet.src_mac, packet.sport)}</td>
                <td>${this.fmtAddr(packet.dst_ip || packet.dst_mac, packet.dport)}</td>
                <td><span class="badge badge-${proto.toLowerCase()}">${proto}</span></td>
                <td style="font-size:0.8rem">${info}</td>
            `;
            tbody.appendChild(row);
            count++;
        }
    },

    fmtAddr: function (ip, port) {
        if (!ip) return '<span style="color:#444">-</span>';
        if (!port) return `<span class="addr" style="color:#fff; font-weight:bold">${ip}</span>`;
        return `<span class="addr" style="color:#fff; font-weight:bold">${ip}</span> <span style="color:#666">:${port}</span>`;
    },

    // ─── ALERTS ───
    renderAlerts: function () {
        const dashboardFeed = document.getElementById('dashboard-alerts');
        const simpleTable = document.getElementById('simple-alert-table');

        if (dashboardFeed) dashboardFeed.innerHTML = '';
        if (simpleTable) simpleTable.innerHTML = '';

        this.alerts.forEach(a => {
            if (simpleTable) simpleTable.insertAdjacentHTML('beforeend', this.createSimpleAlertRow(a));
        });

        if (dashboardFeed) {
            this.alerts.slice(0, 5).forEach(a => {
                dashboardFeed.insertAdjacentHTML('beforeend', this.createMiniAlertHTML(a));
            });
        }
    },

    addAlertToFeed: function (alert) {
        // 1. Add to Simple Log
        const simpleTable = document.getElementById('simple-alert-table');
        if (simpleTable) {
            simpleTable.insertAdjacentHTML('afterbegin', this.createSimpleAlertRow(alert));
        }

        // 2. Add to Dashboard
        const dashboardFeed = document.getElementById('dashboard-alerts');
        if (dashboardFeed) {
            dashboardFeed.insertAdjacentHTML('afterbegin', this.createMiniAlertHTML(alert));
            if (dashboardFeed.children.length > 5) dashboardFeed.lastElementChild.remove();
        }
    },

    createSimpleAlertRow: function (alert) {
        const severity = (alert.severity || 'medium').toUpperCase();
        let color = '#fff';
        if (severity === 'HIGH') color = 'var(--danger)';
        if (severity === 'MEDIUM') color = 'var(--warning)';
        if (severity === 'LOW') color = 'var(--bg-panel)';

        return `
            <tr>
                <td style="color:#666">${alert.timestamp}</td>
                <td><span style="color:${color}; font-weight:bold">${severity}</span></td>
                <td>${alert.type}</td>
                <td class="addr">${alert.source || 'Unknown'}</td>
                <td style="color:#ccc">${alert.message}</td>
            </tr>
        `;
    },

    createMiniAlertHTML: function (alert) {
        const severity = (alert.severity || 'medium').toLowerCase();
        return `
            <div class="alert-item ${severity}">
                <div class="alert-header">
                    <span class="alert-type">${alert.type.toUpperCase()}</span>
                    <span class="alert-time">${alert.timestamp}</span>
                </div>
                <div class="alert-msg">${alert.message}</div>
            </div>
        `;
    }
};



// Start App when DOM ready
document.addEventListener('DOMContentLoaded', () => app.init());

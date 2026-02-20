(function() {
    'use strict';
    
    let cpuGauge, memGauge, diskGauge, networkChart, loadChart;
    let performanceTimer = null;
    
    // Initialize gauges and charts
    window.initPerformanceMonitor = function() {
        console.log('🔧 Initializing performance monitor...');
        
        // Create gauges
        cpuGauge = createGauge('cpuGauge', '#10b981');
        memGauge = createGauge('memGauge', '#3b82f6');
        diskGauge = createGauge('diskGauge', '#f59e0b');
        
        // Create charts
        networkChart = createLineChart('networkChart', ['Sent (MB/s)', 'Received (MB/s)'], ['#3b82f6', '#10b981']);
        loadChart = createLineChart('loadChart', ['1min', '5min', '15min'], ['#ef4444', '#f59e0b', '#10b981']);
        
        // Initial load
        loadPerformanceData();
        
        // Auto-refresh every 10 seconds
        performanceTimer = setInterval(loadPerformanceData, 10000);
        
        console.log('✅ Performance monitor initialized');
        // Force resize charts after init
        setTimeout(function() {
            if (networkChart) networkChart.resize();
            if (loadChart) loadChart.resize();
        }, 500);
    };
    
    window.stopPerformanceMonitor = function() {
        if (performanceTimer) {
            clearInterval(performanceTimer);
            performanceTimer = null;
        }
    };
    
    function createGauge(canvasId, color) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        
        // Destroy existing chart if any
        const existing = Chart.getChart(canvas);
        if (existing) existing.destroy();
        
        const ctx = canvas.getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [color, 'rgba(255,255,255,0.08)'],
                    borderWidth: 0,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '70%',
                rotation: -90,
                circumference: 180,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    }
    
    function createLineChart(canvasId, labels, colors) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        
        // Destroy existing chart if any
        const existing = Chart.getChart(canvas);
        if (existing) existing.destroy();
        
        const ctx = canvas.getContext('2d');
        
        const datasets = labels.map((label, i) => ({
            label,
            data: [],
            borderColor: colors[i],
            backgroundColor: colors[i].replace(')', ', 0.1)').replace('rgb', 'rgba'),
            borderWidth: 2,
            tension: 0.4,
            fill: true
        }));
        
        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { 
                            color: 'rgba(255,255,255,0.7)',
                            maxRotation: 0,
                            autoSkip: true
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: 'rgba(255,255,255,0.7)' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: 'white' }
                    }
                }
            }
        });
    }
    
    async function loadPerformanceData() {
        try {
            // Get latest metrics
            const latestRes = await fetch('/api/server-metrics/latest', { credentials: 'include' });
            const latestData = await latestRes.json();
            
            if (!latestData.success) return;
            
            const metrics = latestData.data;
            
            // Update gauges
            updateGauge(cpuGauge, metrics.cpu_percent, 'cpuText', 'cpuLoad', metrics.load_1.toFixed(2));
            updateGauge(memGauge, metrics.mem_percent, 'memText', 'memUsed', metrics.mem_used_gb.toFixed(2), 'memTotal', metrics.mem_total_gb.toFixed(0));
            updateGauge(diskGauge, metrics.disk_percent, 'diskText', 'diskUsed', metrics.disk_used_gb.toFixed(1), 'diskTotal', metrics.disk_total_gb.toFixed(0));
            
            // Update uptime
            const uptime = formatUptime(metrics.uptime_seconds);
            document.getElementById('uptimeText').textContent = uptime;
            
            // Get history for charts
            const historyRes = await fetch('/api/server-metrics/history?hours=1', { credentials: 'include' });
            const historyData = await historyRes.json();
            
            if (historyData.success && historyData.data.length > 0) {
                updateCharts(historyData.data);
            }
            
        } catch (e) {
            console.error('Performance data load error:', e);
        }
    }
    
    function updateGauge(gauge, percent, textId, ...extraIds) {
        if (gauge) {
            gauge.data.datasets[0].data = [percent, 100 - percent];
            gauge.update('none');
        }
        const barId = textId.replace('Text', 'Bar');
        const barEl = document.getElementById(barId);
        if (barEl) barEl.style.width = Math.min(percent, 100) + '%';
        
        const textEl = document.getElementById(textId);
        if (textEl) {
            textEl.textContent = percent.toFixed(1) + '%';
            
            // Color based on usage
            if (percent > 90) textEl.style.color = '#ef4444';
            else if (percent > 70) textEl.style.color = '#f59e0b';
            else textEl.style.color = '#10b981';
        }
        
        // Update extra fields
        for (let i = 0; i < extraIds.length; i += 2) {
            const el = document.getElementById(extraIds[i]);
            if (el) el.textContent = extraIds[i + 1];
        }
    }
    
    function updateCharts(history) {
        // Limit to last 30 points for better readability
        const data = history.slice(-30);
        
        // Network chart - calculate delta for MB/s
        const networkLabels = [];
        const sentData = [];
        const recvData = [];
        
        for (let i = 1; i < data.length; i++) {
            const time = new Date(data[i].timestamp);
            networkLabels.push(time.getHours() + ':' + String(time.getMinutes()).padStart(2, '0'));
            
            const timeDiff = 60; // 1 minute in seconds
            const sentDelta = (data[i].net_sent_mb - data[i-1].net_sent_mb) / timeDiff;
            const recvDelta = (data[i].net_recv_mb - data[i-1].net_recv_mb) / timeDiff;
            
            sentData.push(sentDelta.toFixed(2));
            recvData.push(recvDelta.toFixed(2));
        }
        
        if (networkChart && networkLabels.length > 0) {
            // Auto-skip labels for readability
            const skipFactor = Math.max(1, Math.floor(networkLabels.length / 10));
            const displayLabels = networkLabels.map((l, i) => i % skipFactor === 0 ? l : '');
            
            networkChart.data.labels = displayLabels;
            networkChart.data.datasets[0].data = sentData;
            networkChart.data.datasets[1].data = recvData;
            networkChart.update('none');
        }
        
        // Load chart
        const loadLabels = [];
        const load1Data = [];
        const load5Data = [];
        const load15Data = [];
        
        data.forEach(m => {
            const time = new Date(m.timestamp);
            loadLabels.push(time.getHours() + ':' + String(time.getMinutes()).padStart(2, '0'));
            load1Data.push(m.load_1.toFixed(2));
            load5Data.push(m.load_5.toFixed(2));
            load15Data.push(m.load_15.toFixed(2));
        });
        
        if (loadChart && loadLabels.length > 0) {
            const skipFactor = Math.max(1, Math.floor(loadLabels.length / 10));
            const displayLabels = loadLabels.map((l, i) => i % skipFactor === 0 ? l : '');
            
            loadChart.data.labels = displayLabels;
            loadChart.data.datasets[0].data = load1Data;
            loadChart.data.datasets[1].data = load5Data;
            loadChart.data.datasets[2].data = load15Data;
            loadChart.update('none');
        }
    }
    
    function formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) return `${days}d ${hours}h ${mins}m`;
        if (hours > 0) return `${hours}h ${mins}m`;
        return `${mins}m`;
    }
    
})();

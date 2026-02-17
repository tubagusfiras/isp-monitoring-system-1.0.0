(function() {
    'use strict';
    console.log('🔔 Notification Bell System Loading...');
    
    // Wait for page ready
    function init() {
        // Wait for logout button to exist
        const checkReady = setInterval(() => {
            const logoutBtn = document.querySelector('button[onclick="doLogout()"]');
            if (logoutBtn) {
                clearInterval(checkReady);
                setup();
            }
        }, 100);
    }
    
    function setup() {
        createBell();
        createPanel();
        attachListeners();
        startAutoRefresh();
        console.log('✅ Notification system ready');
    }
    
    function createBell() {
        const logoutBtn = document.querySelector('button[onclick="doLogout()"]');
        
        const bellBtn = document.createElement('button');
        bellBtn.id = 'criticalBell';
        bellBtn.style.cssText = 'position:relative; padding:8px 12px; background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.2); border-radius:6px; color:white; cursor:pointer; font-size:18px; margin-right:15px; transition:0.2s;';
        bellBtn.innerHTML = '🔔 <span id="criticalBadge" style="display:none; position:absolute; top:-5px; right:-5px; background:#ef4444; color:white; border-radius:10px; padding:2px 6px; font-size:10px; font-weight:bold; min-width:18px; text-align:center;">0</span>';
        
        bellBtn.onmouseover = () => bellBtn.style.background = 'rgba(255,255,255,0.2)';
        bellBtn.onmouseout = () => bellBtn.style.background = 'rgba(255,255,255,0.1)';
        
        logoutBtn.parentElement.insertBefore(bellBtn, logoutBtn);
    }
    
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'criticalPanel';
        panel.style.cssText = 'display:none; position:fixed; top:80px; right:20px; width:350px; max-height:500px; overflow-y:auto; background:rgba(15,23,42,0.98); border:1px solid rgba(255,255,255,0.2); border-radius:8px; box-shadow:0 10px 30px rgba(0,0,0,0.5); z-index:2147483647;';
        
        panel.innerHTML = `
            <div style="padding:15px; border-bottom:1px solid rgba(255,255,255,0.1); display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0; font-size:14px; color:white; font-weight:600;">⚠️ Critical Issues</h3>
                <span id="criticalCount" style="font-size:12px; color:rgba(255,255,255,0.6);">Loading...</span>
            </div>
            <div id="criticalList" style="padding:10px; max-height:400px; overflow-y:auto;">
                <div style="text-align:center; color:rgba(255,255,255,0.5); padding:20px; font-size:13px;">
                    <div style="font-size:24px; margin-bottom:10px;">🔄</div>
                    Loading notifications...
                </div>
            </div>
        `;
        
        document.body.appendChild(panel);
    }
    
    let isOpen = false;
    
    function attachListeners() {
        // Bell click
        document.getElementById('criticalBell').addEventListener('click', (e) => {
            e.stopPropagation();
            togglePanel();
        });
        
        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!isOpen) return;
            const panel = document.getElementById('criticalPanel');
            if (!panel.contains(e.target)) {
                closePanel();
            }
        });
    }
    
    function togglePanel() {
        isOpen = !isOpen;
        const panel = document.getElementById('criticalPanel');
        panel.style.display = isOpen ? 'block' : 'none';
        
        if (isOpen) {
            loadNotifications();
        }
    }
    
    function closePanel() {
        isOpen = false;
        document.getElementById('criticalPanel').style.display = 'none';
    }
    
    async function loadNotifications() {
        try {
            const res = await fetch('/api/notifications/critical', { credentials: 'include' });
            const data = await res.json();
            
            if (!data.success) {
                showError('Failed to load notifications');
                return;
            }
            
            updateBadge(data.total || 0);
            updatePanel(data);
            
        } catch (e) {
            console.error('Notification error:', e);
            showError('Connection error');
        }
    }
    
    function updateBadge(count) {
        const badge = document.getElementById('criticalBadge');
        if (count > 0) {
            badge.style.display = 'block';
            badge.textContent = count > 99 ? '99+' : count;
        } else {
            badge.style.display = 'none';
        }
    }
    
    function updatePanel(data) {
        const count = document.getElementById('criticalCount');
        const list = document.getElementById('criticalList');
        
        const total = data.total || 0;
        count.textContent = `${total} issue${total !== 1 ? 's' : ''}`;
        
        if (total === 0) {
            list.innerHTML = `
                <div style="text-align:center; color:rgba(255,255,255,0.5); padding:30px 20px; font-size:13px;">
                    <div style="font-size:32px; margin-bottom:10px;">✅</div>
                    <div style="font-weight:500;">All Systems Healthy</div>
                    <div style="font-size:11px; margin-top:8px; opacity:0.7;">No critical issues detected</div>
                </div>
            `;
            return;
        }
        
        list.innerHTML = data.notifications.map(n => renderNotification(n)).join('');
    }
    
    function renderNotification(n) {
        const colors = {
            critical: { bg: '#ef4444', icon: '🔴' },
            warning: { bg: '#f59e0b', icon: '⚠️' }
        };
        
        const color = colors[n.severity] || colors.warning;
        
        let message = '';
        if (n.issue_type === 'device_down') {
            message = `<strong>${n.hostname}</strong> is DOWN`;
        } else if (n.issue_type === 'high_loss') {
            message = `<strong>${n.hostname}</strong>: ${n.packet_loss}% packet loss`;
        } else if (n.issue_type === 'interface_errors') {
            message = `<strong>${n.hostname}</strong> ${n.interface_name}: ${n.total_errors.toLocaleString()} errors`;
        }
        
        return `
            <div style="padding:12px; margin-bottom:8px; background:rgba(255,255,255,0.05); border-left:3px solid ${color.bg}; border-radius:4px; cursor:pointer; transition:0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.08)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
                <div style="display:flex; gap:10px; margin-bottom:6px; align-items:flex-start;">
                    <span style="font-size:14px;">${color.icon}</span>
                    <div style="flex:1;">
                        <div style="font-size:12px; color:white; line-height:1.4;">${message}</div>
                        <div style="font-size:11px; color:rgba(255,255,255,0.5); margin-top:4px;">
                            ${n.ip_address || ''} • ${formatTime(n.timestamp)}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    function formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return date.toLocaleString();
    }
    
    function showError(msg) {
        document.getElementById('criticalList').innerHTML = `
            <div style="text-align:center; color:#ef4444; padding:20px; font-size:13px;">
                ❌ ${msg}
            </div>
        `;
    }
    
    function startAutoRefresh() {
        // Initial load after 2 seconds
        setTimeout(loadNotifications, 2000);
        
        // Refresh every 2 minutes
        setInterval(() => {
            if (!isOpen) {
                loadNotifications();
            }
        }, 120000);
    }
    
    // Start
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
})();

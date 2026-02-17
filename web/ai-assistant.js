(function() {
    'use strict';

    // Auto-delete after 2 hours idle
    const IDLE_TIMEOUT = 2 * 60 * 60 * 1000; // 2 hours
    let idleTimer = null;
    let messages = [];
    let isTyping = false;

    window.initAIAssistant = function() {
        console.log('🤖 Initializing AI Assistant...');
        loadMessages();
        renderMessages();
        startIdleTimer();
        console.log('✅ AI Assistant ready');
    };

    // =====================
    // MESSAGE MANAGEMENT
    // =====================
    function loadMessages() {
        try {
            const stored = localStorage.getItem('ai_messages');
            const lastActivity = localStorage.getItem('ai_last_activity');

            if (stored && lastActivity) {
                const idleTime = Date.now() - parseInt(lastActivity);
                if (idleTime > IDLE_TIMEOUT) {
                    clearMessages();
                    console.log('🗑️ Messages cleared due to 2h idle');
                } else {
                    messages = JSON.parse(stored);
                }
            }
        } catch (e) {
            messages = [];
        }
    }

    function saveMessages() {
        try {
            localStorage.setItem('ai_messages', JSON.stringify(messages));
            localStorage.setItem('ai_last_activity', Date.now().toString());
        } catch (e) {
            console.error('Failed to save messages:', e);
        }
    }

    function clearMessages() {
        messages = [];
        localStorage.removeItem('ai_messages');
        localStorage.removeItem('ai_last_activity');
    }

    function startIdleTimer() {
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            clearMessages();
            renderMessages();
            console.log('🗑️ Auto-cleared after 2h idle');
        }, IDLE_TIMEOUT);
    }

    function resetIdleTimer() {
        startIdleTimer();
        localStorage.setItem('ai_last_activity', Date.now().toString());
    }

    // =====================
    // RENDER UI
    // =====================
    function renderMessages() {
        const container = document.getElementById('aiMessages');
        if (!container) return;

        if (messages.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: rgba(255,255,255,0.4);">
                    <div style="font-size: 60px; margin-bottom: 20px;">🤖</div>
                    <div style="font-size: 18px; font-weight: 600; margin-bottom: 10px; color: rgba(255,255,255,0.7);">AI Network Assistant</div>
                    <div style="font-size: 14px; margin-bottom: 30px;">Tanyakan tentang status jaringan, device, anomali, atau performa network Anda.</div>
                    
                    <div style="display: flex; flex-wrap: wrap; gap: 10px; justify-content: center;">
                        ${getSuggestedPrompts().map(p => `
                            <button onclick="window.sendSuggestedPrompt('${p.replace(/'/g, "\\'")}')"
                                style="padding: 10px 16px; background: rgba(59,130,246,0.2); border: 1px solid rgba(59,130,246,0.4); border-radius: 20px; color: #93c5fd; cursor: pointer; font-size: 13px; transition: 0.2s;"
                                onmouseover="this.style.background='rgba(59,130,246,0.4)'"
                                onmouseout="this.style.background='rgba(59,130,246,0.2)'"
                            >${p}</button>
                        `).join('')}
                    </div>
                </div>
            `;
            return;
        }

        container.innerHTML = messages.map(m => renderMessage(m)).join('');
        container.scrollTop = container.scrollHeight;
    }

    function renderMessage(msg) {
        const isUser = msg.role === 'user';
        const time = new Date(msg.timestamp).toLocaleTimeString('id-ID', {hour: '2-digit', minute: '2-digit'});

        if (isUser) {
            return `
                <div style="display: flex; justify-content: flex-end; margin-bottom: 16px;">
                    <div style="max-width: 70%;">
                        <div style="background: linear-gradient(135deg, #3b82f6, #2563eb); padding: 12px 16px; border-radius: 16px 16px 4px 16px; color: white; font-size: 14px; line-height: 1.5;">
                            ${escapeHtml(msg.content)}
                        </div>
                        <div style="text-align: right; font-size: 11px; color: rgba(255,255,255,0.4); margin-top: 4px;">${time}</div>
                    </div>
                </div>
            `;
        } else {
            return `
                <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                    <div style="width: 36px; height: 36px; background: linear-gradient(135deg, #10b981, #059669); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0;">🤖</div>
                    <div style="max-width: 75%;">
                        <div style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.1); padding: 12px 16px; border-radius: 4px 16px 16px 16px; color: rgba(255,255,255,0.9); font-size: 14px; line-height: 1.6;">
                            ${formatAIResponse(msg.content)}
                        </div>
                        <div style="font-size: 11px; color: rgba(255,255,255,0.4); margin-top: 4px;">${time}</div>
                    </div>
                </div>
            `;
        }
    }

    function showTypingIndicator() {
        const container = document.getElementById('aiMessages');
        if (!container) return;

        const typing = document.createElement('div');
        typing.id = 'typingIndicator';
        typing.style.cssText = 'display: flex; gap: 12px; margin-bottom: 16px;';
        typing.innerHTML = `
            <div style="width: 36px; height: 36px; background: linear-gradient(135deg, #10b981, #059669); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0;">🤖</div>
            <div style="background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.1); padding: 12px 16px; border-radius: 4px 16px 16px 16px;">
                <div style="display: flex; gap: 4px; align-items: center;">
                    <div style="width: 8px; height: 8px; background: rgba(255,255,255,0.5); border-radius: 50%; animation: bounce 1.2s infinite;"></div>
                    <div style="width: 8px; height: 8px; background: rgba(255,255,255,0.5); border-radius: 50%; animation: bounce 1.2s infinite 0.2s;"></div>
                    <div style="width: 8px; height: 8px; background: rgba(255,255,255,0.5); border-radius: 50%; animation: bounce 1.2s infinite 0.4s;"></div>
                </div>
            </div>
        `;

        container.appendChild(typing);
        container.scrollTop = container.scrollHeight;
    }

    function removeTypingIndicator() {
        const typing = document.getElementById('typingIndicator');
        if (typing) typing.remove();
    }

    // =====================
    // SEND MESSAGE
    // =====================
    window.sendAIMessage = async function() {
        const input = document.getElementById('aiInput');
        const message = input.value.trim();

        if (!message || isTyping) return;

        // Add user message
        messages.push({
            role: 'user',
            content: message,
            timestamp: Date.now()
        });

        input.value = '';
        isTyping = true;
        updateSendBtn(true);
        renderMessages();
        showTypingIndicator();
        resetIdleTimer();

        try {
            const res = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    message,
                    history: messages.slice(-10) // Last 10 messages for context
                })
            });

            const data = await res.json();
            removeTypingIndicator();

            if (data.success) {
                messages.push({
                    role: 'assistant',
                    content: data.reply,
                    timestamp: Date.now()
                });
                saveMessages();
                renderMessages();
            } else {
                showError(data.error || 'Terjadi kesalahan');
            }

        } catch (e) {
            removeTypingIndicator();
            showError('Koneksi error - coba lagi');
            console.error('AI chat error:', e);
        }

        isTyping = false;
        updateSendBtn(false);
    };

    window.sendSuggestedPrompt = function(prompt) {
        const input = document.getElementById('aiInput');
        if (input) {
            input.value = prompt;
            window.sendAIMessage();
        }
    };

    window.clearAIChat = function() {
        if (confirm('Hapus semua percakapan?')) {
            clearMessages();
            renderMessages();
        }
    };

    function updateSendBtn(loading) {
        const btn = document.getElementById('aiSendBtn');
        if (btn) {
            btn.disabled = loading;
            btn.innerHTML = loading ? '⏳' : '➤';
            btn.style.opacity = loading ? '0.6' : '1';
        }
    }

    function showError(msg) {
        messages.push({
            role: 'assistant',
            content: `❌ Error: ${msg}`,
            timestamp: Date.now()
        });
        renderMessages();
    }

    // =====================
    // HELPERS
    // =====================
    function getSuggestedPrompts() {
        return [
            'Bagaimana status jaringan saat ini?',
            'Device mana yang bermasalah?',
            'Tampilkan anomali aktif',
            'Berapa rata-rata latency jaringan?',
            'Device mana yang memiliki packet loss tinggi?',
        ];
    }

    function formatAIResponse(text) {
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/\n/g, '<br>');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
    }

    // Handle Enter key
    window.aiHandleKeyPress = function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            window.sendAIMessage();
        }
    };

    // Add bounce animation style
    const style = document.createElement('style');
    style.textContent = `
        @keyframes bounce {
            0%, 60%, 100% { transform: translateY(0); }
            30% { transform: translateY(-6px); }
        }
    `;
    document.head.appendChild(style);

})();

/* =========================================================
   PCAP Analyzer — Frontend Logic (Enhanced)
   ========================================================= */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// Sections
const uploadSection = $('#upload-section');
const loadingSection = $('#loading-section');
const resultsSection = $('#results-section');

// Upload elements
const uploadZone = $('#upload-zone');
const fileInput = $('#file-input');
const btnBrowse = $('#btn-browse');
const loaderFilename = $('#loader-filename');

// Results
let currentResults = null;
let analysisId = null;

// ──────────────────────────────────────────────────────────
// Printable-only flag filter (defense in depth — backend
// already filters, but double-check on frontend)
// ──────────────────────────────────────────────────────────
function isPrintable(str) {
    if (!str) return false;
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        // Allow printable ASCII (space=32 through tilde=126) plus common whitespace
        if (code < 32 || code > 126) {
            // Allow tab, newline, carriage return
            if (code !== 9 && code !== 10 && code !== 13) {
                return false;
            }
        }
    }
    return true;
}

function filterPrintableFlags(flags) {
    if (!flags) return [];
    return flags.filter(f => isPrintable(f.flag));
}

// ──────────────────────────────────────────────────────────
// Upload Handling
// ──────────────────────────────────────────────────────────
btnBrowse.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
});

uploadZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) uploadFile(e.target.files[0]);
});

// Drag and drop
uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('drag-over');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
});

async function uploadFile(file) {
    const validExts = ['.pcap', '.pcapng', '.cap'];
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!validExts.includes(ext)) {
        alert('Please upload a .pcap, .pcapng, or .cap file.');
        return;
    }

    // Show loading
    showSection('loading');
    loaderFilename.textContent = file.name;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await res.json();

        if (data.error) {
            alert('Error: ' + data.error);
            showSection('upload');
            return;
        }

        currentResults = data.results;
        analysisId = data.id;
        renderResults();
        showSection('results');
    } catch (err) {
        alert('Upload failed: ' + err.message);
        showSection('upload');
    }
}

function showSection(name) {
    uploadSection.classList.add('hidden');
    loadingSection.classList.add('hidden');
    resultsSection.classList.add('hidden');

    if (name === 'upload') uploadSection.classList.remove('hidden');
    if (name === 'loading') loadingSection.classList.remove('hidden');
    if (name === 'results') resultsSection.classList.remove('hidden');
}

// ──────────────────────────────────────────────────────────
// Tab Navigation
// ──────────────────────────────────────────────────────────
$$('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        $$('.tab').forEach(t => t.classList.remove('active'));
        $$('.tab-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        $(`#panel-${tab.dataset.tab}`).classList.add('active');
    });
});

// New analysis
$('#btn-new').addEventListener('click', () => {
    currentResults = null;
    analysisId = null;
    fileInput.value = '';
    showSection('upload');
});

// ──────────────────────────────────────────────────────────
// Render Results
// ──────────────────────────────────────────────────────────
function renderResults() {
    if (!currentResults) return;

    const r = currentResults;

    // Filter flags to printable only
    const printableFlags = filterPrintableFlags(r.flags);
    r._printableFlags = printableFlags;

    // Update counts
    $('#count-flags').textContent = printableFlags.length || 0;
    $('#count-credentials').textContent = r.credentials?.length || 0;
    $('#count-files').textContent = r.files?.length || 0;
    $('#count-dns').textContent = r.dns?.unique_domains || 0;
    $('#count-http').textContent = r.http?.total_requests || 0;
    $('#count-streams').textContent = r.streams?.length || 0;
    $('#count-strings').textContent = r.strings?.length || 0;
    $('#count-suspicious').textContent = r.suspicious?.length || 0;

    // File info bar
    renderFileInfo(r);

    // Flags banner
    renderFlagsBanner(printableFlags);

    // Panels
    renderOverview(r);
    renderFlags(printableFlags);
    renderCredentials(r.credentials);
    renderFiles(r.files);
    renderDNS(r.dns);
    renderHTTP(r.http);
    renderStreams(r.streams);
    renderStrings(r.strings);
    renderSuspicious(r.suspicious);
}

// ──────────────────────────────────────────────────────────
// File Info Bar
// ──────────────────────────────────────────────────────────
function renderFileInfo(r) {
    const s = r.summary || {};
    const items = [
        { label: 'File', value: r.filename || '—' },
        { label: 'Packets', value: s.total_packets?.toLocaleString() || '0' },
        { label: 'Size', value: formatBytes(s.total_bytes || 0) },
        { label: 'Duration', value: `${s.duration_seconds || 0}s` },
        { label: 'Avg Pkt', value: formatBytes(s.avg_packet_size || 0) },
    ];

    $('#file-info-bar').innerHTML = items.map(i => `
        <div class="file-info-item">
            <span class="file-info-label">${i.label}:</span>
            <span class="file-info-value">${i.value}</span>
        </div>
    `).join('');
}

// ──────────────────────────────────────────────────────────
// Flags Banner
// ──────────────────────────────────────────────────────────
function renderFlagsBanner(flags) {
    const banner = $('#flags-banner');
    if (!flags || flags.length === 0) {
        banner.classList.add('hidden');
        return;
    }

    banner.classList.remove('hidden');
    $('#flags-banner-list').innerHTML = flags.map(f => `
        <div class="flag-item">
            <span class="flag-value">${escapeHtml(f.flag)}</span>
            <span class="flag-source">${f.packet_num ? 'Pkt #' + f.packet_num + ' · ' : ''}${escapeHtml(f.source)}</span>
            <button class="btn-copy" onclick="copyText('${escapeHtml(f.flag).replace(/'/g, "\\\\'")}')"">Copy</button>
        </div>
    `).join('');
}

// ──────────────────────────────────────────────────────────
// Overview Panel
// ──────────────────────────────────────────────────────────
function renderOverview(r) {
    const s = r.summary || {};
    const protos = r.protocols?.protocols || [];
    const maxCount = protos.length > 0 ? protos[0].count : 1;
    const printableFlags = r._printableFlags || [];

    let html = `
        <div class="stats-grid">
            ${statCard(s.total_packets, 'Total Packets')}
            ${statCard(formatBytes(s.total_bytes || 0), 'Total Data')}
            ${statCard(`${s.duration_seconds || 0}s`, 'Duration')}
            ${statCard(printableFlags.length || 0, 'Flags Found')}
            ${statCard(r.credentials?.length || 0, 'Credentials')}
            ${statCard(r.files?.length || 0, 'Carved Files')}
            ${statCard(r.dns?.unique_domains || 0, 'DNS Domains')}
            ${statCard(r.http?.total_requests || 0, 'HTTP Requests')}
            ${statCard(r.suspicious?.length || 0, 'Suspicious')}
        </div>
    `;

    // Protocol distribution
    if (protos.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">📡</span> Protocol Distribution</div>`;
        html += protos.slice(0, 10).map(p => `
            <div class="proto-bar-container">
                <span class="proto-bar-label">${p.name}</span>
                <div class="proto-bar-track">
                    <div class="proto-bar-fill" style="width: ${(p.count / maxCount * 100).toFixed(1)}%">
                        ${p.count.toLocaleString()}
                    </div>
                </div>
            </div>
        `).join('');
        html += `</div>`;
    }

    // Top talkers
    const convos = r.top_talkers?.top_conversations || [];
    if (convos.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">🗣️</span> Top Conversations</div>`;
        html += `<table class="data-table"><thead><tr><th>Source</th><th>Destination</th><th>Packets</th></tr></thead><tbody>`;
        html += convos.slice(0, 10).map(c => `
            <tr>
                <td class="mono">${c.src}</td>
                <td class="mono">${c.dst}</td>
                <td class="mono highlight">${c.count.toLocaleString()}</td>
            </tr>
        `).join('');
        html += `</tbody></table></div>`;
    }

    // Top ports
    const ports = r.protocols?.top_ports || [];
    if (ports.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">🔌</span> Top Ports</div>`;
        html += `<table class="data-table"><thead><tr><th>Port</th><th>Packets</th><th>Service</th></tr></thead><tbody>`;
        html += ports.slice(0, 15).map(p => `
            <tr>
                <td class="mono highlight">${p.port}</td>
                <td class="mono">${p.count.toLocaleString()}</td>
                <td><span class="tag tag-blue">${guessService(p.port)}</span></td>
            </tr>
        `).join('');
        html += `</tbody></table></div>`;
    }

    $('#panel-overview').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Flags Panel
// ──────────────────────────────────────────────────────────
function renderFlags(flags) {
    if (!flags || flags.length === 0) {
        $('#panel-flags').innerHTML = emptyState('🚩', 'No flags detected in packet data');
        return;
    }

    let html = `<div class="card"><div class="card-title"><span class="emoji">🚩</span> Detected Flags (${flags.length})</div>`;
    html += `<div class="search-bar"><input type="text" class="search-input" placeholder="Filter flags..." oninput="filterTable(this, 'flags-table')"></div>`;
    html += `<table class="data-table" id="flags-table"><thead><tr><th>Flag</th><th>Source</th><th>Packet</th><th></th></tr></thead><tbody>`;
    html += flags.map(f => {
        // Color-code by source type
        let sourceClass = 'tag-green';
        if (f.source.includes('base64')) sourceClass = 'tag-purple';
        else if (f.source.includes('dns')) sourceClass = 'tag-blue';
        else if (f.source.includes('icmp')) sourceClass = 'tag-orange';
        else if (f.source.includes('rot13') || f.source.includes('xor')) sourceClass = 'tag-yellow';
        else if (f.source.includes('udp')) sourceClass = 'tag-red';

        return `
        <tr>
            <td class="mono highlight" style="word-break:break-all">${escapeHtml(f.flag)}</td>
            <td><span class="tag ${sourceClass}">${escapeHtml(f.source)}</span></td>
            <td class="mono">${f.packet_num ? '#' + f.packet_num : '—'}</td>
            <td><button class="btn-copy" onclick="copyText(\`${escapeHtml(f.flag).replace(/`/g, '\\`')}\`)">Copy</button></td>
        </tr>
    `}).join('');
    html += `</tbody></table></div>`;

    $('#panel-flags').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Credentials Panel
// ──────────────────────────────────────────────────────────
function renderCredentials(creds) {
    if (!creds || creds.length === 0) {
        $('#panel-credentials').innerHTML = emptyState('🔑', 'No credentials detected');
        return;
    }

    let html = `<div class="card"><div class="card-title"><span class="emoji">🔑</span> Extracted Credentials (${creds.length})</div>`;
    html += `<table class="data-table"><thead><tr><th>Type</th><th>Value</th><th>Packet</th></tr></thead><tbody>`;
    html += creds.map(c => `
        <tr>
            <td><span class="tag tag-red">${escapeHtml(c.type)}</span></td>
            <td class="mono" style="word-break:break-all">${escapeHtml(c.value)}</td>
            <td class="mono">#${c.packet_num}</td>
        </tr>
    `).join('');
    html += `</tbody></table></div>`;

    $('#panel-credentials').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Files Panel
// ──────────────────────────────────────────────────────────
function renderFiles(files) {
    if (!files || files.length === 0) {
        $('#panel-files').innerHTML = emptyState('📁', 'No files carved from packet data');
        return;
    }

    let html = `<div class="card"><div class="card-title"><span class="emoji">📁</span> Carved Files (${files.length})</div>`;
    html += `<table class="data-table"><thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>Stream</th><th></th></tr></thead><tbody>`;
    html += files.map(f => `
        <tr>
            <td class="mono">${escapeHtml(f.filename)}</td>
            <td><span class="tag tag-purple">${escapeHtml(f.type)}</span></td>
            <td class="mono">${formatBytes(f.size)}</td>
            <td class="mono" style="font-size:0.7rem">${escapeHtml(f.stream).substring(0, 40)}</td>
            <td><a href="/api/files/${analysisId}/${f.filename}" class="btn-download" download>Download</a></td>
        </tr>
    `).join('');
    html += `</tbody></table></div>`;

    $('#panel-files').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// DNS Panel
// ──────────────────────────────────────────────────────────
function renderDNS(dns) {
    if (!dns) {
        $('#panel-dns').innerHTML = emptyState('🌐', 'No DNS traffic found');
        return;
    }

    let html = '';

    // DNS Exfiltration Reconstructed Data
    if (dns.exfil_reconstructed) {
        html += `<div class="card" style="border-color: var(--accent);">
            <div class="card-title"><span class="emoji">🔓</span> DNS Exfiltration Reconstructed</div>
            <div class="preview-box" style="color:var(--accent);font-size:0.9rem;font-weight:600">${escapeHtml(dns.exfil_reconstructed)}</div>
        </div>`;
    }

    // Exfiltration warnings
    if (dns.exfiltration_suspects?.length > 0) {
        html += `<div class="card" style="border-color: var(--red);">
            <div class="card-title"><span class="emoji">🚨</span> DNS Exfiltration Suspects</div>`;
        html += dns.exfiltration_suspects.map(e => `
            <div style="margin-bottom:6px">
                <span class="mono highlight" style="color:var(--red)">${escapeHtml(e.domain)}</span>
                — <span class="mono">${e.query_count} queries</span>
            </div>
        `).join('');
        html += `</div>`;
    }

    // Long subdomain labels
    if (dns.long_subdomain_labels?.length > 0) {
        html += `<div class="card" style="border-color: var(--yellow);">
            <div class="card-title"><span class="emoji">⚠️</span> Suspiciously Long Subdomain Labels</div>`;
        html += dns.long_subdomain_labels.map(l => `
            <div style="margin-bottom:6px">
                <span class="mono" style="word-break:break-all">${escapeHtml(l.query)}</span>
                <span class="tag tag-yellow">${l.length} chars</span>
            </div>
        `).join('');
        html += `</div>`;
    }

    // Queries
    const queries = dns.queries || [];
    if (queries.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">🔍</span> DNS Queries (${queries.length})</div>`;
        html += `<div class="search-bar"><input type="text" class="search-input" placeholder="Filter DNS queries..." oninput="filterTable(this, 'dns-table')"></div>`;
        html += `<table class="data-table" id="dns-table"><thead><tr><th>Domain</th><th>Type</th><th>Packet</th></tr></thead><tbody>`;
        html += queries.map(q => `
            <tr>
                <td class="mono" style="word-break:break-all">${escapeHtml(q.name)}</td>
                <td><span class="tag tag-blue">${q.type}</span></td>
                <td class="mono">#${q.packet_num}</td>
            </tr>
        `).join('');
        html += `</tbody></table></div>`;
    }

    // Responses
    const responses = dns.responses || [];
    if (responses.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">📨</span> DNS Responses (${responses.length})</div>`;
        html += `<table class="data-table"><thead><tr><th>Name</th><th>Data</th><th>Packet</th></tr></thead><tbody>`;
        html += responses.slice(0, 100).map(r => `
            <tr>
                <td class="mono">${escapeHtml(r.name)}</td>
                <td class="mono highlight">${escapeHtml(r.data)}</td>
                <td class="mono">#${r.packet_num}</td>
            </tr>
        `).join('');
        html += `</tbody></table></div>`;
    }

    if (!html) html = emptyState('🌐', 'No DNS traffic found');
    $('#panel-dns').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// HTTP Panel
// ──────────────────────────────────────────────────────────
function renderHTTP(http) {
    if (!http || (http.total_requests === 0 && http.total_responses === 0)) {
        $('#panel-http').innerHTML = emptyState('🔗', 'No HTTP traffic found');
        return;
    }

    let html = '';

    // Requests
    const requests = http.requests || [];
    if (requests.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">📤</span> HTTP Requests (${requests.length})</div>`;
        html += `<div class="search-bar"><input type="text" class="search-input" placeholder="Filter HTTP requests..." oninput="filterTable(this, 'http-req-table')"></div>`;
        html += `<table class="data-table" id="http-req-table"><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Pkt</th><th></th></tr></thead><tbody>`;
        html += requests.map((r, idx) => {
            const methodClass = r.method === 'GET' ? 'tag-green' : r.method === 'POST' ? 'tag-orange' : 'tag-blue';
            return `
                <tr>
                    <td><span class="tag ${methodClass}">${r.method}</span></td>
                    <td class="mono" style="font-size:0.78rem">${escapeHtml(r.host)}</td>
                    <td class="mono" style="word-break:break-all;font-size:0.78rem">${escapeHtml(r.path)}</td>
                    <td class="mono">#${r.packet_num}</td>
                    <td><button class="btn-toggle" onclick="toggleDetail('http-req-${idx}')">Details</button></td>
                </tr>
                <tr id="http-req-${idx}" style="display:none">
                    <td colspan="5">
                        <div class="preview-box">${escapeHtml(formatHeaders(r.headers))}${r.body ? '\n\n--- Body ---\n' + escapeHtml(r.body) : ''}</div>
                    </td>
                </tr>
            `;
        }).join('');
        html += `</tbody></table></div>`;
    }

    // Responses
    const responses = http.responses || [];
    if (responses.length > 0) {
        html += `<div class="card"><div class="card-title"><span class="emoji">📥</span> HTTP Responses (${responses.length})</div>`;
        html += `<table class="data-table"><thead><tr><th>Status</th><th>Content-Type</th><th>Pkt</th><th></th></tr></thead><tbody>`;
        html += responses.map((r, idx) => {
            const statusClass = r.status_code < 300 ? 'tag-green' : r.status_code < 400 ? 'tag-blue' : r.status_code < 500 ? 'tag-yellow' : 'tag-red';
            return `
                <tr>
                    <td><span class="tag ${statusClass}">${r.status_code} ${escapeHtml(r.status_text)}</span></td>
                    <td class="mono" style="font-size:0.78rem">${escapeHtml(r.content_type)}</td>
                    <td class="mono">#${r.packet_num}</td>
                    <td><button class="btn-toggle" onclick="toggleDetail('http-resp-${idx}')">Details</button></td>
                </tr>
                <tr id="http-resp-${idx}" style="display:none">
                    <td colspan="4">
                        <div class="preview-box">${escapeHtml(formatHeaders(r.headers))}${r.body_preview ? '\n\n--- Body ---\n' + escapeHtml(r.body_preview) : ''}</div>
                    </td>
                </tr>
            `;
        }).join('');
        html += `</tbody></table></div>`;
    }

    $('#panel-http').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Streams Panel
// ──────────────────────────────────────────────────────────
function renderStreams(streams) {
    if (!streams || streams.length === 0) {
        $('#panel-streams').innerHTML = emptyState('🔄', 'No TCP streams reassembled');
        return;
    }

    let html = `<div class="card"><div class="card-title"><span class="emoji">🔄</span> TCP Streams (${streams.length})</div>`;
    html += streams.map((s, idx) => `
        <div class="convo-item">
            <div class="convo-header">
                <span class="mono" style="font-size:0.8rem;color:var(--accent)">${escapeHtml(s.stream)}</span>
                <span class="convo-meta">${formatBytes(s.length)} ${s.is_printable ? '' : '<span class="tag tag-yellow" style="margin-left:6px">Binary</span>'}</span>
            </div>
            <button class="btn-toggle" onclick="toggleDetail('stream-${idx}')">Show Data</button>
            <div id="stream-${idx}" style="display:none">
                <div class="preview-box">${escapeHtml(s.preview)}</div>
            </div>
        </div>
    `).join('');
    html += `</div>`;

    $('#panel-streams').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Strings Panel
// ──────────────────────────────────────────────────────────
function renderStrings(strings) {
    if (!strings || strings.length === 0) {
        $('#panel-strings').innerHTML = emptyState('📝', 'No strings extracted');
        return;
    }

    const interesting = strings.filter(s => s.interesting);
    const normal = strings.filter(s => !s.interesting);

    let html = '';

    if (interesting.length > 0) {
        html += `<div class="card" style="border-color: var(--yellow);">
            <div class="card-title"><span class="emoji">⭐</span> Interesting Strings (${interesting.length})</div>`;
        html += `<table class="data-table"><thead><tr><th>String</th><th>Pkt</th></tr></thead><tbody>`;
        html += interesting.map(s => `
            <tr>
                <td class="mono" style="word-break:break-all;color:var(--yellow)">${escapeHtml(s.string)}</td>
                <td class="mono">#${s.packet_num}</td>
            </tr>
        `).join('');
        html += `</tbody></table></div>`;
    }

    html += `<div class="card"><div class="card-title"><span class="emoji">📝</span> All Strings (${strings.length})</div>`;
    html += `<div class="search-bar"><input type="text" class="search-input" placeholder="Filter strings..." oninput="filterTable(this, 'strings-table')"></div>`;
    html += `<table class="data-table" id="strings-table"><thead><tr><th>String</th><th>Pkt</th><th></th></tr></thead><tbody>`;
    html += strings.slice(0, 300).map(s => `
        <tr>
            <td class="mono" style="word-break:break-all;${s.interesting ? 'color:var(--yellow)' : ''}">${escapeHtml(s.string)}</td>
            <td class="mono">#${s.packet_num}</td>
            <td>${s.interesting ? '<span class="badge-interesting">Interesting</span>' : ''}</td>
        </tr>
    `).join('');
    html += `</tbody></table></div>`;

    $('#panel-strings').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Suspicious Panel
// ──────────────────────────────────────────────────────────
function renderSuspicious(suspicious) {
    if (!suspicious || suspicious.length === 0) {
        $('#panel-suspicious').innerHTML = emptyState('⚠️', 'No suspicious activity detected');
        return;
    }

    let html = `<div class="card"><div class="card-title"><span class="emoji">⚠️</span> Suspicious Activity (${suspicious.length})</div>`;
    html += suspicious.map((s, idx) => {
        let typeClass = 'tag-red';
        if (s.type.includes('DNS')) typeClass = 'tag-yellow';
        else if (s.type.includes('ARP')) typeClass = 'tag-orange';
        else if (s.type.includes('Port')) typeClass = 'tag-purple';
        else if (s.type.includes('Shell')) typeClass = 'tag-red';

        return `
        <div class="convo-item" style="border-color: var(--red);">
            <div class="convo-header">
                <span class="tag ${typeClass}">${escapeHtml(s.type)}</span>
                ${s.packet_num ? `<span class="convo-meta">Packet #${s.packet_num}</span>` : ''}
            </div>
            <p style="font-size:0.85rem;color:var(--text-secondary);margin-top:6px">${escapeHtml(s.detail)}</p>
            ${s.data_preview ? `
                <button class="btn-toggle" onclick="toggleDetail('susp-${idx}')" style="margin-top:8px">Show Data</button>
                <div id="susp-${idx}" style="display:none">
                    <div class="preview-box">${escapeHtml(s.data_preview)}</div>
                </div>
            ` : ''}
        </div>
    `}).join('');
    html += `</div>`;

    $('#panel-suspicious').innerHTML = html;
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────
function statCard(value, label) {
    return `<div class="stat-card"><div class="stat-value">${value}</div><div class="stat-label">${label}</div></div>`;
}

function emptyState(icon, message) {
    return `<div class="empty-state"><div class="empty-icon">${icon}</div><p>${message}</p></div>`;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

function formatHeaders(headers) {
    if (!headers) return '';
    return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
}

function guessService(port) {
    const services = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9200: 'Elasticsearch',
    };
    return services[port] || 'Unknown';
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Brief visual feedback
        const btn = event.target;
        const orig = btn.textContent;
        btn.textContent = '✓ Copied';
        btn.style.color = 'var(--accent)';
        btn.style.borderColor = 'var(--accent)';
        setTimeout(() => {
            btn.textContent = orig;
            btn.style.color = '';
            btn.style.borderColor = '';
        }, 1500);
    });
}

function toggleDetail(id) {
    const el = document.getElementById(id);
    if (el) {
        el.style.display = el.style.display === 'none' ? '' : 'none';
    }
}

function filterTable(input, tableId) {
    const filter = input.value.toLowerCase();
    const table = document.getElementById(tableId);
    if (!table) return;
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? '' : 'none';
    });
}

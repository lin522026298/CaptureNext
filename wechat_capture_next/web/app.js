/* Local-only, dependency-free interface. All archive content is rendered as text. */
(() => {
  'use strict';
  const pendingRequests = new Map();
  const boot = window.__BOOTSTRAP__ || {};
  const configuredBase = boot.base ?? boot.base_url ?? '';
  const base = typeof configuredBase === 'string' && !configuredBase.includes('://') && !configuredBase.startsWith('//') ? configuredBase.replace(/\/$/, '') : '';
  const $ = (id) => document.getElementById(id);
  const names = { start_watch: '启动实时采集', stop_watch: '停止实时采集', capture: '断线补采', verify: '归档核验', validate: '独立核验', sync_wua: '同步托管 WUA', backup: '创建备份', restore: '恢复独立副本', compare: '只读比对', configure_assets: '配置附件来源', export_asset: '导出原始附件' };
  const pages = { overview: '概览', messages: '消息浏览', assets: '附件档案', backups: '备份与恢复', compare: '比对与去重', jobs: '任务日志' };
  const state = { connected: false, watching: false, busy: false, status: {}, jobs: [], page: 'overview', submitting: false, pendingWatch: false, query: '', messageOffset: 0, messageNext: null, assetOffset: 0, assetNext: null, messageRequest: 0, assetRequest: 0, exportHash: '', refreshing: false, lastStatusAt: 0 };
  const fmt = new Intl.NumberFormat('zh-CN');
  const statuses = { queued: '排队中', pending: '等待中', running: '执行中', completed: '已完成', complete: '已完成', success: '已完成', succeeded: '已完成', done: '已完成', ok: '已完成', failed: '失败', error: '错误', cancelled: '已取消', stopped: '已停止', warning: '有警告', idle: '空闲' };
  function node(tag, className, text) { const el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = String(text); return el; }
  function setText(id, value) { const el=$(id), text=value == null ? '—' : String(value); if(el.textContent!==text) el.textContent=text; }
  function time(value) { if (!value) return '—'; const d = new Date(value); return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString('zh-CN', { hour12: false }); }
  function number(value) { return typeof value === 'number' ? fmt.format(value) : value == null ? '—' : String(value); }
  function bytes(value) { const n = Number(value); if (!Number.isFinite(n)) return '大小未知'; if (n < 1024) return `${n} B`; if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`; if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`; return `${(n / 1073741824).toFixed(2)} GB`; }
  function stringify(value) { return typeof value === 'string' ? value : JSON.stringify(value, null, 2); }
  function statusBadge(value) { const status = String(value || 'unknown'); const kind = /^(completed|complete|success|succeeded|done|ok)$/.test(status) ? 'success' : /^(failed|error)$/.test(status) ? 'failure' : /^(running|queued|pending|warning)$/.test(status) ? 'running' : ''; return node('span', `job-badge ${kind}`, statuses[status] || status); }
  function empty(container, text, error = false) { container.replaceChildren(node('p', error ? 'load-error' : 'empty-state', text)); }
  function toast(message, error = false) { const el = node('div', `toast${error ? ' error' : ''}`); el.setAttribute('role', error ? 'alert' : 'status'); el.append(node('span', '', message)); const close = node('button', '', '×'); close.type = 'button'; close.setAttribute('aria-label', '关闭通知'); close.addEventListener('click', () => el.remove()); el.append(close); $('toast-region').append(el); while ($('toast-region').children.length > 4) $('toast-region').firstChild.remove(); if (!error) window.setTimeout(() => el.remove(), 7000); }
  async function api(path, options = {}) {
    if (!boot.token) throw new Error('缺少本地会话凭据，请从本地服务提供的地址重新打开工作台。');
    const controller = new AbortController(); const timeout = window.setTimeout(() => controller.abort(), 18000);
    try {
      const response = await fetch(base + path, { ...options, credentials: 'same-origin', cache: 'no-store', signal: controller.signal, headers: { 'X-Capture-Token': boot.token, ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers } });
      let data; try { data = await response.json(); } catch { throw new Error(`服务返回了无法识别的响应（HTTP ${response.status}）。`); }
      if (!response.ok || data.error) throw new Error(stringify(data.error || data.message || `请求失败（HTTP ${response.status}）`));
      return data;
    } catch (e) { if (e.name === 'AbortError') throw new Error('本地服务响应超时。请求结果可能尚未确定，请先检查任务日志，不要重复提交。'); throw e; }
    finally { window.clearTimeout(timeout); }
  }
  function updateControls() {
    $('retry-connection').disabled = state.submitting || !!state.status.closing;
    if (state.status.closing) { document.querySelectorAll('button[type="submit"], [data-action], [data-export], #watch-toggle').forEach((button) => { button.disabled = true; }); return; }
    const workPending = state.busy || state.jobs.some((job) => /^(queued|pending|running)$/.test(job.status) && !/^(start_watch|stop_watch)$/.test(job.action));
    document.querySelectorAll('[data-action]').forEach((button) => { button.disabled = !state.connected || state.submitting || workPending; });
    document.querySelectorAll('.form-panel button[type="submit"], #asset-export button[type="submit"]').forEach((button) => { button.disabled = !state.connected || state.submitting || workPending; });
    $('watch-toggle').disabled = !state.connected || state.submitting || state.pendingWatch;
    $('watch-toggle').textContent = state.pendingWatch ? '采集控制请求处理中…' : state.watching ? '停止实时采集' : '启动实时采集';
    document.querySelectorAll('[data-export]').forEach((button) => { button.disabled = button.dataset.export !== 'available' || !state.connected || state.submitting || workPending; });
  }
  names.refresh_status = '重新核实连接';
  function summaryScope(message) {
    let hint = $('summary-snapshot-scope');
    if (!hint) { hint = node('p', 'helper-text'); hint.id = 'summary-snapshot-scope'; document.querySelector('.stat-grid').after(hint); }
    hint.textContent = message;
  }
  function applyStatus(data) {
    state.status = data; state.watching = !!data.watching; state.busy = !!data.busy; state.connected = true; state.lastStatusAt = Date.now();
    $('connection-dot').className = 'status-dot'; setText('connection-label', '本地服务已连接'); $('connection-error').hidden = true;
    $('capture-dot').className = `status-dot${state.busy ? ' paused' : state.watching ? '' : ' pending'}`;
    setText('capture-state', state.watching ? state.busy ? '采集已启用 · 任务占用中' : '实时采集已启用' : '实时采集未启用');
    setText('capture-description', state.watching ? '服务已启用采集；仅处理微信同步到本机的记录，不代表手机端已完整连接或同步。' : '启动后接续本机落盘记录；也可立即补采，不修改微信原始文件。');
    if (data.watch_error) { $('capture-dot').className='status-dot error'; setText('capture-state','持续采集存在错误 · 等待重试'); setText('capture-description','采集线程报告未完成，本机仍可能有缺口。请检查最近周期和任务结果，后续成功核对前不视为恢复。'); }
    const summary = data.summary || {}; setText('stat-messages', number(summary.active_messages)); setText('stat-versions', number(summary.versions)); setText('stat-captures', number(summary.captures)); setText('stat-assets', number(summary.assets));
    summaryScope(`统计截至 ${time(data.summary_as_of)} · 第 ${data.summary_generation ?? '未知'} 代 / 服务历元 ${data.service_epoch ?? '未知'}；${state.busy ? '后台任务中，仅显示最近完成边界，不是即时总数。' : '仅表示最近提交边界。'}周期记录独立读取，可能不在同一截面；不代表手机历史完整。`);
    const cycle = data.last_cycle || {}; setText('last-cycle-status', cycle.status ? statuses[cycle.status] || cycle.status : '尚无采集记录'); setText('last-cycle-time', time(cycle.finished));
    const errors = Number(cycle.errors_count ?? (Array.isArray(cycle.errors) ? cycle.errors.length : cycle.errors ?? 0)); setText('last-cycle-errors', cycle.status ? `${Number.isFinite(errors) ? errors : '未知'} 项错误 · 详细结论见日志` : '启动采集后更新');
    setText('output-root', data.output_root || boot.state_label || '服务未提供仓库路径'); $('busy-banner').hidden = !state.busy;
    const current = data.current_job; setText('busy-title', current ? `后台任务执行中：${typeof current === 'object' ? names[current.action] || current.action || current.id || '任务' : current}` : '后台任务执行中');
    setText('last-updated', `状态更新于 ${new Date().toLocaleTimeString('zh-CN', { hour12: false })}`); updateControls();
    if (data.closing) { setText('connection-label','正在安全关闭'); setText('capture-state','采集已停止 · 当前任务收尾'); }
    let assetScope=$('asset-scope-state');
    if(!assetScope) { assetScope=node('p','helper-text'); assetScope.id='asset-scope-state'; $('asset-results').before(assetScope); }
    const assetScan=cycle.assets;
    assetScope.textContent=!data.asset_enabled ? '附件来源未配置；未启用不等于采集完成。' : !assetScan ? '附件来源已配置，尚无本轮完整遍历结果。' : (assetScan.errors_count || assetScan.errors?.length) ? '附件扫描有错误，请查看任务与核验结果。' : assetScan.complete ? '最近一轮本机附件树遍历已结束；不代表全部附件已解码或与消息关联。' : '附件仍在分批遍历 / 验证，不限制总数量或历史范围。';
  }
  function disconnected(message) {
    ['stat-messages', 'stat-versions', 'stat-captures', 'stat-assets'].forEach((id) => setText(id, '—'));
    summaryScope('统计暂不可用；上次快照不作为当前有效统计显示。');
    state.connected = false; $('connection-dot').className = 'status-dot error'; setText('connection-label', '本地服务未连接'); $('connection-error').hidden = false; setText('connection-error-text', message); setText('capture-state', '采集状态未知'); setText('capture-description', '无法读取服务状态；不能据此判断采集是否仍在运行。恢复连接后会自动更新。'); $('capture-dot').className = 'status-dot error'; updateControls();
  }
  async function refresh() {
    if (state.refreshing) return; state.refreshing = true;
    try { const data = await api('/api/status'); applyStatus(data); await loadJobs(true); }
    catch (e) { disconnected(e.message); }
    finally { state.refreshing = false; }
  }
  async function queue(action, params = {}) {
    if (state.submitting || state.status.closing || (!state.connected && action !== 'refresh_status')) return null;
    state.submitting = true; updateControls();
    const key = JSON.stringify({ action, ...params });
    const requestId = pendingRequests.get(key) || (window.crypto?.randomUUID ? window.crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`);
    pendingRequests.set(key, requestId);
    try { const result = await api('/api/jobs', { method: 'POST', body: JSON.stringify({ action, ...params, request_id: requestId }) }); pendingRequests.delete(key); if (action === 'start_watch' || action === 'stop_watch') state.pendingWatch = true; toast(`${names[action] || action}已排队。任务 ${result.id || '已提交'}；请在任务日志查看结果。`); await loadJobs(true); return result; }
    catch (e) { toast(e.message, true); return null; }
    finally { state.submitting = false; updateControls(); void refresh(); }
  }
  function jobRow(job, compact) {
    if (compact) { const row = node('div', 'activity-row'); row.append(node('span', 'activity-icon', '↗')); const info = node('div', 'activity-info'); info.append(node('strong', '', names[job.action] || job.action || '任务'), node('small', '', `任务 ${job.id || '—'}`)); const created = node('time', '', time(job.created)); row.append(info, created, statusBadge(job.status)); return row; }
    const row = node('article', 'record-row'); const top = node('div', 'record-top'); top.append(node('strong', '', names[job.action] || job.action || '任务'), statusBadge(job.status)); row.append(top, node('p', 'record-meta', `任务 ${job.id || '—'} · 创建 ${time(job.created)} · 完成 ${time(job.finished)}`));
    if (job.error) row.append(node('p', 'record-error', stringify(job.error)));
    if (job.result != null) { const detail = node('details', 'record-details'); detail.append(node('summary', '', '查看结果与核验结论'), node('pre', '', stringify(job.result))); row.append(detail); }
    return row;
  }
  async function loadJobs(quiet = false) {
    try {
      const data = await api('/api/jobs'); const previous = state.jobs; state.jobs = Array.isArray(data.jobs) ? data.jobs.slice(0, 100) : [];
      const newlyFinished = state.jobs.some((job) => !/^(queued|pending|running)$/.test(job.status) && previous.some((old) => old.id === job.id && /^(queued|pending|running)$/.test(old.status)));
      const active = state.jobs.filter((job) => /^(queued|pending|running)$/.test(job.status)); state.pendingWatch = active.some((job) => job.action === 'start_watch' || job.action === 'stop_watch');
      setText('running-count', active.length); $('running-count').hidden = !active.length;
      const list = $('job-results'); const signature = JSON.stringify(state.jobs);
      if (list.dataset.signature !== signature) {
        const openResults = new Set(Array.from(list.querySelectorAll('details[open]')).map((el) => el.closest('[data-job-id]')?.dataset.jobId));
        const focused = list.contains(document.activeElement) ? { id: document.activeElement.closest('[data-job-id]')?.dataset.jobId, summary: document.activeElement.tagName === 'SUMMARY' } : null;
        if (!state.jobs.length) { empty(list, '暂无任务。启动采集或创建一个核验任务后，进度会显示在这里。'); empty($('recent-jobs'), '还没有活动记录。你的第一次采集将从这里开始。'); }
        else { list.replaceChildren(...state.jobs.map((job) => { const row = jobRow(job, false); row.dataset.jobId = String(job.id || ''); if (openResults.has(row.dataset.jobId)) { const details = row.querySelector('details'); if (details) details.open = true; } return row; })); $('recent-jobs').replaceChildren(...state.jobs.slice(0, 4).map((job) => jobRow(job, true))); }
        list.dataset.signature = signature;
        if (focused?.id) {
          const row = Array.from(list.children).find((item) => item.dataset.jobId === focused.id);
          const target = focused.summary ? row?.querySelector('summary') : row;
          if (target) { if (target.tagName !== 'SUMMARY') target.tabIndex = -1; target.focus({ preventScroll: true }); }
          else $('main').focus({ preventScroll: true });
        }
      }
      updateControls();
      if (newlyFinished) { if (state.page === 'backups') void loadBackups(); if (state.page === 'compare') void loadReports(); if (state.page === 'assets') void loadAssets(); }
    } catch (e) { if (!quiet) toast(`任务列表加载失败：${e.message}`, true); empty($('job-results'), `任务列表加载失败：${e.message}`, true); empty($('recent-jobs'), '任务列表暂不可用，请稍后重试。', true); }
  }
  async function loadMessages() {
    const request = ++state.messageRequest; const offset = state.messageOffset; $('message-prev').disabled = true; $('message-next').disabled = true; empty($('message-results'), '正在读取本机归档…');
    try { const data = await api(`/api/messages?q=${encodeURIComponent(state.query)}&limit=50&offset=${offset}`); if (request !== state.messageRequest) return; const rows = Array.isArray(data.rows) ? data.rows : []; state.messageNext = data.next_offset == null ? null : Number(data.next_offset); setText('messages-count', `${number(data.total)} 条匹配消息`); setText('message-page', `第 ${Math.floor(offset / 50) + 1} 页`);
      if (!rows.length) empty($('message-results'), state.query ? '没有匹配的消息。试试其他关键词，或清空搜索。' : '归档中暂无可浏览消息。请先采集本机记录。');
      else $('message-results').replaceChildren(...rows.map((message) => { const row = node('article', 'message-row'); const meta = node('div', 'message-meta'); meta.append(node('span', 'message-sender', message.sender_id || '未知发送方'), node('span', '', `会话 ${message.conversation_id || '—'}`), node('span', 'badge', message.message_type ?? '消息'), node('time', '', time(message.event_time))); row.append(meta, node('div', 'message-body', message.body_text || '（此条消息没有文本正文）'), node('div', 'message-id', `记录标识 ${message.id || '—'}`)); return row; }));
      $('message-prev').disabled = offset === 0; $('message-next').disabled = !Number.isFinite(state.messageNext) || state.messageNext <= offset;
    } catch (e) { if (request !== state.messageRequest) return; empty($('message-results'), `消息加载失败：${e.message}`, true); setText('messages-count', '加载失败'); $('message-prev').disabled = offset === 0; }
  }
  async function loadAssets() {
    const request = ++state.assetRequest; const offset = state.assetOffset; $('asset-prev').disabled = true; $('asset-next').disabled = true; empty($('asset-results'), '正在加载附件档案…');
    try { const data = await api(`/api/assets?offset=${offset}&limit=50`); if (request !== state.assetRequest) return; const rows = Array.isArray(data.rows) ? data.rows : []; const total = Number(data.total || 0); state.assetNext = data.next_offset != null ? Number(data.next_offset) : offset + rows.length < total ? offset + rows.length : null; setText('assets-count', `${number(data.total)} 个文件`); setText('asset-page', `第 ${Math.floor(offset / 50) + 1} 页`);
      if (!rows.length) empty($('asset-results'), '暂无已归档附件。请检查来源目录并执行采集。');
      else $('asset-results').replaceChildren(...rows.map((asset) => { const row = node('article', 'file-row'); row.append(node('span', 'file-icon', '▧')); const detail = node('div', 'file-details'); detail.append(node('p', 'file-path', asset.relative_path || '未命名附件')); const meta = node('div', 'file-meta'); meta.append(node('span', 'badge', asset.decode_status === 'verified' ? '已验证解码' : '原始归档 · 解码未验证'), node('span', '', `${bytes(asset.bytes)} · SHA ${asset.file_sha || '未提供'}`)); detail.append(meta); const button = node('button', 'button small secondary', '导出副本'); button.type = 'button'; button.dataset.export = asset.file_sha ? 'available' : 'unavailable'; button.disabled = !asset.file_sha; button.addEventListener('click', () => openExport(asset)); row.append(detail, button); return row; }));
      $('asset-prev').disabled = offset === 0; $('asset-next').disabled = !Number.isFinite(state.assetNext) || state.assetNext <= offset; updateControls();
    } catch (e) { if (request !== state.assetRequest) return; empty($('asset-results'), `附件加载失败：${e.message}`, true); setText('assets-count', '加载失败'); $('asset-prev').disabled = offset === 0; }
  }
  async function loadBackups() {
    let scope=$('backup-list-scope');
    if(!scope) { scope=node('p','helper-text','列表仅核对快照清单与引用，不代表全部内容已核验；完整数据检查在备份和恢复时执行。'); scope.id='backup-list-scope'; $('backup-results').before(scope); }
    empty($('backup-results'), '正在读取快照列表…');
    try { const data = await api('/api/backups'); const snapshots = Array.isArray(data.snapshots) ? data.snapshots : []; const selected = $('restore-snapshot').value; const placeholder = node('option', '', snapshots.length ? '请选择要恢复的快照' : '暂无可恢复快照'); placeholder.value = ''; $('restore-snapshot').replaceChildren(placeholder); snapshots.forEach((snapshot) => { const option = node('option', '', `${snapshot.id} · ${time(snapshot.created)}`); option.value = String(snapshot.id); $('restore-snapshot').append(option); }); $('restore-snapshot').value = snapshots.some((s) => String(s.id) === selected) ? selected : ''; setText('backup-count', `${snapshots.length} 个快照`);
      if (data.integrity_scope === 'manifest_metadata_only') scope.textContent = '此列表仅校验所有权、清单哈希与引用元数据，未扫描备份数据块；不代表完整内容已通过核验。备份与恢复仍执行完整内容校验。';
      if (!snapshots.length) empty($('backup-results'), '还没有快照。创建第一份备份，为归档保留可恢复的底稿。');
      else $('backup-results').replaceChildren(...snapshots.map((snapshot) => { const row = node('article', 'record-row'); const top = node('div', 'record-top'); top.append(node('strong', '', snapshot.id), node('span', 'badge', snapshot.include_secrets ? '含敏感密钥' : '快照')); row.append(top, node('p', 'record-meta', `${time(snapshot.created)} · ${number(snapshot.files)} 个文件 · 逻辑大小 ${bytes(snapshot.logical_bytes)}`)); return row; }));
    } catch (e) { empty($('backup-results'), `快照加载失败：${e.message}`, true); setText('backup-count', '加载失败'); }
  }
  async function loadReports() {
    empty($('report-results'), '正在读取采集周期记录…');
    try { const data = await api('/api/reports?limit=20'); const rows = Array.isArray(data.rows) ? data.rows : []; if (!rows.length) { empty($('report-results'), '暂无采集周期记录。未执行的核验或比对不能视为已通过。'); return; } $('report-results').replaceChildren(...rows.map((report) => { const row = node('article', 'record-row'); const top = node('div', 'record-top'); top.append(node('strong', '', `${report.mode || '采集周期'} · ${report.id || '—'}`), statusBadge(report.status)); row.append(top, node('p', 'record-meta', `开始 ${time(report.started)} · 完成 ${time(report.finished)} · ${number(report.errors_count)} 项错误`)); return row; })); }
    catch (e) { empty($('report-results'), `报告加载失败：${e.message}`, true); }
  }
  function navigate() { const hash = location.hash.slice(1); state.page = Object.hasOwn(pages, hash) ? hash : 'overview'; document.querySelectorAll('.page').forEach((page) => { page.hidden = page.id !== state.page; }); document.querySelectorAll('.nav-link').forEach((link) => { const active = link.hash === `#${state.page}`; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); }); setText('breadcrumb-page', pages[state.page]); document.title = `${pages[state.page]} · 本地聊天档案`; if (state.page === 'messages') void loadMessages(); if (state.page === 'assets') void loadAssets(); if (state.page === 'backups') void loadBackups(); if (state.page === 'compare') void loadReports(); if (state.page === 'jobs') void loadJobs(); }
  function openExport(asset) { state.exportHash = asset.file_sha; const filename = String(asset.relative_path || '').split(/[\\/]/).pop() || 'attachment.bin'; $('export-name').value = filename; setText('export-source', `SHA ${asset.file_sha}`); $('export-dialog').showModal(); }
  function bindForm(id, callback) { $(id).addEventListener('submit', (event) => { event.preventDefault(); if ($(id).checkValidity()) void callback(); }); }
  document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', () => void queue(button.dataset.action)));
  $('watch-toggle').addEventListener('click', () => void queue(state.watching ? 'stop_watch' : 'start_watch'));
  $('retry-connection').addEventListener('click', () => void queue('refresh_status')); $('jobs-refresh').addEventListener('click', () => void loadJobs()); $('assets-refresh').addEventListener('click', () => void loadAssets()); $('backups-refresh').addEventListener('click', () => void loadBackups()); $('reports-refresh').addEventListener('click', () => void loadReports());
  bindForm('message-search', async () => { state.query = $('message-query').value.trim(); state.messageOffset = 0; await loadMessages(); });
  $('message-prev').addEventListener('click', () => { state.messageOffset = Math.max(0, state.messageOffset - 50); void loadMessages(); }); $('message-next').addEventListener('click', () => { if (state.messageNext != null) { state.messageOffset = state.messageNext; void loadMessages(); } });
  $('asset-prev').addEventListener('click', () => { state.assetOffset = Math.max(0, state.assetOffset - 50); void loadAssets(); }); $('asset-next').addEventListener('click', () => { if (state.assetNext != null) { state.assetOffset = state.assetNext; void loadAssets(); } });
  bindForm('assets-configure', () => queue('configure_assets', { root: $('assets-root').value.trim() }));
  bindForm('backup-create', async () => { const note=$('backup-name').value.trim(); if (await queue('backup', { ...(note ? { output_name:note } : {}), include_secrets: $('include-secrets').checked })) { $('include-secrets').checked = false; } });
  bindForm('backup-restore', () => queue('restore', { snapshot_id: $('restore-snapshot').value, output_name: $('restore-name').value.trim() }));
  bindForm('compare-form', () => queue('compare', { reference_path: $('compare-reference').value.trim(), output_name: $('compare-name').value.trim() }));
  bindForm('asset-export', async () => { if (await queue('export_asset', { file_sha: state.exportHash, output_name: $('export-name').value.trim() })) $('export-dialog').close(); });
  $('export-cancel').addEventListener('click', () => $('export-dialog').close());
  document.querySelector('.skip-link').addEventListener('click', (event) => { event.preventDefault(); $('main').focus(); });
  window.addEventListener('offline', () => disconnected('浏览器当前离线；显示的是最后已知状态，采集运行情况未知。'));
  window.addEventListener('hashchange', navigate); document.addEventListener('visibilitychange', () => { if (!document.hidden) void refresh(); });
  Object.assign(statuses,{warning:'需核对 / 未完全通过',local_complete:'本机归档已完成',local_complete_assets_pending:'消息已归档 · 附件处理中',partial:'部分完成 · 有错误',interrupted:'上次运行被中断'});
  const backupLabel=document.querySelector('label[for="backup-name"]'); if(backupLabel) backupLabel.textContent='本次任务备注（可选，不改变备份目录）';
  $('backup-name').required=false;
  ['backup-name','restore-name','compare-name'].forEach((id)=>$(id).removeAttribute('pattern'));
  $('export-name').maxLength=80;
  $('backup-name').placeholder='快照统一保存在专用 CAS 仓库中';
  $('backup-name').nextElementSibling.textContent='备注可留空，不参与目录或文件路径；快照按内容生成唯一标识。';
  document.querySelector('.sensitive-note').textContent='即使不含密钥，快照仍含聊天明文与个人信息。勾选后还含明文密钥；请仅保存在自己控制的本机，并限制访问。';
  const messageScope=document.querySelector('#message-search + .helper-text'); if(messageScope) messageScope.textContent='默认按最近收录顺序浏览；分页和搜索不限制归档历史。';
  updateControls(); navigate(); void refresh(); window.setInterval(() => { if (!document.hidden) void refresh(); }, 3000);
  window.setInterval(() => { if (state.connected && Date.now() - state.lastStatusAt > 12000) disconnected('超过 12 秒未取得服务状态，当前采集状态未知；正在重新核实。'); }, 1000);
})();

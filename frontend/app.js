const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = (name) => `<i data-lucide="${esc(name)}"></i>`;
const state = { view: 'incidents', incidents: [], sources: [], selectedId: null, selected: null, tab: 'diagnosis', loading: false, detailSignature: '', busy: false, grouping: null };
const severityNames = { critical: '严重', error: '错误', warning: '警告', info: '信息' };
const statusNames = { new: '已接入', diagnosing: '诊断中', awaiting_confirmation: '待确认', acknowledged: '已确认', resolved: '已解决', failed: '诊断失败' };
const sourceNames = { auto: '自动识别', server: 'Linux', nginx: 'Nginx', docker: 'Docker', kubernetes: 'Kubernetes', k8s: 'Kubernetes', mixed: '混合日志', unknown: '未知来源' };
const toolNames = { parse_logs: '解析异常日志', retrieve_knowledge: '检索故障知识', reason: '验证故障假设', finish: '生成诊断结论', collect_context: '采集故障上下文', verify: '验证故障证据', inspect_history: '检索历史故障', verify_recovery: '验证恢复状态', fetch_metrics: '查询监控指标', fetch_changes: '查询发布变更', fetch_topology: '查询服务依赖', ingest_alert: '接入告警', diagnose: '自动诊断', create_incident: '创建事件', update_incident: '更新事件', scan_source: '采集日志', create_source: '接入数据源', update_source: '更新数据源', delete_source: '删除数据源', followup: '补充诊断', acknowledge: '确认方案', resolve: '记录解决', rediagnose: '重新诊断', alert_received: '异常告警已聚合', incident_created: '发现故障事件', diagnosis_started: '开始自动诊断', diagnosis_completed: '自动诊断完成', diagnosis_failed: '诊断失败', status_changed: '人工更新事件', context_added: '收到补充信息', recovery_verified: '检查恢复状态', incidents_merged: '人工合并事件', incident_split: '人工拆分事件' };

function icons() { if (window.lucide) window.lucide.createIcons(); }
function items(data) { return Array.isArray(data) ? data : data?.items || []; }
function readToken() { try { return sessionStorage.getItem('sre-access-token') || ''; } catch { return ''; } }
function storeToken(value) { try { value ? sessionStorage.setItem('sre-access-token', value) : sessionStorage.removeItem('sre-access-token'); } catch { throw new Error('浏览器未允许保存访问凭据。'); } }
function time(value, full = false) {
  if (!value) return '尚未采集';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('zh-CN', full ? { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false } : { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}
function severity(value) { return `<span class="severity-label ${esc(value)}"><span class="metric-dot"></span>${esc(severityNames[value] || value || '信息')}</span>`; }
function status(value) { return `<span class="state-label ${esc(value)}">${esc(statusNames[value] || value || '待处理')}</span>`; }
function shortId(value) { return String(value || '').replaceAll('-', '').slice(0, 8).toUpperCase(); }
function diagnosis(incident) { return incident?.diagnosis || null; }
function incidentTitle(incident) { return diagnosis(incident)?.summary || incident.title || incident.failure_type || '待诊断故障事件'; }
function detailTab(key, label) { return `<button type="button" role="tab" aria-label="${esc(label)}" aria-selected="${state.tab === key}" aria-controls="detail-panel" class="${state.tab === key ? 'active' : ''}" data-detail-tab="${esc(key)}">${esc(label)}</button>`; }
function errorMessage(detail) {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((item) => `${(item.loc || []).filter((part) => part !== 'body').join('.')}: ${item.msg}`).join('；');
  return detail?.message || '请求失败，请稍后重试。';
}
async function api(path, options = {}) {
  const token = readToken();
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers } });
  const type = response.headers.get('content-type') || '';
  const data = type.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(errorMessage(typeof data === 'object' ? data.detail || data : data));
  return data;
}
function toast(message, error = false) {
  $('toast').textContent = message;
  $('toast').classList.toggle('error', error);
  $('toast').classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => $('toast').classList.add('hidden'), error ? 7000 : 4000);
}
function globalError(message = '') { $('global-error').textContent = message; $('global-error').classList.toggle('hidden', !message); }
function sourceForm() { $('source-form').reset(); $('source-form-error').textContent = ''; $('source-dialog').showModal(); }

async function health() {
  try {
    const data = await api('/api/health');
    const ok = data.status === 'ok';
    document.querySelector('.demo-band').classList.toggle('hidden', data.demo_enabled === false);
    $('health').innerHTML = `<span class="status-dot ${ok ? '' : 'error'}"></span>${ok ? '服务在线' : data.status === 'degraded' ? '后台异常' : '配置异常'}`;
    $('health').className = `health ${ok ? 'ok' : 'error'}`;
    $('health').title = monitorErrors(data.monitor) || (ok ? '服务在线' : data.status === 'degraded' ? '后台监控或诊断任务异常' : '服务配置异常');
    $('agent-mode').textContent = data.mode === 'llm' ? 'LLM 推理模式' : '本地诊断 · 已连接';
  } catch { $('health').innerHTML = '<span class="status-dot error"></span>服务离线'; $('health').className = 'health error'; $('health').title = '无法连接诊断服务'; $('agent-mode').textContent = '服务连接失败'; }
}
async function overview() {
  const data = await api('/api/overview');
  const metrics = data.metrics || {};
  $('metric-active').textContent = metrics.active_incidents ?? 0;
  $('metric-diagnosed').textContent = metrics.diagnosed_incidents ?? 0;
  $('metric-alerts').textContent = metrics.original_alerts ?? 0;
  $('metric-sources').textContent = metrics.enabled_sources ?? 0;
  $('metric-aggregation').textContent = `聚合为 ${metrics.total_incidents ?? 0} 个事件`;
  $('metric-source-health').textContent = metrics.unhealthy_sources ? `${metrics.unhealthy_sources} 个采集异常` : metrics.enabled_sources ? '采集状态正常' : '暂无在线数据源';
  $('nav-active-count').textContent = metrics.active_incidents ?? 0;
  $('nav-source-count').textContent = metrics.enabled_sources ?? 0;
  const running = data.monitor?.running;
  const errors = monitorErrors(data.monitor);
  const abnormal = Boolean(errors) || data.monitor?.status === 'degraded';
  $('monitor-dot').className = `status-dot ${abnormal ? 'error' : running ? '' : 'offline'}`;
  $('monitor-status').textContent = abnormal ? '监控异常' : running ? '持续监控中' : '监控已暂停';
  $('monitor-status').title = errors;
  $('last-updated').textContent = `更新于 ${time(new Date().toISOString())}`;
}
function monitorErrors(monitor) {
  return (monitor?.errors || []).map((item) => typeof item === 'string' ? item : `${{ log_monitor: '日志监控', diagnosis_worker: '诊断任务' }[item.task] || item.task}：${item.error}`).join('；');
}
function filters() {
  const environment = $('environment-filter').value;
  const environments = [...new Set(state.incidents.map((item) => item.environment).filter(Boolean))].sort();
  $('environment-filter').innerHTML = '<option value="">全部环境</option>' + environments.map((value) => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
  $('environment-filter').value = environments.includes(environment) ? environment : '';
}
function filteredIncidents() {
  const query = $('incident-search').value.trim().toLowerCase();
  return state.incidents.filter((item) => {
    const currentStatus = $('status-filter').value;
    return (!query || [incidentTitle(item), item.id, item.service, item.instance, item.failure_type].some((value) => String(value || '').toLowerCase().includes(query))) &&
      (!$('environment-filter').value || item.environment === $('environment-filter').value) &&
      (!$('severity-filter').value || item.severity === $('severity-filter').value) &&
      (!currentStatus || (currentStatus === 'active' ? item.status !== 'resolved' : item.status === currentStatus));
  });
}
function renderIncidentRows() {
  const current = filteredIncidents();
  $('incident-count').textContent = `${current.length} 个事件`;
  $('incident-rows').innerHTML = current.length ? current.map((item) => `<tr data-incident="${esc(item.id)}" class="${item.id === state.selectedId ? 'selected' : ''}" tabindex="0" aria-label="查看 ${esc(incidentTitle(item))}"><td>${severity(item.severity)}</td><td><span class="event-title">${esc(incidentTitle(item))}</span><span class="event-meta"><span>${esc(item.service || '未知服务')}</span><span>·</span><span>${esc(item.environment || '未标记环境')}</span>${item.is_demo ? '<span class="demo-label">演示</span>' : ''}</span></td><td>${status(item.status)}</td><td class="count-cell">${esc(item.occurrences ?? 1)}</td><td class="time-cell">${esc(time(item.last_seen || item.updated_at || item.first_seen))}<small>${esc(sourceNames[item.source] || item.source || '')}</small></td></tr>`).join('') : `<tr><td colspan="5" class="table-empty"><span class="empty-icon">${icon('check-check')}</span><strong>${state.incidents.length ? '没有符合条件的事件' : '暂无故障事件'}</strong><p>${state.incidents.length ? '调整筛选条件后重试' : '数据源正在等待新日志'}</p></td></tr>`;
  $('list-status').textContent = `共 ${state.incidents.length} 个事件 · ${current.length} 个符合筛选`;
  icons();
}
async function loadIncidents() {
  state.incidents = items(await api('/api/incidents?limit=200'));
  filters();
  renderIncidentRows();
  const visible = filteredIncidents();
  if (!state.selectedId && visible.length) await selectIncident(visible[0].id);
  else if (state.selectedId) await refreshDetail();
}

function risk(step) {
  const value = step.risk_level || step.risk;
  if (value) return { level: /high|高/.test(value) ? 'high' : /low|read_only|readonly|只读/.test(value) ? '' : 'medium', label: { read_only: '只读建议', readonly: '只读建议', low: '低风险建议', medium: '人工执行', high: '高风险建议', manual: '人工执行' }[value] || value };
  const command = step.command || '';
  if (!command) return { level: '', label: '人工排查' };
  if (/\b(rm|delete|drop|truncate|prune|kill|format)\b|restart|rollout|apply|patch|set |reload|systemctl (start|stop)|nginx -s/i.test(command)) return { level: 'high', label: '人工执行' };
  if (/\b(get|describe|logs|top|inspect|stats|ps|events|df|du|free|uptime|journalctl|ss|cat|tail|head|status|version|curl)\b/i.test(command)) return { level: '', label: '只读建议' };
  return { level: 'medium', label: '人工执行' };
}
function stepsHtml(data) {
  return (data.steps || []).length ? `<ol class="steps">${data.steps.map((step, index) => {
    const level = risk(step);
    return `<li class="step"><span class="step-number">${index + 1}</span><div><div class="step-heading">${esc(step.title)}<span class="risk-label ${level.level}">${esc(level.label)}</span></div><p class="step-description">${esc(step.description)}</p>${step.command ? `<div class="command-line"><code>${esc(step.command)}</code><button class="icon-button" data-copy="${esc(step.command)}" title="复制命令" aria-label="复制命令">${icon('copy')}</button></div>` : ''}${step.expected_result ? `<p class="expected">验证：${esc(step.expected_result)}</p>` : ''}</div></li>`;
  }).join('')}</ol>` : '<p class="muted">尚未生成排查方案</p>';
}
function evidenceHtml(data) {
  const evidence = data.evidence || [];
  return evidence.length ? `<div class="evidence-list">${evidence.map((item) => `<div class="evidence-line"><b>${item.line_number ? `L${esc(item.line_number)}` : esc(item.type || '证据')}</b><span>${esc(item.message || item.value || item.summary)}</span></div>`).join('')}</div>` : '<p class="muted">当前缺少可定位根因的日志证据</p>';
}
function sourceLinks(item) {
  const urls = item.source_urls || item.references || (item.source_url ? [item.source_url] : []);
  return `<div class="reference-links">${urls.map((reference, index) => {
    const url = typeof reference === 'string' ? reference : reference.url;
    if (/^\/api\/incidents\/[a-zA-Z0-9-]+(?:\/export)?$/.test(url || '')) return `<a href="${esc(url)}" data-incident-reference="${esc(url)}">${esc(reference.title || `事件来源 ${index + 1}`)}${icon('arrow-up-right')}</a>`;
    return /^https?:\/\//i.test(url || '') ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(reference.title || `参考来源 ${index + 1}`)}${icon('arrow-up-right')}</a>` : '';
  }).join('')}</div>`;
}
function referenceMeta(item) {
  const trust = { official: '官方文档', reviewed: '人工复核', personal: '个人经验', unverified: '待复核', internal: '内部手册', curated_runbook: '已整理处置手册', human_reviewed: '人工复核案例' }[item.trust_level] || item.trust_level || '内置运维手册';
  return `<div class="reference-meta">${esc(trust)} · ${esc(item.id)}${item.updated_at ? ` · ${esc(time(item.updated_at, true))}` : ''}${item.score != null && item.score > 0 ? ` · 相关度 ${Math.round(item.score * 100)}%` : ''}</div>${sourceLinks(item)}`;
}
function knowledgeHtml(data) {
  return (data.knowledge || []).map((item) => `<details class="knowledge-reference"><summary>${icon('book-open')}${esc(item.title)}</summary><p>${esc(item.excerpt || item.summary)}</p>${referenceMeta(item)}</details>`).join('') || '<p class="muted">尚无匹配的知识条目</p>';
}
function missingContext(incident, data) {
  const values = data.missing_information || data.missing_context || incident.missing_information || [];
  const parts = Array.isArray(values) ? values.map((item) => typeof item === 'string' ? item : item.description || item.name || JSON.stringify(item)) : [String(values)];
  if (data.uncertainty) parts.unshift(String(data.uncertainty));
  if (data.boundary) parts.unshift(String(data.boundary));
  if (incident.fallback_reason) parts.unshift(`诊断已降级：${incident.fallback_reason}`);
  return parts.filter(Boolean);
}
function diagnosisHtml(incident) {
  const data = diagnosis(incident);
  if (!data) return `<div class="detail-section"><div class="section-heading"><h3>${icon('scan-line')}诊断进展</h3></div><p class="root-cause">${incident.status === 'failed' ? esc(incident.diagnosis_error || '诊断失败，请重新诊断或补充上下文。') : '正在采集上下文并分析故障证据。'}</p></div>${timelineHtml(incident.timeline || [])}`;
  const confidence = Math.round((data.confidence || 0) * 100);
  const missing = missingContext(incident, data);
  const impact = data.impact_scope || incident.impact_scope;
  const impactNames = { service: '服务', environment: '环境', instance: '实例', affected_users: '受影响用户', affected_interfaces: '受影响接口', affected_endpoints: '受影响接口', users: '用户量级', log_source: '日志来源' };
  const impactText = typeof impact === 'string' ? impact : impact ? Object.entries(impact).map(([name, value]) => `${impactNames[name] || name}：${value == null || value === '' ? '未知' : name === 'log_source' ? sourceNames[value] || value : value}`).join(' · ') : '';
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('git-branch')}根因判断</h3><span class="confidence ${confidence < 65 ? 'low' : ''}">置信度 ${confidence}%</span></div><p class="root-cause">${esc(data.root_cause || '证据不足，需进一步排查')}</p>${impactText ? `<p class="step-description">影响范围：${esc(impactText)}</p>` : ''}${missing.length ? `<div class="uncertainty">诊断边界：${missing.map(esc).join('；')}</div>` : ''}</div><div class="detail-section"><div class="section-heading"><h3>${icon('file-text')}证据日志</h3><span class="muted">${(data.evidence || []).length} 条关键证据</span></div>${evidenceHtml(data)}</div><div class="detail-section"><div class="section-heading"><h3>${icon('list-checks')}排查与处置方案</h3><span class="muted">人工确认处置</span></div>${stepsHtml(data)}</div><div class="detail-section"><div class="section-heading"><h3>${icon('book-open')}知识引用</h3><span class="muted">${(data.knowledge || []).length} 条</span></div>${knowledgeHtml(data)}</div>${incident.resolution ? `<div class="detail-section"><div class="section-heading"><h3>${icon('check-check')}解决记录</h3></div><p class="root-cause">${esc(incident.resolution)}</p></div>` : ''}`;
}
function contextItems(collection) {
  if (Array.isArray(collection)) return collection;
  if (!collection || typeof collection !== 'object') return [];
  if (Array.isArray(collection.items)) return collection.items;
  if (Array.isArray(collection.sources)) return collection.sources;
  if (Array.isArray(collection.context_sources)) return collection.context_sources;
  return Object.entries(collection).filter(([key]) => !['collected_at', 'duration_ms', 'missing_information', 'summary'].includes(key)).map(([key, value]) => ({ name: key, ...(value && typeof value === 'object' && !Array.isArray(value) ? value : { data: value }) }));
}
function contextHtml(incident) {
  const rows = contextItems(incident.context_collection || []);
  const names = { logs: '异常日志', metrics: '监控指标', changes: '近期发布变更', topology: '服务依赖拓扑', history: '历史故障', resources: '主机资源', manual: '人工补充', service: '服务信息', kubernetes: 'Kubernetes 状态' };
  const states = { ok: '已采集', success: '已采集', available: '已采集', collected: '已采集', missing: '未接入', unavailable: '不可用', error: '采集失败', failed: '采集失败', skipped: '未采集', not_configured: '未配置' };
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('network')}上下文采集</h3><span class="muted">${rows.length} 个来源</span></div>${rows.length ? rows.map((row) => {
    const content = row.summary || row.message || row.error || row.reason || row.data || row.result;
    return `<div class="context-row"><div><strong>${esc(names[row.name || row.tool || row.kind] || row.name || row.tool || row.kind || row.type || '数据源')}</strong><p>${esc(typeof content === 'object' ? JSON.stringify(content, null, 2) : content || '当前无可用数据')}</p>${row.collected_at || row.observed_at ? `<p>${esc(time(row.collected_at || row.observed_at, true))}</p>` : ''}${row.data ? `<details><summary>采集数据</summary><pre>${esc(JSON.stringify(row.data, null, 2))}</pre></details>` : ''}${row.source_url ? sourceLinks(row) : ''}</div><span class="context-state ${esc(row.status)}">${esc(states[row.status] || row.status || '未知')}</span></div>`;
  }).join('') : '<div class="uncertainty">尚无上下文采集结果</div>'}</div><div class="detail-section"><div class="section-heading"><h3>${icon('server')}影响对象</h3></div><div class="context-row"><div>服务<p>${esc(incident.service || '未提供')}</p></div><div>环境<p>${esc(incident.environment || '未提供')}</p></div></div><div class="context-row"><div>主机 / 实例<p>${esc(incident.instance || '未提供')}</p></div><div>原始告警<p>${esc(incident.occurrences ?? 1)} 次</p></div></div></div>${rawAlertsHtml(incident)}${timelineHtml(incident.timeline || [])}`;
}
function rawAlertsHtml(incident) {
  const alerts = incident.original_alerts || [];
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('layers')}原始告警</h3><span class="muted">${alerts.length} 条</span></div><div class="raw-alert-list">${alerts.length ? [...alerts].reverse().map((alert) => `<details class="raw-alert"><summary><div class="raw-alert-meta"><time>${esc(time(alert.received_at || alert.starts_at, true))}</time>${severity(alert.severity)}<span class="subtle-tag">${alert.status === 'resolved' ? '恢复通知' : '异常通知'}</span></div><span class="raw-alert-title">${esc(alert.message)}</span></summary><pre class="raw-alert-message">${esc(alert.message)}</pre><div class="reference-meta">${esc(alert.service)} · ${esc(alert.environment)} · ${esc(alert.instance)} · ${esc(alert.id)}</div></details>`).join('') : '<p class="muted">暂无原始告警记录</p>'}</div></div>`;
}
function timelineHtml(timeline) {
  if (!Array.isArray(timeline) || !timeline.length) return '';
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('clock-3')}事件时间线</h3></div>${timeline.map((item) => `<div class="trace-item"><time>${esc(time(item.timestamp || item.created_at || item.at))}</time><strong>${esc(item.title || toolNames[item.action || item.type] || item.action || item.type || '事件更新')}</strong><p>${esc(item.summary || item.description || item.message || item.detail || '')}</p></div>`).join('')}</div>`;
}
function traceHtml(incident) {
  const trace = diagnosis(incident)?.trace || [];
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('workflow')}工具调用轨迹</h3><span class="muted">${trace.length} 步</span></div>${trace.length ? trace.map((item, index) => `<div class="trace-item">${item.timestamp ? `<time>${esc(time(item.timestamp))}</time>` : ''}<strong>${index + 1}. ${esc(toolNames[item.action || item.tool] || item.action || item.tool || '工具调用')}</strong>${item.hypothesis || item.reasoning || item.thought ? `<p>${esc(item.hypothesis || item.reasoning || item.thought)}</p>` : ''}${item.expected_result ? `<p>验证目标：${esc(item.expected_result)}</p>` : ''}<p>${esc(item.observation || item.summary || '')}</p>${item.judgment ? `<p>判断：${esc(item.judgment)}</p>` : ''}${item.action_input || item.input ? `<details><summary>调用参数</summary><pre>${esc(typeof (item.action_input || item.input) === 'object' ? JSON.stringify(item.action_input || item.input, null, 2) : item.action_input || item.input)}</pre></details>` : ''}</div>`).join('') : '<p class="muted">尚无工具调用记录</p>'}</div>${timelineHtml(incident.timeline || [])}`;
}
function renderDetail(incident, force = false) {
  if (!incident) return;
  const signature = JSON.stringify(incident) + state.tab;
  if (signature === state.detailSignature && !force) return;
  const draft = document.getElementById('followup-message')?.value || '';
  if ((document.activeElement?.id === 'followup-message' || state.busy) && !force) return;
  state.detailSignature = signature;
  const data = diagnosis(incident);
  $('incident-detail').innerHTML = `<div class="detail-heading"><div class="detail-id"><span>INC-${esc(shortId(incident.id))}${incident.is_demo ? ' · 演示事件' : ''}</span><button class="icon-button" data-action="refresh-detail" title="刷新事件详情" aria-label="刷新事件详情">${icon('refresh-cw')}</button></div><h2>${esc(incidentTitle(incident))}</h2><div class="detail-meta">${severity(incident.severity)}${status(incident.status)}<span>首次发现 ${esc(time(incident.first_seen, true))}</span></div><div class="detail-tags"><span class="subtle-tag">${esc(incident.service || '未提供服务')}</span><span class="subtle-tag">${esc(incident.environment || '未提供环境')}</span><span class="subtle-tag">${esc(incident.instance || '未提供实例')}</span></div></div><div class="detail-tabs" role="tablist" aria-label="事件详情">${detailTab('diagnosis', '诊断结论')}${detailTab('context', '故障上下文')}${detailTab('trace', '工具轨迹')}</div><div class="detail-body" id="detail-panel" role="tabpanel">${state.tab === 'diagnosis' ? diagnosisHtml(incident) : state.tab === 'context' ? contextHtml(incident) : traceHtml(incident)}${incident.status !== 'resolved' ? `<form class="followup-form" id="followup-form"><label for="followup-message">补充信息 / 修正诊断</label><textarea id="followup-message" required maxlength="10000" placeholder="例如：故障只影响 node-01，今天没有发布变更">${esc(draft)}</textarea><div class="followup-footer"><button type="submit" class="button small">${icon('send')}补充并诊断</button></div><p id="followup-error" class="form-error" role="alert"></p></form>` : ''}</div><div class="detail-actions">${incident.status !== 'resolved' ? `<button class="button primary" data-action="acknowledge" ${!data || incident.status === 'acknowledged' ? 'disabled' : ''}>${icon('check')}${incident.status === 'acknowledged' ? '已确认方案' : '确认方案'}</button><button class="button" data-action="resolve" ${!data ? 'disabled' : ''}>${icon('check-check')}记录解决</button>` : ''}<button class="icon-button" data-action="rediagnose" title="重新采集并诊断" aria-label="重新采集并诊断" ${incident.status === 'diagnosing' ? 'disabled' : ''}>${icon('rotate-cw')}</button><button class="icon-button" data-action="verify" title="验证恢复状态" aria-label="验证恢复状态">${icon('shield-check')}</button><button class="icon-button export-action" data-action="export" title="导出故障复盘" aria-label="导出故障复盘">${icon('download')}</button></div>`;
  const refreshButton = $('incident-detail').querySelector('[data-action="refresh-detail"]');
  if (data && ['new', 'diagnosing'].includes(incident.status)) {
    const pendingNotice = document.createElement('div');
    pendingNotice.className = 'uncertainty';
    pendingNotice.textContent = '新一轮诊断处理中，以下为上一轮诊断记录。';
    $('detail-panel').prepend(pendingNotice);
    const acknowledgeButton = $('incident-detail').querySelector('[data-action="acknowledge"]');
    if (acknowledgeButton) acknowledgeButton.disabled = true;
  }
  const headingTools = document.createElement('div');
  headingTools.className = 'detail-heading-tools';
  refreshButton.replaceWith(headingTools);
  headingTools.innerHTML = `<button class="icon-button" data-action="merge" title="合并事件" aria-label="合并事件" ${incident.status === 'diagnosing' ? 'disabled' : ''}>${icon('combine')}</button><button class="icon-button" data-action="split" title="拆分原始告警" aria-label="拆分原始告警" ${incident.status === 'diagnosing' || (incident.original_alerts || []).length < 2 ? 'disabled' : ''}>${icon('split')}</button>`;
  headingTools.append(refreshButton);
  icons();
}
async function selectIncident(id) {
  if (state.busy) return;
  if (state.selectedId !== id) {
    state.selected = null;
    $('incident-detail').innerHTML = '<div class="empty-state">正在读取事件详情…</div>';
  }
  state.selectedId = id;
  state.tab = 'diagnosis';
  state.detailSignature = '';
  renderIncidentRows();
  await refreshDetail();
}
async function refreshDetail() {
  if (!state.selectedId) return;
  const id = state.selectedId;
  const data = await api(`/api/incidents/${encodeURIComponent(id)}`);
  if (state.selectedId !== id) return;
  state.selected = data;
  renderDetail(data);
}

function renderSources() {
  $('source-total').textContent = `${state.sources.length} 个数据源`;
  const enabled = state.sources.filter((item) => item.enabled).length;
  $('source-summary').textContent = `${enabled} 个已启用 · ${state.sources.length - enabled} 个已暂停`;
  $('source-rows').innerHTML = state.sources.length ? state.sources.map((item) => {
    const error = item.last_error;
    const running = item.enabled;
    const current = error ? 'error' : running ? '' : 'offline';
    return `<tr><td><span class="source-name">${icon('file-text')}${esc(item.name)}${item.is_demo ? '<span class="subtle-tag">演示</span>' : ''}</span><code class="source-path">${esc(item.path)}</code></td><td><span class="source-service">${esc(item.service)}</span><div class="source-secondary">${esc(item.environment)} · ${esc(item.instance)}</div></td><td><span class="source-status ${current}"><span class="status-dot ${current}"></span>${error ? '采集异常' : running ? (item.last_polled_at ? '采集中' : '等待采集') : '已暂停'}</span>${error ? `<p class="source-error">${esc(error)}</p>` : `<div class="source-secondary">${esc(sourceNames[item.source] || item.source)} · ${esc(item.poll_interval_seconds || 5)} 秒</div>`}</td><td class="time-cell">${esc(time(item.last_polled_at))}<div class="source-secondary">游标 ${esc(item.cursor_offset ?? 0)} 字节</div></td><td><input class="switch" type="checkbox" data-source-toggle="${esc(item.id)}" ${running ? 'checked' : ''} title="${running ? '暂停监控' : '启用监控'}" aria-label="${running ? '暂停' : '启用'} ${esc(item.name)} 监控" /></td><td class="actions-cell"><button class="icon-button" data-source-scan="${esc(item.id)}" title="立即采集" aria-label="立即采集 ${esc(item.name)}">${icon('scan-line')}</button><button class="icon-button" data-source-delete="${esc(item.id)}" title="移除数据源" aria-label="移除 ${esc(item.name)}">${icon('trash-2')}</button></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="table-empty">尚未接入日志数据源</td></tr>';
  icons();
}
async function loadSources() { state.sources = items(await api('/api/sources')); renderSources(); }
async function loadKnowledge() {
  const query = $('knowledge-search').value.trim();
  const data = await api(query ? `/api/knowledge/search?q=${encodeURIComponent(query)}&limit=20` : '/api/knowledge');
  const documents = items(data);
  $('knowledge-count').textContent = `${documents.length} 条知识`;
  $('knowledge-summary').textContent = `${data.total ?? documents.length} 条故障手册 · Server / Nginx / Docker / Kubernetes`;
  $('knowledge-list').innerHTML = documents.length ? documents.map((item) => `<details class="knowledge-item"><summary>${icon('book-open')}<div><h3>${esc(item.title)}</h3><div class="knowledge-category">${esc(item.category)} · ${esc(item.id)}</div></div></summary><p>${esc(item.summary)}</p><div class="knowledge-excerpt">${esc(item.excerpt || item.summary)}</div>${referenceMeta(item)}</details>`).join('') : '<div class="empty-state">没有匹配的故障知识</div>';
  icons();
}
async function loadAudit() {
  const rows = items(await api('/api/audit?limit=200'));
  $('audit-rows').innerHTML = rows.length ? rows.map((item) => `<tr><td>${esc(time(item.created_at, true))}</td><td>${esc(item.actor || '智能体')}</td><td>${esc(toolNames[item.action] || item.action)}</td><td>${esc(item.target || '—')}</td><td><span class="audit-result">${esc(typeof item.result === 'object' ? JSON.stringify(item.result) : item.result || '')}</span>${item.details ? `<details><summary>详情</summary><div class="audit-result">${esc(typeof item.details === 'object' ? JSON.stringify(item.details, null, 2) : item.details)}</div></details>` : ''}</td></tr>`).join('') : '<tr><td colspan="5" class="table-empty">暂无审计记录</td></tr>';
}
async function switchView(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach((element) => element.classList.toggle('hidden', element.id !== `view-${view}`));
  document.querySelectorAll('[data-view]').forEach((element) => { element.classList.toggle('active', element.dataset.view === view); element.setAttribute('aria-current', element.dataset.view === view ? 'page' : 'false'); });
  $('view-name').textContent = { incidents: '故障事件', sources: '数据源', knowledge: '知识库', audit: '审计记录' }[view];
  globalError();
  try {
    if (view === 'incidents') { await overview(); await loadIncidents(); }
    else if (view === 'sources') await loadSources();
    else if (view === 'knowledge') await loadKnowledge();
    else if (view === 'audit') await loadAudit();
  } catch (error) { globalError(`数据加载失败：${error.message}`); }
}
async function refresh() {
  if (state.loading || document.hidden || state.busy) return;
  state.loading = true;
  try {
    await health();
    await overview();
    if (state.view === 'incidents') await loadIncidents();
    if (state.view === 'sources') await loadSources();
    if (state.view === 'audit') await loadAudit();
    globalError();
  } catch (error) { globalError(`同步失败：${error.message}`); }
  finally { state.loading = false; }
}
async function exportIncident(id) {
  const content = await api(`/api/incidents/${encodeURIComponent(id)}/export`);
  const url = URL.createObjectURL(new Blob([content], { type: 'text/markdown;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `incident-${shortId(id)}.md`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function incidentAction(action, button) {
  if (!state.selectedId || state.busy) return;
  if (action === 'merge' || action === 'split') { await openGrouping(action); return; }
  if (action === 'resolve') {
    $('resolve-incident-label').textContent = `INC-${shortId(state.selectedId)} · ${state.selected?.service || ''}`;
    $('resolution').value = '';
    $('resolve-error').textContent = '';
    $('resolve-dialog').showModal();
    return;
  }
  state.busy = true;
  button.disabled = true;
  try {
    const path = `/api/incidents/${encodeURIComponent(state.selectedId)}`;
    if (action === 'acknowledge') { await api(path, { method: 'PATCH', body: JSON.stringify({ status: 'acknowledged', operator: 'local-operator' }) }); toast('方案已确认，人工执行后记录处置结果。'); }
    if (action === 'rediagnose') { await api(`${path}/followup`, { method: 'POST', body: JSON.stringify({ message: '重新诊断', logs: null }) }); toast('已提交重新诊断'); }
    if (action === 'verify') { const data = await api(`${path}/verify`, { method: 'POST', body: '{}' }); toast(data.note || (data.healthy === true ? '新采集日志未发现异常，请结合服务指标确认恢复。' : data.healthy === false ? '仍然发现异常日志，需要继续排查。' : '恢复状态仍需人工验证。')); }
    if (action === 'export') await exportIncident(state.selectedId);
  } catch (error) { toast(error.message, true); }
  finally { state.busy = false; if (button.isConnected) button.disabled = false; }
  try { await refreshDetail(); await loadIncidents(); await overview(); } catch (error) { toast(error.message, true); }
}
async function openGrouping(mode) {
  try {
    await refreshDetail();
    const incident = state.selected;
    if (!incident) return;
    if (incident.status === 'diagnosing') { toast('诊断正在进行，请等待完成后再拆分或合并。', true); return; }
    const candidates = mode === 'merge' ? state.incidents.filter((item) => item.id !== incident.id && item.status !== 'diagnosing' && Boolean(item.is_demo) === Boolean(incident.is_demo)) : incident.original_alerts || [];
    state.grouping = { mode, incidentId: incident.id, alertCount: (incident.original_alerts || []).length };
    $('group-title').textContent = mode === 'merge' ? '合并故障事件' : '拆分原始告警';
    $('group-target').textContent = `INC-${shortId(incident.id)} · ${incident.service}${incident.is_demo ? ' · 演示事件' : ' · 真实事件'}`;
    $('group-error').textContent = '';
    $('group-options').innerHTML = candidates.length ? candidates.map((item) => `<label class="group-option"><input type="checkbox" name="group-id" value="${esc(item.id)}" /><span><strong>${esc(mode === 'merge' ? incidentTitle(item) : item.message)}</strong><small>${mode === 'merge' ? `INC-${esc(shortId(item.id))} · ${esc(item.service)} · ${esc(item.environment)} · ${esc(statusNames[item.status] || item.status)}` : `${esc(time(item.received_at || item.starts_at, true))} · ${esc(severityNames[item.severity] || item.severity)} · ${item.status === 'resolved' ? '恢复通知' : '异常通知'}`}</small></span></label>`).join('') : '<div class="empty-state">暂无可合并事件</div>';
    updateGroupingSelection();
    $('group-dialog').showModal();
    icons();
  } catch (error) { toast(error.message, true); }
}
function updateGroupingSelection() {
  const selected = document.querySelectorAll('#group-options input:checked').length;
  const mode = state.grouping?.mode;
  const valid = selected > 0 && (mode === 'merge' ? selected <= 20 : selected < state.grouping.alertCount && selected <= 100);
  $('group-selection').textContent = mode === 'merge' ? `已选 ${selected} 个事件` : `拆出 ${selected} 条 · 原事件保留 ${(state.grouping?.alertCount || 0) - selected} 条`;
  $('group-submit').disabled = !valid;
  $('group-submit').innerHTML = `${icon(mode === 'merge' ? 'combine' : 'split')}${mode === 'merge' ? '合并事件' : '拆分告警'}`;
  icons();
}
document.querySelector('#group-options').addEventListener('change', updateGroupingSelection);
$('group-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const ids = [...document.querySelectorAll('#group-options input:checked')].map((element) => element.value);
  const grouping = state.grouping;
  if (!grouping || !ids.length) { $('group-error').textContent = '请至少选择一项'; return; }
  if (grouping.mode === 'split' && ids.length >= grouping.alertCount) { $('group-error').textContent = '原事件至少保留一条告警'; return; }
  if (ids.length > (grouping.mode === 'merge' ? 20 : 100)) { $('group-error').textContent = grouping.mode === 'merge' ? '单次最多合并 20 个事件' : '单次最多拆分 100 条告警'; return; }
  state.busy = true;
  $('group-submit').disabled = true;
  $('group-error').textContent = '';
  let targetId = grouping.incidentId;
  try {
    const result = await api(`/api/incidents/${encodeURIComponent(grouping.incidentId)}/${grouping.mode}`, { method: 'POST', body: JSON.stringify(grouping.mode === 'merge' ? { incident_ids: ids } : { alert_ids: ids }) });
    if (grouping.mode === 'split' && result.split?.id) targetId = result.split.id;
    $('group-dialog').close();
    toast(grouping.mode === 'merge' ? '事件已合并，正在重新诊断' : '告警已拆分，新事件正在自动诊断');
  } catch (error) { $('group-error').textContent = error.message; if (!$('group-dialog').open) toast(error.message, true); }
  finally { state.busy = false; updateGroupingSelection(); }
  if (!$('group-dialog').open) {
    try { await loadIncidents(); await selectIncident(targetId); await overview(); } catch (error) { toast(error.message, true); }
  }
});

document.addEventListener('click', async (event) => {
  const nav = event.target.closest('[data-view]');
  if (nav) { await switchView(nav.dataset.view); return; }
  const close = event.target.closest('[data-close]');
  if (close) { $(close.dataset.close).close(); return; }
  const incident = event.target.closest('[data-incident]');
  if (incident) { try { await selectIncident(incident.dataset.incident); } catch (error) { toast(`读取事件失败：${error.message}`, true); } return; }
  const tab = event.target.closest('[data-detail-tab]');
  if (tab) { state.tab = tab.dataset.detailTab; renderDetail(state.selected, true); return; }
  const action = event.target.closest('[data-action]');
  if (action) { await incidentAction(action.dataset.action, action); return; }
  const copy = event.target.closest('[data-copy]');
  if (copy) { try { await navigator.clipboard.writeText(copy.dataset.copy); toast('命令已复制'); } catch { toast('浏览器未允许复制命令。', true); } return; }
  const reference = event.target.closest('[data-incident-reference]');
  if (reference) {
    event.preventDefault();
    const id = reference.dataset.incidentReference.split('/')[3];
    try { if (reference.dataset.incidentReference.endsWith('/export')) await exportIncident(id); else { await switchView('incidents'); await selectIncident(id); } } catch (error) { toast(error.message, true); }
    return;
  }
  const scan = event.target.closest('[data-source-scan]');
  if (scan) { scan.disabled = true; try { const result = await api(`/api/sources/${encodeURIComponent(scan.dataset.sourceScan)}/scan-now`, { method: 'POST', body: '{}' }); toast(`采集完成：${result.lines_read ?? 0} 行日志，${result.anomalies_detected ?? 0} 个异常`); await loadSources(); await overview(); } catch (error) { toast(error.message, true); } finally { if (scan.isConnected) scan.disabled = false; } return; }
  const remove = event.target.closest('[data-source-delete]');
  if (remove) {
    const source = state.sources.find((item) => item.id === remove.dataset.sourceDelete);
    if (!window.confirm(`移除数据源“${source?.name || ''}”？已有事件和日志文件将保留。`)) return;
    try { await api(`/api/sources/${encodeURIComponent(remove.dataset.sourceDelete)}`, { method: 'DELETE' }); toast('数据源已移除'); await loadSources(); await overview(); } catch (error) { toast(error.message, true); }
  }
});
document.addEventListener('keydown', async (event) => {
  const row = event.target.closest('[data-incident]');
  if (row && ['Enter', ' '].includes(event.key)) { event.preventDefault(); try { await selectIncident(row.dataset.incident); } catch (error) { toast(error.message, true); } }
});
document.addEventListener('change', async (event) => {
  const toggle = event.target.closest('[data-source-toggle]');
  if (!toggle) return;
  const enabled = toggle.checked;
  toggle.disabled = true;
  try { await api(`/api/sources/${encodeURIComponent(toggle.dataset.sourceToggle)}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }); toast(enabled ? '已启用监控' : '已暂停监控'); await loadSources(); await overview(); }
  catch (error) { toggle.checked = !enabled; toast(error.message, true); }
  finally { if (toggle.isConnected) toggle.disabled = false; }
});
$('source-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const fields = new FormData(event.currentTarget);
  const body = Object.fromEntries(fields.entries());
  body.enabled = fields.has('enabled');
  body.read_existing = fields.has('read_existing');
  body.poll_interval_seconds = Number(body.poll_interval_seconds);
  const button = event.currentTarget.querySelector('[type="submit"]');
  button.disabled = true;
  $('source-form-error').textContent = '';
  try { await api('/api/sources', { method: 'POST', body: JSON.stringify(body) }); $('source-dialog').close(); toast('数据源已接入'); await switchView('sources'); await overview(); }
  catch (error) { $('source-form-error').textContent = error.message; }
  finally { button.disabled = false; }
});
document.addEventListener('submit', async (event) => {
  if (event.target.id !== 'followup-form') return;
  event.preventDefault();
  const message = $('followup-message').value.trim();
  if (!message) return;
  const button = event.target.querySelector('[type="submit"]');
  button.disabled = true;
  state.busy = true;
  $('followup-error').textContent = '';
  try { await api(`/api/incidents/${encodeURIComponent(state.selectedId)}/followup`, { method: 'POST', body: JSON.stringify({ message }) }); $('followup-message').value = ''; toast('补充信息已纳入诊断'); state.detailSignature = ''; }
  catch (error) { $('followup-error').textContent = error.message; }
  finally { state.busy = false; if (button.isConnected) button.disabled = false; }
  try { await refreshDetail(); await loadIncidents(); } catch (error) { toast(error.message, true); }
});
$('resolve-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const resolution = $('resolution').value.trim();
  if (!resolution) { $('resolve-error').textContent = '请记录实际处置结果'; return; }
  const button = event.currentTarget.querySelector('[type="submit"]');
  button.disabled = true;
  $('resolve-error').textContent = '';
  try { await api(`/api/incidents/${encodeURIComponent(state.selectedId)}`, { method: 'PATCH', body: JSON.stringify({ status: 'resolved', resolution, operator: 'local-operator' }) }); $('resolve-dialog').close(); toast('解决结果已保存，复盘已更新'); await refreshDetail(); await loadIncidents(); await overview(); }
  catch (error) { $('resolve-error').textContent = error.message; }
  finally { button.disabled = false; }
});
$('inject-demo').addEventListener('click', async () => {
  $('inject-demo').disabled = true;
  $('demo-feedback').textContent = '';
  try { const data = await api('/api/demo/events', { method: 'POST', body: JSON.stringify({ scenario: $('demo-scenario').value }) }); $('demo-feedback').textContent = data.message || '异常已写入演示日志，等待自动采集'; toast('演示异常已注入，自动监控正在检测'); await refresh(); }
  catch (error) { $('demo-feedback').textContent = `注入失败：${error.message}`; toast(error.message, true); }
  finally { $('inject-demo').disabled = false; }
});
$('manual-example').addEventListener('change', async () => {
  const selected = $('manual-example').selectedOptions[0];
  if (!selected.value) return;
  try { const response = await fetch(`/examples/${encodeURIComponent(selected.value)}`); if (!response.ok) throw new Error('样例日志加载失败'); $('manual-logs').value = await response.text(); $('manual-source').value = selected.dataset.source; $('manual-error').textContent = ''; }
  catch (error) { $('manual-error').textContent = error.message; }
});
$('manual-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const logs = $('manual-logs').value.trim();
  if (!logs) { $('manual-error').textContent = '请输入日志内容'; return; }
  $('manual-diagnose').disabled = true;
  $('manual-error').textContent = '';
  $('manual-result').classList.add('hidden');
  try { const data = await api('/api/diagnose', { method: 'POST', body: JSON.stringify({ logs, source: $('manual-source').value, context: $('manual-context').value.trim() || null }) }); $('manual-result').innerHTML = `<h3>${esc(data.summary)}</h3>${diagnosisHtml({ diagnosis: data })}${traceHtml({ diagnosis: data })}`; $('manual-result').classList.remove('hidden'); icons(); $('manual-result').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  catch (error) { $('manual-error').textContent = error.message; }
  finally { $('manual-diagnose').disabled = false; }
});
$('auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { storeToken($('access-token').value.trim()); $('auth-dialog').close(); toast('访问凭据已保存'); await refresh(); }
  catch (error) { $('auth-error').textContent = error.message; }
});
$('clear-token').addEventListener('click', async () => { try { storeToken(''); $('access-token').value = ''; $('auth-dialog').close(); toast('访问凭据已清除'); await refresh(); } catch (error) { $('auth-error').textContent = error.message; } });
$('knowledge-file').addEventListener('change', async () => {
  const file = $('knowledge-file').files[0];
  if (!file) return;
  if (file.size > 2_000_000) { $('import-error').textContent = '文件不能超过 2 MB'; return; }
  try { $('knowledge-json').value = await file.text(); $('import-error').textContent = ''; } catch { $('import-error').textContent = '知识文件读取失败'; }
});
$('import-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('[type="submit"]');
  button.disabled = true;
  $('import-error').textContent = '';
  try {
    const data = JSON.parse($('knowledge-json').value);
    const documents = Array.isArray(data) ? data : data.documents;
    if (!Array.isArray(documents) || !documents.length) throw new Error('知识文档必须为非空 JSON 数组或包含 documents 数组');
    const result = await api('/api/knowledge/import', { method: 'POST', body: JSON.stringify({ documents }) });
    $('import-dialog').close(); toast(`知识导入成功：${result.imported ?? result.added ?? documents.length} 条`); await loadKnowledge(); await health();
  } catch (error) { $('import-error').textContent = error instanceof SyntaxError ? 'JSON 格式无效，请检查引号、逗号和括号' : error.message; }
  finally { button.disabled = false; }
});

$('add-source').addEventListener('click', sourceForm);
$('add-source-from-incidents').addEventListener('click', sourceForm);
$('open-manual').addEventListener('click', () => $('manual-dialog').showModal());
$('open-auth').addEventListener('click', () => { $('access-token').value = readToken(); $('auth-error').textContent = ''; $('auth-dialog').showModal(); });
$('import-knowledge').addEventListener('click', () => { $('import-error').textContent = ''; $('import-dialog').showModal(); });
$('refresh-all').addEventListener('click', async () => { await refresh(); if (state.view === 'knowledge') { try { await loadKnowledge(); } catch (error) { globalError(error.message); } } });
$('refresh-knowledge').addEventListener('click', async () => { try { await loadKnowledge(); } catch (error) { globalError(error.message); } });
$('search-knowledge').addEventListener('click', async () => { try { await loadKnowledge(); } catch (error) { globalError(error.message); } });
$('knowledge-search').addEventListener('keydown', async (event) => { if (event.key === 'Enter') { try { await loadKnowledge(); } catch (error) { globalError(error.message); } } });
$('refresh-audit').addEventListener('click', async () => { try { await loadAudit(); } catch (error) { globalError(error.message); } });
$('incident-search').addEventListener('input', renderIncidentRows);
['environment-filter', 'severity-filter', 'status-filter'].forEach((id) => $(id).addEventListener('change', renderIncidentRows));
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
icons();
refresh();
setInterval(refresh, 5000);

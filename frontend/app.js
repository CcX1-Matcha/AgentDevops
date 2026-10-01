const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = (name) => `<i data-lucide="${esc(name)}"></i>`;
const state = { view: 'incidents', incidents: [], sources: [], accounts: [], selectedId: null, selected: null, tab: 'diagnosis', loading: false, detailSignature: '', busy: false, grouping: null, user: null, bootstrap: false, authReady: false, epoch: 0, remediation: null, learning: null, executionPlan: null };
const roleNames = { guest: '访客', viewer: '观察员', junior: '初级工程师', senior: '高级工程师', admin: '管理员', operator: '本地手动权限' };
const planStatusNames = { pending: '待确认', running: '执行中', succeeded: '执行成功', failed: '执行失败', verification_failed: '执行完成 · 恢复验证失败', unknown: '执行结果未知', stale: '计划已失效', simulated: '演示完成 · 未修改真实环境' };
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
  if (typeof detail === 'string') return ({ 'Invalid username or password.': '账号或密码错误，或账号已停用。', 'A valid access token or account session is required.': '登录已失效，请重新登录。', 'Your role does not have permission for this operation.': '当前账号无权执行此操作。', 'Your account does not have permission for this operation.': '当前账号无权执行此操作。', 'The last enabled administrator cannot be disabled or demoted.': '最后一个启用的管理员不能停用或降级。', 'Username must contain 3-64 letters, digits, dots, underscores or hyphens.': '账号需为 3 至 64 位字母、数字、点、下划线或连字符。', 'Password must contain between 9 and 1024 characters.': '密码长度需为 9 至 1024 个字符。', 'The first administrator must be initialized from this machine.': '首次管理员需要在部署本机初始化。' }[detail.replace(/^Value error, /, '')] || detail);
  if (Array.isArray(detail)) return detail.map((item) => `${(item.loc || []).filter((part) => part !== 'body').join('.')}: ${errorMessage(item.msg)}`).join('；');
  return detail?.message || '请求失败，请稍后重试。';
}
async function api(path, options = {}) {
  const epoch = state.epoch;
  const token = readToken();
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers } });
  const type = response.headers.get('content-type') || '';
  const data = type.includes('json') ? await response.json() : await response.text();
  if (epoch !== state.epoch) throw new Error('账号已切换，请重新操作。');
  if (response.status === 401 && path !== '/api/auth/login') {
    try { storeToken(''); } catch {}
    state.epoch++;
    state.user = null;
    clearPrivateData();
    updateIdentity();
  }
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
function can(permission) { return Boolean(state.user?.authenticated && state.user.permissions?.includes(permission)); }
function need(permission) { if (can(permission)) return true; toast('当前账号无权执行此操作。', true); return false; }
function clearPrivateData() {
  state.incidents = []; state.sources = []; state.accounts = []; state.selected = null; state.selectedId = null;
  state.learning = null; state.remediation = null; state.executionPlan = null; state.detailSignature = ''; state.grouping = null;
  $('incident-rows').innerHTML = '<tr><td colspan="5" class="table-empty">登录后查看故障事件</td></tr>';
  $('incident-detail').innerHTML = '<div class="detail-empty"><span class="empty-icon">' + icon('lock-keyhole') + '</span><h2>等待账号登录</h2></div>';
  $('source-rows').innerHTML = '<tr><td colspan="6" class="table-empty">登录后查看数据源</td></tr>';
  $('knowledge-list').innerHTML = ''; $('audit-rows').innerHTML = ''; $('campaign-list').innerHTML = ''; $('learning-rows').innerHTML = ''; $('accounts-rows').innerHTML = '';
  $('manual-result').innerHTML = ''; $('manual-result').classList.add('hidden'); $('manual-logs').value = ''; $('manual-context').value = '';
  ['metric-active', 'metric-diagnosed', 'metric-alerts', 'metric-sources', 'learning-count', 'learning-useful', 'learning-rate', 'learning-review'].forEach((id) => $(id).textContent = '—');
  ['nav-active-count', 'nav-source-count', 'nav-campaign-count'].forEach((id) => $(id).textContent = '0');
  $('incident-count').textContent = '0 个事件'; $('list-status').textContent = '等待账号登录'; $('source-summary').textContent = '等待账号登录'; $('source-total').textContent = '';
  $('knowledge-count').textContent = ''; $('knowledge-summary').textContent = '运维手册与故障处置记录'; $('accounts-summary').textContent = '等待账号登录';
  $('last-updated').textContent = '尚未更新'; $('demo-feedback').textContent = ''; $('monitor-status').textContent = '等待账号登录';
  $('metric-aggregation').textContent = '等待采集'; $('metric-source-health').textContent = '等待采集'; $('group-options').innerHTML = ''; $('execute-review').innerHTML = '';
  ['source-form', 'resolve-form', 'account-form', 'import-form', 'manual-form'].forEach((id) => $(id).reset());
  $('knowledge-search').value = ''; $('incident-search').value = ''; $('severity-filter').value = ''; $('status-filter').value = 'active';
  filters();
  ['resolve-dialog', 'group-dialog', 'source-dialog', 'manual-dialog', 'import-dialog', 'account-dialog', 'execute-dialog'].forEach((id) => { if ($(id).open) $(id).close(); });
}
function updateIdentity() {
  const user = state.user;
  const name = user?.authenticated ? user.username || roleNames[user.role] : '未登录';
  const role = roleNames[user?.role] || '访客';
  $('identity-name').textContent = name; $('identity-role').textContent = role;
  $('operator-name').innerHTML = `${esc(name)}<small id="operator-role">${esc(role)}</small>`;
  $('operator-avatar').textContent = user?.authenticated ? String(name).slice(0, 2).toUpperCase() : '—';
  $('open-auth').title = user?.authenticated ? `${name} · ${role}` : '账号登录';
  $('logout').classList.toggle('hidden', !user?.authenticated);
  $('session-notice').classList.toggle('hidden', can('incident:read') && !state.bootstrap);
  $('session-notice-text').textContent = state.bootstrap ? '本机尚未创建管理员账号' : '请登录查看运维事件';
  $('session-login').innerHTML = `${icon(state.bootstrap ? 'user-plus' : 'log-in')}${state.bootstrap ? '创建管理员' : '登录'}`;
  const permissions = { 'add-source': 'source:manage', 'add-source-from-incidents': 'source:manage', 'inject-demo': 'incident:write', 'import-knowledge': 'knowledge:import', 'create-account': 'account:manage' };
  Object.entries(permissions).forEach(([id, permission]) => { $(id).disabled = !can(permission); $(id).title = can(permission) ? '' : '当前账号无操作权限'; });
  document.querySelectorAll('[data-permission]').forEach((element) => {
    const allowed = can(element.dataset.permission);
    if (element.dataset.view === 'accounts') element.classList.toggle('hidden', !allowed);
    else element.disabled = !allowed;
  });
  document.querySelectorAll('[data-view]').forEach((element) => { if (element.dataset.view !== 'accounts') element.disabled = !can('incident:read'); });
  if (state.view === 'accounts' && !can('account:manage')) showView('incidents');
  if (can('incident:read') && !state.selectedId && !state.incidents.length) renderIncidentRows();
  icons();
}
async function loadIdentity() {
  const previous = state.user;
  const user = await api('/api/auth/me');
  state.user = user; state.bootstrap = Boolean(user.bootstrap_available); state.authReady = true;
  if (previous && (previous.username !== user.username || previous.role !== user.role || Boolean(previous.authenticated) !== Boolean(user.authenticated))) { state.epoch++; clearPrivateData(); }
  updateIdentity();
}
function openAuth() {
  $('auth-form').reset(); $('auth-error').textContent = ''; $('access-token').value = '';
  $('auth-title').textContent = state.bootstrap ? '创建本机管理员' : '登录运维账号';
  $('auth-caption').textContent = state.bootstrap ? '仅支持本机首次初始化' : state.user?.authenticated ? `当前：${state.user.username} · ${roleNames[state.user.role] || state.user.role}` : 'SRE 工作区';
  $('auth-password').minLength = state.bootstrap ? 9 : 1;
  $('auth-password').autocomplete = state.bootstrap ? 'new-password' : 'current-password';
  $('auth-submit').innerHTML = `${icon(state.bootstrap ? 'user-plus' : 'log-in')}${state.bootstrap ? '创建并登录' : '登录'}`;
  $('auth-dialog').showModal(); icons();
}
function sourceForm() { if (!need('source:manage')) return; $('source-form').reset(); $('source-form-error').textContent = ''; $('source-dialog').showModal(); }

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
  const readable = can('incident:read');
  const current = filteredIncidents();
  $('incident-count').textContent = `${current.length} 个事件`;
  $('incident-rows').innerHTML = current.length ? current.map((item) => `<tr data-incident="${esc(item.id)}" class="${item.id === state.selectedId ? 'selected' : ''}" tabindex="0" aria-label="查看 ${esc(incidentTitle(item))}"><td>${severity(item.severity)}</td><td><span class="event-title">${esc(incidentTitle(item))}</span><span class="event-meta"><span>${esc(item.service || '未知服务')}</span><span>·</span><span>${esc(item.environment || '未标记环境')}</span>${item.is_demo ? '<span class="demo-label">演示</span>' : ''}</span></td><td>${status(item.status)}</td><td class="count-cell">${esc(item.occurrences ?? 1)}</td><td class="time-cell">${esc(time(item.last_seen || item.updated_at || item.first_seen))}<small>${esc(sourceNames[item.source] || item.source || '')}</small></td></tr>`).join('') : `<tr><td colspan="5" class="table-empty"><span class="empty-icon">${icon('check-check')}</span><strong>${state.incidents.length ? '没有符合条件的事件' : '暂无故障事件'}</strong><p>${state.incidents.length ? '调整筛选条件后重试' : '数据源正在等待新日志'}</p></td></tr>`;
  $('list-status').textContent = readable ? `共 ${state.incidents.length} 个事件 · ${current.length} 个符合筛选` : '等待账号登录';
  if (!state.selectedId) $('incident-detail').innerHTML = `<div class="detail-empty"><span class="empty-icon">${icon(readable ? 'scan-line' : 'lock-keyhole')}</span><h2>${readable ? '等待故障事件' : '等待账号登录'}</h2><p>${readable ? state.incidents.length ? '暂无符合条件的事件' : '暂无故障事件' : '登录后查看故障详情'}</p></div>`;
  if (!readable) $('incident-rows').innerHTML = '<tr><td colspan="5" class="table-empty">登录后查看故障事件</td></tr>';
  icons();
}
async function loadIncidents() {
  if (!can('incident:read')) return;
  state.incidents = items(await api('/api/incidents?limit=200'));
  if (state.selectedId && !state.incidents.some((item) => item.id === state.selectedId)) { state.selectedId = null; state.selected = null; state.learning = null; state.remediation = null; state.detailSignature = ''; }
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
function executionMode(mode) { return { demo: '演示 · 不修改真实环境', http: '真实环境 · HTTP 执行器' }[mode] || mode || '尚未配置'; }
function targetHtml(target = {}) {
  return `<dl class="target-grid"><dt>服务</dt><dd>${esc(target.service || '未提供')}</dd><dt>环境</dt><dd>${esc(target.environment || '未提供')}</dd><dt>实例</dt><dd>${esc(target.instance || '未提供')}</dd></dl>`;
}
function planHtml(plan) {
  const verification = plan.verification;
  const recovery = verification?.healthy === true ? '恢复验证通过' : verification?.healthy === false ? '恢复验证失败，仍需人工排查' : '恢复状态未知，请人工核查';
  return `<div class="remediation-plan"><div class="plan-heading"><strong>${esc(plan.name || plan.playbook_id)}</strong><span class="plan-status ${esc(plan.status)}">${esc(planStatusNames[plan.status] || plan.status)}</span></div><p class="step-description">${esc(executionMode(plan.mode))} · ${esc(time(plan.created_at, true))}</p>${targetHtml(plan.target)}${plan.status === 'pending' ? `<p class="plan-expiry">有效至 ${esc(time(plan.expires_at, true))}</p>` : ''}${['running', 'pending', 'stale'].includes(plan.status) ? '' : `<p class="recovery-result ${verification?.healthy === false ? 'error' : ''}">${esc(recovery)}${verification?.note ? `：${esc(verification.note)}` : ''}</p>`}${plan.result ? `<details class="execution-result"><summary>执行结果</summary><pre>${esc(typeof plan.result === 'object' ? JSON.stringify(plan.result, null, 2) : plan.result)}</pre></details>` : ''}${plan.executed_by ? `<p class="reference-meta">执行人：${esc(plan.executed_by)}</p>` : ''}${plan.status === 'pending' && can('remediation:execute') ? `<button class="button small" data-execute-plan="${esc(plan.id)}">${icon('play')}审阅并执行</button>` : ''}</div>`;
}
function remediationHtml(incident) {
  const data = state.remediation;
  const manual = state.user?.role === 'junior' ? '当前账号为初级工程师，请按诊断方案人工处置并记录结果。' : !can('remediation:execute') ? '当前账号仅可查看处置方案，无辅助执行权限。' : '';
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('shield-check')}AI 辅助处置</h3><span class="muted">${can('remediation:execute') ? '确认后执行' : '人工处置'}</span></div>${manual ? `<p class="permission-note">${esc(manual)}</p>` : ''}${!data ? '<p class="muted">正在读取可用剧本</p>' : data.error ? `<p class="permission-note">${esc(data.error)}</p>` : `<p class="step-description">${esc(data.reason || (data.eligible ? '满足辅助处置条件' : '当前事件不满足辅助处置条件'))}</p>${(data.playbooks || []).map((playbook) => `<div class="playbook-row"><div><strong>${esc(playbook.name)}</strong><p>${esc(playbook.description)}</p><span class="reference-meta">${esc(executionMode(playbook.mode))} · ${esc({ low: '低风险', read_only: '只读' }[playbook.risk] || playbook.risk || '风险待审核')}</span></div>${can('remediation:execute') ? `<button class="button small" data-create-plan="${esc(playbook.id)}" ${!data.eligible ? 'disabled' : ''}>${icon('list-checks')}生成计划</button>` : ''}</div>`).join('')}${!(data.playbooks || []).length ? '<p class="muted">没有匹配的已审核白名单剧本</p>' : ''}`}</div>${(data?.plans || []).length ? `<div class="detail-section"><div class="section-heading"><h3>${icon('history')}处置记录</h3><span class="muted">${data.plans.length} 条</span></div>${data.plans.map(planHtml).join('')}</div>` : ''}${feedbackHtml(incident)}`;
}
function feedbackHtml(incident) {
  const learning = state.learning;
  const feedback = learning?.current_feedback;
  const enabled = can('incident:write') && Boolean(diagnosis(incident)) && !incident.is_demo;
  return `<div class="detail-section"><div class="section-heading"><h3>${icon('message-square-heart')}诊断建议反馈</h3>${feedback ? '<span class="muted">已反馈</span>' : ''}</div>${incident.is_demo ? '<p class="permission-note">演示事件不计入真实反馈指标或历史案例。</p>' : learning?.error ? `<p class="permission-note">${esc(learning.error)}</p>` : `<form id="feedback-form"><div class="feedback-options"><label class="${feedback?.useful === true ? 'selected' : ''}"><input type="radio" name="useful" value="true" ${feedback?.useful === true ? 'checked' : ''} ${!enabled ? 'disabled' : ''} required />${icon('thumbs-up')}建议有用</label><label class="${feedback?.useful === false ? 'selected' : ''}"><input type="radio" name="useful" value="false" ${feedback?.useful === false ? 'checked' : ''} ${!enabled ? 'disabled' : ''} required />${icon('thumbs-down')}建议无用</label></div><label class="sr-only" for="feedback-comment">反馈说明</label><textarea id="feedback-comment" maxlength="2000" placeholder="实际结果、建议问题或修正意见（可选）" ${!enabled ? 'disabled' : ''}>${esc(feedback?.comment || '')}</textarea><div class="followup-footer"><button class="button small" type="submit" ${!enabled ? 'disabled' : ''}>${icon('send')}${feedback ? '更新反馈' : '提交反馈'}</button></div><p id="feedback-error" class="form-error" role="alert"></p></form>`}${learning?.case ? `<div class="case-record">${icon('book-check')}已沉淀历史案例 <span>${esc(learning.case.id)}</span></div>` : ''}</div>`;
}
function renderDetail(incident, force = false) {
  if (!incident) return;
  const signature = JSON.stringify([incident, state.remediation, state.learning, state.user?.role, state.user?.permissions]) + state.tab;
  if (signature === state.detailSignature && !force) return;
  const draft = document.getElementById('followup-message')?.value || '';
  if (['followup-message', 'feedback-comment'].includes(document.activeElement?.id) && !force || state.busy && !force) return;
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
  const tabs = $('incident-detail').querySelector('.detail-tabs');
  tabs.insertAdjacentHTML('beforeend', detailTab('remediation', '处置与反馈'));
  if (state.tab === 'remediation') $('detail-panel').innerHTML = remediationHtml(incident);
  if (!can('incident:write')) {
    $('followup-form')?.remove();
    $('incident-detail').querySelectorAll('[data-action="acknowledge"], [data-action="resolve"], [data-action="rediagnose"], [data-action="verify"], [data-action="merge"], [data-action="split"]').forEach((button) => { button.disabled = true; button.title = '当前账号仅可查看'; });
  }
  if (can('remediation:execute') && state.tab !== 'remediation') {
    $('incident-detail').querySelector('.detail-actions').insertAdjacentHTML('afterbegin', `<button class="button" data-action="remediation">${icon('shield-check')}辅助处置</button>`);
  }
  icons();
}
async function selectIncident(id) {
  if (state.busy) return;
  if (state.selectedId !== id) {
    state.selected = null;
    state.learning = null; state.remediation = null;
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
  const path = `/api/incidents/${encodeURIComponent(id)}`;
  const results = await Promise.allSettled([api(path), api(`${path}/remediation`), api(`${path}/learning`)]);
  if (state.selectedId !== id) return;
  if (results[0].status === 'rejected') throw results[0].reason;
  state.selected = results[0].value;
  state.remediation = results[1].status === 'fulfilled' ? results[1].value : { error: results[1].reason.message };
  state.learning = results[2].status === 'fulfilled' ? results[2].value : { error: results[2].reason.message };
  renderDetail(state.selected);
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
  $('source-rows').querySelectorAll('[data-source-toggle], [data-source-delete]').forEach((control) => { control.disabled = !can('source:manage'); });
  $('source-rows').querySelectorAll('[data-source-scan]').forEach((control) => { control.disabled = !can('source:scan'); });
  icons();
}
async function loadSources() { if (!can('incident:read')) return; state.sources = items(await api('/api/sources')); renderSources(); }
async function loadKnowledge() {
  if (!can('incident:read')) return;
  const query = $('knowledge-search').value.trim();
  const data = await api(query ? `/api/knowledge/search?q=${encodeURIComponent(query)}&limit=20` : '/api/knowledge');
  const documents = items(data);
  $('knowledge-count').textContent = `${documents.length} 条知识`;
  $('knowledge-summary').textContent = `${data.total ?? documents.length} 条故障手册 · Server / Nginx / Docker / Kubernetes`;
  $('knowledge-list').innerHTML = documents.length ? documents.map((item) => `<details class="knowledge-item"><summary>${icon('book-open')}<div><h3>${esc(item.title)}</h3><div class="knowledge-category">${esc(item.category)} · ${esc(item.id)}</div></div></summary><p>${esc(item.summary)}</p><div class="knowledge-excerpt">${esc(item.excerpt || item.summary)}</div>${referenceMeta(item)}</details>`).join('') : '<div class="empty-state">没有匹配的故障知识</div>';
  icons();
}
async function loadAudit() {
  if (!can('incident:read')) return;
  const rows = items(await api('/api/audit?limit=200'));
  $('audit-rows').innerHTML = rows.length ? rows.map((item) => `<tr><td>${esc(time(item.created_at, true))}</td><td>${esc(item.actor || '智能体')}</td><td>${esc(toolNames[item.action] || item.action)}</td><td>${esc(item.target || '—')}</td><td><span class="audit-result">${esc(typeof item.result === 'object' ? JSON.stringify(item.result) : item.result || '')}</span>${item.details ? `<details><summary>详情</summary><div class="audit-result">${esc(typeof item.details === 'object' ? JSON.stringify(item.details, null, 2) : item.details)}</div></details>` : ''}</td></tr>`).join('') : '<tr><td colspan="5" class="table-empty">暂无审计记录</td></tr>';
}
async function loadCampaigns() {
  if (!can('incident:read')) return;
  const data = await api('/api/campaigns');
  const groups = items(data);
  $('nav-campaign-count').textContent = groups.length;
  $('campaign-summary').textContent = `${groups.length} 组关联候选 · ${Math.round((data.window_seconds || 600) / 60)} 分钟关联窗口`;
  $('campaign-list').innerHTML = `${data.boundary ? `<p class="permission-note campaign-boundary">${esc(data.boundary)}</p>` : ''}${groups.length ? groups.map((group) => `<article class="campaign-row"><div class="campaign-heading"><span class="campaign-id">GRP-${esc(shortId(group.id))}</span>${severity(group.severity)}${group.is_demo ? '<span class="demo-label">演示</span>' : ''}<span class="muted">${esc(group.environment || '未标记环境')}</span></div><h2>${esc(group.summary || '疑似同源故障')}</h2><p class="step-description">${esc(group.root_cause || '关联线索待人工核实，尚未确认统一根因')}</p><div class="campaign-scope"><span>服务：${esc((group.services || []).join('、') || '未知')}</span><span>实例：${esc((group.instances || []).join('、') || '未知')}</span></div><div class="campaign-evidence">${(group.evidence || []).map((evidence) => `<p>${icon('link')}${esc(typeof evidence === 'string' ? evidence : evidence.detail || evidence.relation)}</p>`).join('')}</div><div class="campaign-incidents">${(group.incident_ids || []).map((id) => `<button class="button small" data-campaign-incident="${esc(id)}">${icon('arrow-up-right')}INC-${esc(shortId(id))}</button>`).join('')}</div><p class="reference-meta">${esc(time(group.first_seen, true))} 至 ${esc(time(group.last_seen, true))}</p></article>`).join('') : '<div class="empty-state">尚无满足关联条件的故障组</div>'}`;
  icons();
}
function rate(value) { return value == null ? '—' : `${Math.round(value * 100)}%`; }
async function loadLearning() {
  if (!can('incident:read')) return;
  const data = await api('/api/learning/metrics');
  const rows = data.runbooks || [];
  $('learning-count').textContent = data.feedback_count ?? 0;
  $('learning-useful').textContent = data.useful_count ?? 0;
  $('learning-rate').textContent = rate(data.acceptance_rate);
  $('learning-review').textContent = rows.filter((item) => item.review_required).length;
  $('learning-rows').innerHTML = rows.length ? rows.map((row) => `<tr><td><strong>${esc(row.title || row.id)}</strong><small>${esc(row.title ? row.id : '')}</small></td><td>${esc(row.feedback_count ?? row.total ?? 0)}</td><td>${esc(row.useful_count ?? row.useful ?? 0)}</td><td>${rate(row.acceptance_rate ?? row.rate)}</td><td><span class="quality-status ${row.review_required ? 'review' : ''}">${row.review_required ? '建议人工复核' : (row.feedback_count || row.total) ? '持续观察' : '暂无反馈'}</span></td></tr>`).join('') : '<tr><td colspan="5" class="table-empty">尚无真实事件反馈</td></tr>';
}
async function loadAccounts() {
  if (!can('account:manage')) return;
  state.accounts = items(await api('/api/accounts'));
  $('accounts-summary').textContent = `${state.accounts.length} 个账号 · ${state.accounts.filter((item) => item.enabled).length} 个启用`;
  $('accounts-rows').innerHTML = state.accounts.map((account) => `<tr><td><strong>${esc(account.username)}</strong>${account.username === state.user?.username ? '<span class="subtle-tag">当前账号</span>' : ''}</td><td><label class="sr-only" for="account-role-${esc(account.id)}">${esc(account.username)} 的级别</label><select id="account-role-${esc(account.id)}" data-account-role="${esc(account.id)}">${Object.entries(roleNames).filter(([key]) => ['viewer', 'junior', 'senior', 'admin'].includes(key)).map(([key, name]) => `<option value="${esc(key)}" ${account.role === key ? 'selected' : ''}>${esc(name)}</option>`).join('')}</select><button class="icon-button" data-save-account="${esc(account.id)}" title="保存账号级别" aria-label="保存 ${esc(account.username)} 的级别">${icon('save')}</button></td><td><label class="account-enabled"><input type="checkbox" class="switch" data-account-enabled="${esc(account.id)}" ${account.enabled ? 'checked' : ''} aria-label="启用 ${esc(account.username)}" /><span>${account.enabled ? '已启用' : '已停用'}</span></label></td><td class="time-cell">${esc(time(account.created_at, true))}</td><td><span class="reference-meta">${esc(roleNames[account.role] || account.role)}</span></td></tr>`).join('') || '<tr><td colspan="5" class="table-empty">暂无账号</td></tr>';
  icons();
}
function showView(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach((element) => element.classList.toggle('hidden', element.id !== `view-${view}`));
  document.querySelectorAll('[data-view]').forEach((element) => { element.classList.toggle('active', element.dataset.view === view); element.setAttribute('aria-current', element.dataset.view === view ? 'page' : 'false'); });
  $('view-name').textContent = { incidents: '故障事件', sources: '数据源', knowledge: '知识库', audit: '审计记录', campaigns: '关联故障', learning: '知识质量', accounts: '账号管理' }[view];
  globalError();
}
async function switchView(view) {
  if (view === 'accounts' ? !need('account:manage') : !need('incident:read')) return;
  showView(view);
  try {
    if (view === 'incidents') { await overview(); await loadIncidents(); }
    else if (view === 'sources') await loadSources();
    else if (view === 'knowledge') await loadKnowledge();
    else if (view === 'audit') await loadAudit();
    else if (view === 'campaigns') await loadCampaigns();
    else if (view === 'learning') await loadLearning();
    else if (view === 'accounts') await loadAccounts();
  } catch (error) { globalError(`数据加载失败：${error.message}`); }
}
async function refresh() {
  if (state.loading || document.hidden || state.busy) return;
  state.loading = true;
  try {
    await health();
    await loadIdentity();
    if (!can('incident:read')) { globalError(); return; }
    await overview();
    if (state.view === 'incidents') await loadIncidents();
    if (state.view === 'sources') await loadSources();
    if (state.view === 'audit') await loadAudit();
    if (state.view === 'campaigns') await loadCampaigns();
    if (state.view === 'learning') await loadLearning();
    if (state.view === 'accounts' && !document.activeElement?.closest('.accounts-table')) await loadAccounts();
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
async function updateAccount(id, body, control) {
  if (!need('account:manage')) return;
  control.disabled = true;
  try { await api(`/api/accounts/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) }); toast('账号权限已更新'); await loadIdentity(); if (can('account:manage')) await loadAccounts(); }
  catch (error) { toast(error.message, true); if (can('account:manage')) { try { await loadAccounts(); } catch {} } }
  finally { if (control.isConnected) control.disabled = !can('account:manage'); }
}
async function createRemediationPlan(playbookId, button) {
  if (!need('remediation:execute') || !state.selectedId || state.busy) return;
  state.busy = true; button.disabled = true;
  try { await api(`/api/incidents/${encodeURIComponent(state.selectedId)}/remediation/plans`, { method: 'POST', body: JSON.stringify({ playbook_id: playbookId }) }); toast('处置计划已生成，请核对目标和风险'); }
  catch (error) { toast(error.message, true); }
  finally { state.busy = false; if (button.isConnected) button.disabled = !can('remediation:execute'); }
  try { await refreshDetail(); } catch (error) { toast(error.message, true); }
}
function openExecution(id) {
  if (!need('remediation:execute')) return;
  const plan = (state.remediation?.plans || []).find((item) => item.id === id);
  if (!plan || plan.status !== 'pending') { toast('该计划已不可执行，请刷新处置记录。', true); return; }
  if (plan.expires_at && new Date(plan.expires_at).getTime() <= Date.now()) { toast('该计划已过期，请重新生成。', true); return; }
  state.executionPlan = plan;
  $('execute-plan-id').textContent = `PLAN-${shortId(plan.id)} · INC-${shortId(plan.incident_id)}`;
  $('execute-review').innerHTML = `<h3>${esc(plan.name || plan.playbook_id)}</h3>${targetHtml(plan.target)}<dl class="target-grid"><dt>故障类型</dt><dd>${esc(plan.failure_type)}</dd><dt>告警等级</dt><dd>${esc(severityNames[plan.severity] || plan.severity)}</dd><dt>执行方式</dt><dd>${esc(executionMode(plan.mode))}</dd><dt>动作风险</dt><dd>${esc({ low: '低风险 · 已审核白名单', read_only: '只读' }[plan.risk] || plan.risk || '由服务端审核')}</dd><dt>剧本审核人</dt><dd>${esc(plan.approved_by || '未提供')}</dd><dt>执行确认人</dt><dd>${esc(state.user?.username)}</dd><dt>有效期</dt><dd>${esc(time(plan.expires_at, true))}</dd></dl>${plan.action ? `<div class="review-action"><strong>执行动作</strong><p>${esc(typeof plan.action === 'object' ? JSON.stringify(plan.action, null, 2) : plan.action)}</p></div>` : ''}<div class="review-action"><strong>回滚 / 后续处理</strong><p>${esc(typeof plan.rollback === 'object' ? JSON.stringify(plan.rollback, null, 2) : plan.rollback || '如验证失败，继续人工排查并升级处理。')}</p></div>${plan.mode === 'demo' ? '<p class="permission-note">本次为模拟执行，执行结果不会证明真实服务已恢复。</p>' : '<p class="uncertainty">本次将调用真实环境执行器。请确认目标与当前故障一致。</p>'}`;
  $('execute-confirm').checked = false; $('execute-submit').disabled = true; $('execute-error').textContent = '';
  $('execute-dialog').showModal(); icons();
}
$('execute-confirm').addEventListener('change', () => { $('execute-submit').disabled = !$('execute-confirm').checked || !can('remediation:execute'); });
$('execute-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!need('remediation:execute') || !state.executionPlan || !$('execute-confirm').checked || state.busy) return;
  const plan = state.executionPlan;
  state.busy = true; $('execute-submit').disabled = true; $('execute-error').textContent = '';
  try {
    const response = await api(`/api/remediation/plans/${encodeURIComponent(plan.id)}/execute`, { method: 'POST', body: JSON.stringify({ confirmed: true }) });
    const result = response.plan || response;
    $('execute-dialog').close(); state.executionPlan = null;
    toast(planStatusNames[result.status] || '执行状态已更新', ['failed', 'verification_failed', 'unknown', 'stale'].includes(result.status));
  } catch (error) { $('execute-error').textContent = error.message; }
  finally { state.busy = false; $('execute-submit').disabled = !$('execute-confirm').checked || !can('remediation:execute'); }
  try { await refreshDetail(); await overview(); } catch (error) { toast(error.message, true); }
});
document.addEventListener('submit', async (event) => {
  if (event.target.id !== 'feedback-form') return;
  event.preventDefault();
  if (!need('incident:write') || !state.selectedId || state.busy) return;
  const fields = new FormData(event.target);
  if (!fields.has('useful')) return;
  const button = event.target.querySelector('[type="submit"]'); button.disabled = true; state.busy = true;
  $('feedback-error').textContent = '';
  try { state.learning = await api(`/api/incidents/${encodeURIComponent(state.selectedId)}/feedback`, { method: 'POST', body: JSON.stringify({ useful: fields.get('useful') === 'true', comment: $('feedback-comment').value.trim() || null }) }); toast('反馈已保存'); }
  catch (error) { if ($('feedback-error')) $('feedback-error').textContent = error.message; }
  finally { state.busy = false; if (button.isConnected) button.disabled = !can('incident:write'); }
  renderDetail(state.selected, true);
});
$('create-account').addEventListener('click', () => { if (!need('account:manage')) return; $('account-form').reset(); $('account-error').textContent = ''; $('account-dialog').showModal(); });
$('account-form').addEventListener('submit', async (event) => {
  event.preventDefault(); if (!need('account:manage')) return;
  const button = event.target.querySelector('[type="submit"]'); button.disabled = true;
  $('account-error').textContent = '';
  try { const fields = new FormData(event.target); await api('/api/accounts', { method: 'POST', body: JSON.stringify({ username: String(fields.get('username')).trim(), password: fields.get('password'), role: fields.get('role') }) }); $('account-form').reset(); $('account-dialog').close(); toast('运维账号已创建'); await loadAccounts(); }
  catch (error) { $('account-error').textContent = error.message; }
  finally { button.disabled = false; }
});
async function incidentAction(action, button) {
  if (!state.selectedId || state.busy) return;
  if (action === 'remediation') { state.tab = 'remediation'; renderDetail(state.selected, true); return; }
  if (!need(['export', 'refresh-detail'].includes(action) ? 'incident:read' : 'incident:write')) return;
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
    if (action === 'acknowledge') { await api(path, { method: 'PATCH', body: JSON.stringify({ status: 'acknowledged', operator: state.user?.username }) }); toast('方案已确认，人工执行后记录处置结果。'); }
    if (action === 'rediagnose') { await api(`${path}/followup`, { method: 'POST', body: JSON.stringify({ message: '重新诊断', logs: null }) }); toast('已提交重新诊断'); }
    if (action === 'verify') { const data = await api(`${path}/verify`, { method: 'POST', body: '{}' }); toast(data.note || (data.healthy === true ? '新采集日志未发现异常，请结合服务指标确认恢复。' : data.healthy === false ? '仍然发现异常日志，需要继续排查。' : '恢复状态仍需人工验证。')); }
    if (action === 'export') await exportIncident(state.selectedId);
  } catch (error) { toast(error.message, true); }
  finally { state.busy = false; if (button.isConnected) button.disabled = false; }
  try { await refreshDetail(); await loadIncidents(); await overview(); } catch (error) { toast(error.message, true); }
}
async function openGrouping(mode) {
  if (!need('incident:write')) return;
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
  if (!need('incident:write')) return;
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
  if (event.target.closest('button:disabled')) return;
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
  const campaignIncident = event.target.closest('[data-campaign-incident]');
  if (campaignIncident) { try { await switchView('incidents'); await selectIncident(campaignIncident.dataset.campaignIncident); } catch (error) { toast(error.message, true); } return; }
  const createPlan = event.target.closest('[data-create-plan]');
  if (createPlan) { await createRemediationPlan(createPlan.dataset.createPlan, createPlan); return; }
  const executePlan = event.target.closest('[data-execute-plan]');
  if (executePlan) { openExecution(executePlan.dataset.executePlan); return; }
  const saveAccount = event.target.closest('[data-save-account]');
  if (saveAccount) { const select = $(`account-role-${saveAccount.dataset.saveAccount}`); await updateAccount(saveAccount.dataset.saveAccount, { role: select.value }, saveAccount); return; }
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
  if (scan) { if (!need('source:scan')) return; scan.disabled = true; try { const result = await api(`/api/sources/${encodeURIComponent(scan.dataset.sourceScan)}/scan-now`, { method: 'POST', body: '{}' }); toast(`采集完成：${result.lines_read ?? 0} 行日志，${result.anomalies_detected ?? 0} 个异常`); await loadSources(); await overview(); } catch (error) { toast(error.message, true); } finally { if (scan.isConnected) scan.disabled = !can('source:scan'); } return; }
  const remove = event.target.closest('[data-source-delete]');
  if (remove) {
    if (!need('source:manage')) return;
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
  const accountEnabled = event.target.closest('[data-account-enabled]');
  if (accountEnabled) { const enabled = accountEnabled.checked; if (!enabled && !window.confirm('停用此账号后，该账号将无法访问工作区。确定停用？')) { accountEnabled.checked = true; return; } await updateAccount(accountEnabled.dataset.accountEnabled, { enabled }, accountEnabled); return; }
  const toggle = event.target.closest('[data-source-toggle]');
  if (!toggle) return;
  if (!need('source:manage')) return;
  const enabled = toggle.checked;
  toggle.disabled = true;
  try { await api(`/api/sources/${encodeURIComponent(toggle.dataset.sourceToggle)}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }); toast(enabled ? '已启用监控' : '已暂停监控'); await loadSources(); await overview(); }
  catch (error) { toggle.checked = !enabled; toast(error.message, true); }
  finally { if (toggle.isConnected) toggle.disabled = !can('source:manage'); }
});
$('source-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!need('source:manage')) return;
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
  if (!need('incident:write')) return;
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
  if (!need('incident:write')) return;
  const resolution = $('resolution').value.trim();
  if (!resolution) { $('resolve-error').textContent = '请记录实际处置结果'; return; }
  const button = event.currentTarget.querySelector('[type="submit"]');
  button.disabled = true;
  $('resolve-error').textContent = '';
  try { await api(`/api/incidents/${encodeURIComponent(state.selectedId)}`, { method: 'PATCH', body: JSON.stringify({ status: 'resolved', resolution, operator: state.user?.username }) }); $('resolve-dialog').close(); toast('解决结果已保存，复盘已更新'); await refreshDetail(); await loadIncidents(); await overview(); }
  catch (error) { $('resolve-error').textContent = error.message; }
  finally { button.disabled = false; }
});
$('inject-demo').addEventListener('click', async () => {
  if (!need('incident:write')) return;
  $('inject-demo').disabled = true;
  $('demo-feedback').textContent = '';
  try { const data = await api('/api/demo/events', { method: 'POST', body: JSON.stringify({ scenario: $('demo-scenario').value }) }); $('demo-feedback').textContent = data.message || '异常已写入演示日志，等待自动采集'; toast('演示异常已注入，自动监控正在检测'); await refresh(); }
  catch (error) { $('demo-feedback').textContent = `注入失败：${error.message}`; toast(error.message, true); }
  finally { $('inject-demo').disabled = !can('incident:write'); }
});
$('manual-example').addEventListener('change', async () => {
  const selected = $('manual-example').selectedOptions[0];
  if (!selected.value) return;
  try { const response = await fetch(`/examples/${encodeURIComponent(selected.value)}`); if (!response.ok) throw new Error('样例日志加载失败'); $('manual-logs').value = await response.text(); $('manual-source').value = selected.dataset.source; $('manual-error').textContent = ''; }
  catch (error) { $('manual-error').textContent = error.message; }
});
$('manual-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!need('incident:write')) return;
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
  const button = $('auth-submit'); button.disabled = true;
  $('auth-error').textContent = ''; state.busy = true;
  try {
    const data = await api(state.bootstrap ? '/api/auth/bootstrap' : '/api/auth/login', { method: 'POST', body: JSON.stringify({ username: $('auth-username').value.trim(), password: $('auth-password').value }) });
    storeToken(data.token); state.epoch++; state.user = null; clearPrivateData(); $('auth-form').reset();
    await loadIdentity(); $('auth-dialog').close(); toast('账号已登录'); state.busy = false; await switchView('incidents');
  }
  catch (error) { $('auth-error').textContent = error.message; }
  finally { button.disabled = false; state.busy = false; }
});
$('token-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { storeToken($('access-token').value.trim()); state.epoch++; state.user = null; clearPrivateData(); await loadIdentity(); if (!state.user.authenticated) throw new Error('访问令牌未关联可用账号。'); $('access-token').value = ''; $('auth-dialog').close(); toast('访问令牌已生效'); await switchView('incidents'); }
  catch (error) { $('auth-error').textContent = error.message; }
});
$('logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); }
  catch (error) { toast(error.message, true); }
  finally { try { storeToken(''); } catch {} state.epoch++; state.user = null; clearPrivateData(); showView('incidents'); updateIdentity(); $('auth-form').reset(); $('access-token').value = ''; globalError(); }
});
$('knowledge-file').addEventListener('change', async () => {
  const file = $('knowledge-file').files[0];
  if (!file) return;
  if (file.size > 2_000_000) { $('import-error').textContent = '文件不能超过 2 MB'; return; }
  try { $('knowledge-json').value = await file.text(); $('import-error').textContent = ''; } catch { $('import-error').textContent = '知识文件读取失败'; }
});
$('import-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!need('knowledge:import')) return;
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
$('open-manual').addEventListener('click', () => { if (need('incident:write')) $('manual-dialog').showModal(); });
$('open-auth').addEventListener('click', openAuth);
$('session-login').addEventListener('click', openAuth);
$('import-knowledge').addEventListener('click', () => { if (!need('knowledge:import')) return; $('import-error').textContent = ''; $('import-dialog').showModal(); });
$('refresh-all').addEventListener('click', async () => { await refresh(); if (state.view === 'knowledge') { try { await loadKnowledge(); } catch (error) { globalError(error.message); } } });
$('refresh-knowledge').addEventListener('click', async () => { try { await loadKnowledge(); } catch (error) { globalError(error.message); } });
$('search-knowledge').addEventListener('click', async () => { try { await loadKnowledge(); } catch (error) { globalError(error.message); } });
$('knowledge-search').addEventListener('keydown', async (event) => { if (event.key === 'Enter') { try { await loadKnowledge(); } catch (error) { globalError(error.message); } } });
$('refresh-audit').addEventListener('click', async () => { try { await loadAudit(); } catch (error) { globalError(error.message); } });
[['refresh-campaigns', loadCampaigns], ['refresh-learning', loadLearning]].forEach(([id, loader]) => $(id).addEventListener('click', async () => { if (!need('incident:read')) return; try { await loader(); } catch (error) { globalError(error.message); } }));
$('incident-search').addEventListener('input', renderIncidentRows);
['environment-filter', 'severity-filter', 'status-filter'].forEach((id) => $(id).addEventListener('change', renderIncidentRows));
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
$('demo-scenario').insertAdjacentHTML('beforeend', '<option value="warning">低等级缓存告警 · 辅助处置</option>');
[$('auth-username'), $('account-form').elements.username].forEach((input) => { input.maxLength = 64; input.minLength = 3; input.pattern = '[A-Za-z0-9][A-Za-z0-9_.-]{2,63}'; });
clearPrivateData();
updateIdentity();
icons();
refresh();
setInterval(refresh, 5000);

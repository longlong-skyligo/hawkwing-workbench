import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, Bot, Boxes, FileText, Globe2, Link, Play, Radar, Save, Settings, ShieldCheck, Workflow, X } from 'lucide-react'
import './styles.css'

const API = import.meta.env.VITE_API_BASE || ''

type Lang = 'zh' | 'en'
type Workspace = { id: number; name: string; description: string; status: string }
type Finding = { id: number; target: string; title: string; severity: string; confidence: number; risk_score: number; status: string; source_tool: string }
type PentestJob = { id: number; finding_id: number; target: string; runner_image: string; runner_profile: string; status: string; result_summary: string }
type Stage = { key: string; label: string; status: string; count: number }
type Evidence = { id: number; file_type: string; path: string; sha256: string; pentest_job_id?: number }
type SessionRef = { id: number; session_type: string; target: string; tool: string; status: string; approval_ref: string; notes: string }
type ProviderDefaults = Record<string, { label: string; api_base: string; model: string; compatible: string }>
type AIConfig = {
  provider: string
  provider_label: string
  providers: ProviderDefaults
  api_base: string
  api_base_configured: boolean
  api_key_configured: boolean
  api_key_masked: string
  model: string
  source: string
}
type ExecutionPlan = {
  id: number
  status: string
  risk_summary: string
  plan: {
    ai_initial_analysis?: string
    recommended_parallelism?: { total_containers: number; max_parallel: number; per_target_limit: number; high_risk_max: number }
    containers?: Array<{
      name: string
      runner_profile: string
      image: string
      risk_level: string
      tools: string[]
      targets: string[]
      ai_recommendation?: { rationale: string; focus_tools: string[]; next_checks: string[]; confidence: number; fallback_runner: string }
    }>
    dynamic_images?: Array<{ name: string; base_image: string; policy_allowed: boolean; policy_reasons: string[] }>
  }
}

const text = {
  zh: {
    product: '鹰翼外部靶场 AI 攻防工作台',
    subtitle: '扫描、复核、评估容器方案、人工批准执行、沉淀证据并生成报告。',
    newWorkspace: '新建工作区',
    workspaces: '工作区',
    aiConfigured: 'AI 已配置',
    aiMissing: 'AI 未配置',
    configureAI: '配置 AI',
    language: '语言',
    stage: '阶段可视化',
    targets: '目标',
    importTargets: '导入目标',
    startScan: '启动标准扫描',
    findings: '漏洞发现',
    noFindings: '暂无发现。请先导入目标并启动扫描。',
    planAssessment: '执行前容器评估',
    aiInitialAnalysis: 'AI 初步判题分析',
    aiRationale: 'AI 推荐理由',
    nextChecks: '建议检查',
    assessPlan: '评估选中漏洞的执行方案',
    approvePlan: '批准最新方案',
    executePlan: '执行最新方案',
    runnerJobs: 'Runner 任务',
    noJobs: '暂无 Runner 任务。',
    sessions: '授权会话登记',
    sessionTarget: '目标或路由',
    sessionTool: '已批准工具',
    registerSession: '登记会话引用',
    noSessions: '暂无授权会话引用。',
    evidence: '证据索引',
    noEvidence: 'Runner 任务完成后会在这里出现证据。',
    report: '报告',
    reportDesc: '根据漏洞、执行计划、Runner 任务和证据引用生成 Markdown 报告。',
    generateReport: '生成 Markdown 报告',
    emptyTitle: '外部靶场工作台',
    selected: '已选',
    policyOk: '策略通过',
    policyBlocked: '策略阻断',
    requiresApproval: '需要人工批准',
    noApprovalRef: '无批准引用',
    aiSettings: 'AI 配置',
    provider: '供应商',
    apiKey: 'API Key',
    apiKeyHint: '留空表示保持现有密钥',
    baseUrl: 'Base URL',
    baseUrlHint: '官方供应商自动填写；自定义供应商需要填写 OpenAI-compatible 地址。',
    model: '模型',
    source: '来源',
    save: '保存',
    close: '关闭',
    saved: 'AI 配置已保存',
    workspaceCreated: '工作区已创建',
    targetsImported: '个目标已导入',
    scanQueued: '扫描任务已排队',
    planCreated: '执行方案已创建',
    planApproved: '执行方案已批准',
    planSubmitted: '执行方案已提交',
    sessionRegistered: '会话引用已登记',
    reportGenerated: '报告已生成',
    stageLabels: { targets: '目标', scan: '扫描', review: '复核', plan: '计划', execute: '执行', evidence: '证据', sessions: '会话', report: '报告' },
    statusLabels: { pending: '待处理', active: '进行中', done: '完成', queued: '排队中', running: '运行中', completed: '完成', draft: '草稿', approved: '已批准', executing: '执行中' }
  },
  en: {
    product: 'HawkWing External Range AI Workbench',
    subtitle: 'Scan, review, assess container plans, approve execution, collect evidence, and generate reports.',
    newWorkspace: 'New workspace',
    workspaces: 'Workspaces',
    aiConfigured: 'AI configured',
    aiMissing: 'AI not configured',
    configureAI: 'Configure AI',
    language: 'Language',
    stage: 'Stage Visualization',
    targets: 'Targets',
    importTargets: 'Import targets',
    startScan: 'Start standard scan',
    findings: 'Findings',
    noFindings: 'No findings yet. Import targets and start a scan.',
    planAssessment: 'Execution Plan Assessment',
    aiInitialAnalysis: 'AI Initial Analysis',
    aiRationale: 'AI Rationale',
    nextChecks: 'Recommended Checks',
    assessPlan: 'Assess plan for selected findings',
    approvePlan: 'Approve latest plan',
    executePlan: 'Execute latest plan',
    runnerJobs: 'Runner Jobs',
    noJobs: 'No runner jobs yet.',
    sessions: 'Approved Session Registry',
    sessionTarget: 'target or route',
    sessionTool: 'approved tool',
    registerSession: 'Register session reference',
    noSessions: 'No approved session references yet.',
    evidence: 'Evidence Index',
    noEvidence: 'Evidence will appear after runner jobs complete.',
    report: 'Report',
    reportDesc: 'Generate a Markdown report from findings, execution plans, runner jobs, and evidence references.',
    generateReport: 'Generate Markdown report',
    emptyTitle: 'External Range Workbench',
    selected: 'selected',
    policyOk: 'policy ok',
    policyBlocked: 'policy blocked',
    requiresApproval: 'requires approval',
    noApprovalRef: 'no approval ref',
    aiSettings: 'AI Settings',
    provider: 'Provider',
    apiKey: 'API Key',
    apiKeyHint: 'Leave blank to keep the current key',
    baseUrl: 'Base URL',
    baseUrlHint: 'Official providers are auto-filled. Custom providers require an OpenAI-compatible endpoint.',
    model: 'Model',
    source: 'Source',
    save: 'Save',
    close: 'Close',
    saved: 'AI configuration saved',
    workspaceCreated: 'Workspace created',
    targetsImported: 'targets imported',
    scanQueued: 'Scan job queued',
    planCreated: 'Execution plan created',
    planApproved: 'Execution plan approved',
    planSubmitted: 'Execution plan submitted',
    sessionRegistered: 'Session reference registered',
    reportGenerated: 'Report generated',
    stageLabels: { targets: 'Targets', scan: 'Scan', review: 'Review', plan: 'Plan', execute: 'Execute', evidence: 'Evidence', sessions: 'Sessions', report: 'Report' },
    statusLabels: { pending: 'pending', active: 'active', done: 'done', queued: 'queued', running: 'running', completed: 'completed', draft: 'draft', approved: 'approved', executing: 'executing' }
  }
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init
  })
  if (!response.ok) throw new Error(await response.text())
  return response.json()
}

function App() {
  const [lang, setLang] = useState<Lang>('zh')
  const copy = text[lang]
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [active, setActive] = useState<Workspace | null>(null)
  const [targets, setTargets] = useState('10.10.10.5\nhttp://target.example')
  const [scenario, setScenario] = useState('外部靶场 Web 验证。可在这里补充 AD、取证、固件、云、代理、提权等题目信息。')
  const [findings, setFindings] = useState<Finding[]>([])
  const [jobs, setJobs] = useState<PentestJob[]>([])
  const [plans, setPlans] = useState<ExecutionPlan[]>([])
  const [stages, setStages] = useState<Stage[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [sessions, setSessions] = useState<SessionRef[]>([])
  const [selected, setSelected] = useState<number[]>([])
  const [sessionTarget, setSessionTarget] = useState('10.10.10.5')
  const [sessionTool, setSessionTool] = useState('approved-proxy')
  const [aiConfig, setAiConfig] = useState<AIConfig | null>(null)
  const [aiOpen, setAiOpen] = useState(false)
  const [aiForm, setAiForm] = useState({ provider: 'openai', api_base: '', api_key: '', model: 'gpt-4.1-mini' })
  const [catalogInfo, setCatalogInfo] = useState({ tools: 0, runners: 0, skills: 0 })
  const [message, setMessage] = useState('')

  const selectedCount = useMemo(() => selected.length, [selected])
  const latestPlan = plans[0]
  const providers = aiConfig?.providers || {}
  const selectedProvider = providers[aiForm.provider]
  const customProvider = aiForm.provider === 'custom'

  function statusLabel(value: string) {
    return copy.statusLabels[value as keyof typeof copy.statusLabels] || value
  }

  async function refresh() {
    const ws = await api<Workspace[]>('/api/workspaces')
    setWorkspaces(ws)
    const current = active || ws[0] || null
    if (!active && current) setActive(current)
    if (current) {
      setFindings(await api<Finding[]>(`/api/workspaces/${current.id}/findings`))
      setJobs(await api<PentestJob[]>(`/api/workspaces/${current.id}/pentest-jobs`))
      setPlans(await api<ExecutionPlan[]>(`/api/workspaces/${current.id}/execution-plans`))
      const stageResult = await api<{ stages: Stage[] }>(`/api/workspaces/${current.id}/stage-summary`)
      setStages(stageResult.stages)
      setEvidence(await api<Evidence[]>(`/api/workspaces/${current.id}/evidence`))
      setSessions(await api<SessionRef[]>(`/api/workspaces/${current.id}/sessions`))
    }
    const config = await api<AIConfig>('/api/ai/config')
    setAiConfig(config)
    const tools = await api<{ tools: Record<string, unknown> }>('/api/tools/catalog')
    const runners = await api<{ runner_profiles: Record<string, unknown> }>('/api/runners/profiles')
    const skills = await api<{ skills: Record<string, unknown> }>('/api/skills')
    setCatalogInfo({
      tools: Object.keys(tools.tools || {}).length,
      runners: Object.keys(runners.runner_profiles || {}).length,
      skills: Object.keys(skills.skills || {}).length
    })
  }

  useEffect(() => {
    refresh().catch((err) => setMessage(err.message))
    const timer = setInterval(() => refresh().catch(() => undefined), 5000)
    return () => clearInterval(timer)
  }, [active?.id])

  function openAiSettings() {
    const config = aiConfig
    setAiForm({
      provider: config?.provider || 'openai',
      api_base: config?.api_base || config?.providers?.openai?.api_base || '',
      api_key: '',
      model: config?.model || config?.providers?.openai?.model || 'gpt-4.1-mini'
    })
    setAiOpen(true)
  }

  function chooseProvider(provider: string) {
    const next = providers[provider]
    setAiForm({
      ...aiForm,
      provider,
      api_base: provider === 'custom' ? aiForm.api_base : next?.api_base || '',
      model: next?.model || aiForm.model
    })
  }

  async function saveAiConfig() {
    const saved = await api<AIConfig>('/api/ai/config', {
      method: 'PUT',
      body: JSON.stringify(aiForm)
    })
    setAiConfig(saved)
    setAiOpen(false)
    setMessage(copy.saved)
  }

  async function createWorkspace() {
    const ws = await api<Workspace>('/api/workspaces', {
      method: 'POST',
      body: JSON.stringify({ name: `range-${new Date().toISOString().slice(0, 19)}`, description: 'Temporary external range workspace' })
    })
    setActive(ws)
    setMessage(`${copy.workspaceCreated} #${ws.id}`)
    await refresh()
  }

  async function importTargets() {
    if (!active) return
    const list = targets.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)
    await api(`/api/workspaces/${active.id}/targets/import`, {
      method: 'POST',
      body: JSON.stringify({ targets: list })
    })
    setMessage(`${list.length} ${copy.targetsImported}`)
  }

  async function startScan() {
    if (!active) return
    await api(`/api/workspaces/${active.id}/scan/start`, {
      method: 'POST',
      body: JSON.stringify({ mode: 'standard' })
    })
    setMessage(copy.scanQueued)
    setTimeout(refresh, 1500)
  }

  async function assessPlan() {
    if (!active || selected.length === 0) return
    const result = await api<{ plan_id: number }>(`/api/workspaces/${active.id}/execution-plans/assess`, {
      method: 'POST',
      body: JSON.stringify({ finding_ids: selected, scenario_text: scenario, allow_dynamic: true })
    })
    setMessage(`${copy.planCreated} #${result.plan_id}`)
    setTimeout(refresh, 800)
  }

  async function approvePlan(planId: number) {
    await api(`/api/execution-plans/${planId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved_by: 'operator' })
    })
    setMessage(`${copy.planApproved} #${planId}`)
    setTimeout(refresh, 800)
  }

  async function executePlan(planId: number) {
    await api(`/api/execution-plans/${planId}/execute`, { method: 'POST' })
    setMessage(`${copy.planSubmitted} #${planId}`)
    setSelected([])
    setTimeout(refresh, 1200)
  }

  async function registerSession() {
    if (!active) return
    await api(`/api/workspaces/${active.id}/sessions`, {
      method: 'POST',
      body: JSON.stringify({
        session_type: 'pivot',
        target: sessionTarget,
        tool: sessionTool,
        status: 'registered',
        approval_ref: latestPlan ? `execution-plan-${latestPlan.id}` : '',
        notes: 'Approved session metadata only. The platform does not auto-deploy webshells or covert channels.'
      })
    })
    setMessage(copy.sessionRegistered)
    setTimeout(refresh, 800)
  }

  async function generateReport() {
    if (!active) return
    const result = await api<{ report_path: string }>(`/api/workspaces/${active.id}/report/generate`, { method: 'POST' })
    setMessage(`${copy.reportGenerated}: ${result.report_path}`)
  }

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <strong>HawkWing</strong>
            <span>{copy.product}</span>
          </div>
        </div>
        <button className="primary" onClick={createWorkspace}><Play size={16} /> {copy.newWorkspace}</button>
        <div className="side-title">{copy.workspaces}</div>
        {workspaces.map((ws) => (
          <button key={ws.id} className={`workspace ${active?.id === ws.id ? 'on' : ''}`} onClick={() => setActive(ws)}>
            #{ws.id} {ws.name}
          </button>
        ))}
      </aside>

      <main>
        <header>
          <div>
            <h1>{active ? active.name : copy.emptyTitle}</h1>
            <p>{copy.subtitle}</p>
          </div>
          <div className="header-pills">
            <div className="lang-switch" aria-label={copy.language}>
              <Globe2 size={16} />
              <button className={lang === 'zh' ? 'on' : ''} onClick={() => setLang('zh')}>中文</button>
              <button className={lang === 'en' ? 'on' : ''} onClick={() => setLang('en')}>EN</button>
            </div>
            <button className="ai-pill action-pill" onClick={openAiSettings}>
              <Bot size={16} /> {aiConfig?.api_key_configured ? copy.aiConfigured : copy.aiMissing}
              <Settings size={15} />
            </button>
            <div className="ai-pill"><Boxes size={16} /> {catalogInfo.tools} tools / {catalogInfo.runners} runners / {catalogInfo.skills} skills</div>
          </div>
        </header>

        {message && <div className="notice">{message}</div>}

        <section className="panel wide">
          <h2><Workflow size={18} /> {copy.stage}</h2>
          <div className="stage-row">
            {stages.map((stage) => (
              <div className={`stage ${stage.status}`} key={stage.key}>
                <strong>{copy.stageLabels[stage.key as keyof typeof copy.stageLabels] || stage.label}</strong>
                <span>{statusLabel(stage.status)}</span>
                <small>{stage.count}</small>
              </div>
            ))}
          </div>
        </section>

        <section className="grid">
          <div className="panel">
            <h2><Radar size={18} /> {copy.targets}</h2>
            <textarea value={targets} onChange={(e) => setTargets(e.target.value)} />
            <div className="actions">
              <button onClick={importTargets} disabled={!active}>{copy.importTargets}</button>
              <button onClick={startScan} disabled={!active}><Activity size={16} /> {copy.startScan}</button>
            </div>
          </div>

          <div className="panel">
            <h2><Activity size={18} /> {copy.findings}</h2>
            <div className="table">
              {findings.map((finding) => (
                <label className="row" key={finding.id}>
                  <input
                    type="checkbox"
                    checked={selected.includes(finding.id)}
                    onChange={(e) => setSelected(e.target.checked ? [...selected, finding.id] : selected.filter((id) => id !== finding.id))}
                  />
                  <span className="score">{finding.risk_score.toFixed(1)}</span>
                  <span>
                    <strong>{finding.title}</strong>
                    <small>{finding.target} / {finding.severity} / {finding.source_tool}</small>
                  </span>
                </label>
              ))}
              {findings.length === 0 && <p className="empty">{copy.noFindings}</p>}
            </div>
          </div>
        </section>

        <section className="panel wide">
          <h2><Workflow size={18} /> {copy.planAssessment}</h2>
          <textarea value={scenario} onChange={(e) => setScenario(e.target.value)} />
          <div className="actions">
            <button onClick={assessPlan} disabled={!active || selectedCount === 0}>{copy.assessPlan} ({selectedCount} {copy.selected})</button>
            {latestPlan && latestPlan.status === 'draft' && <button onClick={() => approvePlan(latestPlan.id)}>{copy.approvePlan} #{latestPlan.id}</button>}
            {latestPlan && latestPlan.status === 'approved' && <button onClick={() => executePlan(latestPlan.id)}>{copy.executePlan} #{latestPlan.id}</button>}
          </div>
          {latestPlan && (
            <div className="plan">
              <strong>#{latestPlan.id}: {statusLabel(latestPlan.status)}</strong>
              <small>{latestPlan.risk_summary}</small>
              {latestPlan.plan.ai_initial_analysis && (
                <div className="ai-analysis">
                  <strong>{copy.aiInitialAnalysis}</strong>
                  <p>{latestPlan.plan.ai_initial_analysis}</p>
                </div>
              )}
              <div className="plan-grid">
                {(latestPlan.plan.containers || []).map((item) => (
                  <div className="plan-item" key={item.name}>
                    <strong>{item.runner_profile}</strong>
                    <span>{item.risk_level}</span>
                    <small>{item.image}</small>
                    <small>{item.tools.slice(0, 6).join(', ')}</small>
                    {item.ai_recommendation && (
                      <div className="runner-reason">
                        <strong>{copy.aiRationale}</strong>
                        <small>{item.ai_recommendation.rationale}</small>
                        {item.ai_recommendation.next_checks?.length > 0 && (
                          <small>{copy.nextChecks}: {item.ai_recommendation.next_checks.slice(0, 3).join(' / ')}</small>
                        )}
                      </div>
                    )}
                  </div>
                ))}
                {(latestPlan.plan.dynamic_images || []).map((item) => (
                  <div className="plan-item dynamic" key={item.name}>
                    <strong>{item.name}</strong>
                    <span>{item.policy_allowed ? copy.policyOk : copy.policyBlocked}</span>
                    <small>{item.base_image}</small>
                    <small>{(item.policy_reasons || []).join('; ') || copy.requiresApproval}</small>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        <section className="panel wide">
          <h2><Boxes size={18} /> {copy.runnerJobs}</h2>
          <div className="job-list">
            {jobs.map((job) => (
              <div className="job" key={job.id}>
                <strong>#{job.id} Finding-{job.finding_id}</strong>
                <span>{statusLabel(job.status)}</span>
                <small>{job.runner_profile || job.runner_image}</small>
                <small>{job.result_summary}</small>
              </div>
            ))}
            {jobs.length === 0 && <p className="empty">{copy.noJobs}</p>}
          </div>
        </section>

        <section className="grid">
          <div className="panel">
            <h2><Link size={18} /> {copy.sessions}</h2>
            <div className="session-form">
              <input value={sessionTarget} onChange={(e) => setSessionTarget(e.target.value)} placeholder={copy.sessionTarget} />
              <input value={sessionTool} onChange={(e) => setSessionTool(e.target.value)} placeholder={copy.sessionTool} />
              <button onClick={registerSession} disabled={!active}>{copy.registerSession}</button>
            </div>
            <div className="mini-list">
              {sessions.map((item) => (
                <div className="mini-item" key={item.id}>
                  <strong>{item.session_type}: {item.target}</strong>
                  <small>{item.tool} / {statusLabel(item.status)} / {item.approval_ref || copy.noApprovalRef}</small>
                </div>
              ))}
              {sessions.length === 0 && <p className="empty">{copy.noSessions}</p>}
            </div>
          </div>

          <div className="panel">
            <h2><FileText size={18} /> {copy.evidence}</h2>
            <div className="mini-list">
              {evidence.slice(0, 12).map((item) => (
                <div className="mini-item" key={item.id}>
                  <strong>{item.file_type} #{item.id}</strong>
                  <small>{item.path}</small>
                  <small>{item.sha256.slice(0, 16)}...</small>
                </div>
              ))}
              {evidence.length === 0 && <p className="empty">{copy.noEvidence}</p>}
            </div>
          </div>
        </section>

        <section className="panel wide">
          <h2><FileText size={18} /> {copy.report}</h2>
          <p>{copy.reportDesc}</p>
          <button onClick={generateReport} disabled={!active}>{copy.generateReport}</button>
        </section>
      </main>

      {aiOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal">
            <div className="modal-head">
              <div>
                <h2><Bot size={18} /> {copy.aiSettings}</h2>
                <small>{aiConfig?.api_key_configured ? `${copy.apiKey}: ${aiConfig.api_key_masked}` : copy.aiMissing}</small>
              </div>
              <button className="icon-button" onClick={() => setAiOpen(false)} aria-label={copy.close}><X size={18} /></button>
            </div>
            <label className="field">
              <span>{copy.provider}</span>
              <div className="provider-grid">
                {Object.keys(providers).map((provider) => (
                  <button key={provider} className={aiForm.provider === provider ? 'on' : ''} onClick={() => chooseProvider(provider)}>
                    {providers[provider].label}
                  </button>
                ))}
              </div>
            </label>
            <label className="field">
              <span>{copy.apiKey}</span>
              <input
                type="password"
                value={aiForm.api_key}
                placeholder={aiConfig?.api_key_masked || copy.apiKeyHint}
                onChange={(e) => setAiForm({ ...aiForm, api_key: e.target.value })}
              />
              <small>{copy.apiKeyHint}</small>
            </label>
            <label className="field">
              <span>{copy.baseUrl}</span>
              <input
                value={customProvider ? aiForm.api_base : selectedProvider?.api_base || aiForm.api_base}
                disabled={!customProvider}
                placeholder={selectedProvider?.api_base || 'https://api.example.com/v1'}
                onChange={(e) => setAiForm({ ...aiForm, api_base: e.target.value })}
              />
              <small>{copy.baseUrlHint}</small>
            </label>
            <label className="field">
              <span>{copy.model}</span>
              <input value={aiForm.model} onChange={(e) => setAiForm({ ...aiForm, model: e.target.value })} />
            </label>
            <div className="modal-foot">
              <small>{copy.source}: {aiConfig?.source || '-'}</small>
              <button className="primary compact" onClick={saveAiConfig}><Save size={16} /> {copy.save}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<App />)

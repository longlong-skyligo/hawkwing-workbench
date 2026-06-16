import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity,
  Bot,
  CheckCircle2,
  Clipboard,
  Copy,
  Download,
  FileText,
  FolderPlus,
  Loader2,
  Play,
  Radar,
  Settings,
  ShieldCheck,
  Trash2,
  Upload,
  X
} from 'lucide-react'
import './styles.css'

const API = import.meta.env.VITE_API_BASE || ''

type Workspace = { id: number; name: string; description: string; status: string }
type Target = { id: number; type: string; value: string; enabled: number }
type Finding = { id: number; target: string; title: string; severity: string; confidence: number; risk_score: number; status: string; source_tool: string; raw_detail?: string }
type PentestJob = { id: number; finding_id: number; target: string; runner_image: string; runner_profile: string; status: string; result_summary: string }
type Evidence = { id: number; file_type: string; path: string; sha256: string; pentest_job_id?: number }
type Writeup = { id: number; pentest_job_id: number; path: string; sha256: string; download_url: string }
type Stage = { key: string; label: string; status: string; count: number }
type FlagHit = { flag: string; source: string; job_id: number; target: string; runner_profile: string }
type ProviderDefaults = Record<string, { label: string; api_base: string; model: string; compatible: string }>
type AIConfig = {
  provider: string
  providers: ProviderDefaults
  api_base: string
  api_key_configured: boolean
  api_key_masked: string
  model: string
  source: string
}
type AIReady = { ready: boolean; provider: string; model: string; error?: string; message?: string }
type ExecutionPlan = {
  id: number
  status: string
  risk_summary: string
  plan: {
    ai_initial_analysis?: string
    containers?: Array<{
      name: string
      runner_profile: string
      image: string
      risk_level: string
      tools: string[]
      targets: string[]
      ai_recommendation?: { rationale: string; focus_tools: string[]; next_checks: string[]; confidence: number; fallback_runner: string }
    }>
  }
}

const progressLabels: Record<string, string> = {
  targets: '目标',
  intake: 'AI读题',
  scan: '扫描',
  findings: '漏洞',
  plan: '方案',
  execute: '执行',
  evidence: '证据',
  report: '报告'
}

const statusText: Record<string, string> = {
  pending: '待处理',
  active: '进行中',
  done: '完成',
  queued: '排队中',
  running: '运行中',
  completed: '完成',
  failed: '失败',
  draft: '待确认',
  approved: '已确认',
  executing: '执行中'
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init
  })
  if (!response.ok) {
    const text = await response.text()
    throw new Error(text)
  }
  return response.json()
}

async function apiForm<T>(path: string, body: FormData): Promise<T> {
  const response = await fetch(`${API}${path}`, { method: 'POST', body })
  if (!response.ok) throw new Error(await response.text())
  return response.json()
}

function App() {
  const [projects, setProjects] = useState<Workspace[]>([])
  const [active, setActive] = useState<Workspace | null>(null)
  const [projectName, setProjectName] = useState('Web CTF 项目')
  const [projectDesc, setProjectDesc] = useState('请在这里粘贴题目要求、靶场地址、flag 格式、附件说明和比赛限制。')
  const [files, setFiles] = useState<FileList | null>(null)
  const [uploadedCount, setUploadedCount] = useState(0)
  const [newProjectOpen, setNewProjectOpen] = useState(false)
  const [newProjectName, setNewProjectName] = useState('Web CTF 项目')
  const [newProjectDesc, setNewProjectDesc] = useState('请在这里粘贴题目要求、靶场地址、flag 格式、附件说明和比赛限制。')
  const [targets, setTargets] = useState<Target[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [jobs, setJobs] = useState<PentestJob[]>([])
  const [plans, setPlans] = useState<ExecutionPlan[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [writeups, setWriteups] = useState<Writeup[]>([])
  const [stages, setStages] = useState<Stage[]>([])
  const [flags, setFlags] = useState<FlagHit[]>([])
  const [aiReady, setAiReady] = useState<AIReady | null>(null)
  const [aiConfig, setAiConfig] = useState<AIConfig | null>(null)
  const [aiOpen, setAiOpen] = useState(false)
  const [aiForm, setAiForm] = useState({ provider: 'openai', api_base: '', api_key: '', model: 'gpt-4.1-mini' })
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState('')
  const [reportUrl, setReportUrl] = useState('')
  const autoAssessRef = useRef<number | null>(null)
  const latestPlan = plans[0]
  const allFindingIds = useMemo(() => findings.map((item) => item.id), [findings])

  async function refresh(current = active) {
    const [ws, ready, config] = await Promise.all([
      api<Workspace[]>('/api/workspaces'),
      api<AIReady>('/api/ai/ready').catch((err) => ({ ready: false, provider: '-', model: '-', error: err.message })),
      api<AIConfig>('/api/ai/config')
    ])
    setProjects(ws)
    setAiReady(ready)
    setAiConfig(config)
    const selected = current || active || ws[0] || null
    if (!active && selected) setActive(selected)
    if (!selected) return
    const [targetData, findingData, jobData, planData, evidenceData, stageData, flagData, writeupData] = await Promise.all([
      api<Target[]>(`/api/workspaces/${selected.id}/targets`),
      api<Finding[]>(`/api/workspaces/${selected.id}/findings`),
      api<PentestJob[]>(`/api/workspaces/${selected.id}/pentest-jobs`),
      api<ExecutionPlan[]>(`/api/workspaces/${selected.id}/execution-plans`),
      api<Evidence[]>(`/api/workspaces/${selected.id}/evidence`),
      api<{ stages: Stage[] }>(`/api/workspaces/${selected.id}/stage-summary`),
      api<{ flags: FlagHit[] }>(`/api/workspaces/${selected.id}/flags`),
      api<Writeup[]>(`/api/workspaces/${selected.id}/writeups`)
    ])
    setTargets(targetData)
    setFindings(findingData)
    setJobs(jobData)
    setPlans(planData)
    setEvidence(evidenceData)
    setWriteups(writeupData)
    setStages(stageData.stages)
    setFlags(flagData.flags)
    setProjectName(selected.name)
    setProjectDesc(selected.description || '')
  }

  useEffect(() => {
    refresh().catch((err) => setMessage(err.message))
    const timer = setInterval(() => refresh().catch(() => undefined), 5000)
    return () => clearInterval(timer)
  }, [active?.id])

  // 自动评估：发现漏洞且无方案时，自动触发 AI 评估
  useEffect(() => {
    if (!active || !aiReady?.ready || findings.length === 0 || plans.length > 0) return
    if (autoAssessRef.current === active.id) return
    autoAssessRef.current = active.id
    const autoAssess = async () => {
      try {
        setBusy('plan')
        await api(`/api/workspaces/${active.id}/execution-plans/assess`, {
          method: 'POST',
          body: JSON.stringify({ finding_ids: findings.map(f => f.id), scenario_text: projectDesc, allow_dynamic: true })
        })
        setMessage('AI 已自动生成解题方案，请人工确认后执行')
        await refresh(active)
      } catch (err) {
        setMessage(String(err))
      } finally {
        setBusy('')
      }
    }
    autoAssess()
  }, [findings.length, plans.length, aiReady?.ready])

  function requireReady() {
    if (!aiReady?.ready) {
      setMessage(`AI 未连通：${aiReady?.error || '请先配置 API Key 并通过连通性检查。'}`)
      return false
    }
    return true
  }

  async function createProject() {
    if (!requireReady()) return
    setBusy('create')
    setNewProjectOpen(false)
    try {
      const ws = await api<Workspace>('/api/workspaces', {
        method: 'POST',
        body: JSON.stringify({ name: newProjectName, description: newProjectDesc })
      })
      for (const file of Array.from(files || [])) {
        const form = new FormData()
        form.append('file', file)
        await apiForm(`/api/workspaces/${ws.id}/attachments`, form)
      }
      setActive(ws)
      setMessage(`项目 #${ws.id} 已创建`)
      await refresh(ws)
    } catch (err) {
      setMessage(String(err))
    } finally {
      setBusy('')
    }
  }

  async function deleteProject(ws: Workspace) {
    if (!confirm(`确定要删除项目 #${ws.id}「${ws.name}」吗？此操作不可撤销。`)) return
    try {
      await api(`/api/workspaces/${ws.id}`, { method: 'DELETE' })
      if (active?.id === ws.id) setActive(null)
      setMessage(`项目 #${ws.id} 已删除`)
      setProjects((prev) => prev.filter((p) => p.id !== ws.id))
    } catch (err) {
      setMessage(String(err))
    }
  }

  async function startTask() {
    if (!active || !requireReady()) return
    setBusy('start')
    try {
      // 1. 保存项目信息
      const ws = await api<Workspace>(`/api/workspaces/${active.id}`, {
        method: 'PUT',
        body: JSON.stringify({ name: projectName, description: projectDesc })
      })
      // 2. 上传附件（如果有）
      let count = 0
      for (const file of Array.from(files || [])) {
        const form = new FormData()
        form.append('file', file)
        await apiForm(`/api/workspaces/${active.id}/attachments`, form)
        count++
      }
      if (count > 0) {
        setUploadedCount(count)
        setFiles(null)
      }
      // 3. AI 读题生成目标
      const intakeForm = new FormData()
      intakeForm.append('description', projectDesc)
      const intakeResult = await apiForm<{ summary: string; imported: number; targets: string[] }>(`/api/workspaces/${active.id}/intake/analyze`, intakeForm)
      setMessage(`任务已启动：AI 识别 ${intakeResult.targets.length} 个目标 → 开始扫描漏洞`)
      // 4. 自动启动漏洞扫描
      await api(`/api/workspaces/${active.id}/scan/start`, { method: 'POST', body: JSON.stringify({ mode: 'standard' }) })
      autoAssessRef.current = null
      await refresh(active)
    } catch (err) {
      setMessage(String(err))
    } finally {
      setBusy('')
    }
  }

  async function assessAll() {
    if (!active || !requireReady() || allFindingIds.length === 0) return
    setBusy('plan')
    await api(`/api/workspaces/${active.id}/execution-plans/assess`, {
      method: 'POST',
      body: JSON.stringify({ finding_ids: allFindingIds, scenario_text: projectDesc, allow_dynamic: true })
    })
    setMessage('AI 已生成针对性解题方案，请确认是否执行')
    await refresh(active)
    setBusy('')
  }

  async function approveAndExecute() {
    if (!latestPlan || !requireReady()) return
    setBusy('execute')
    if (latestPlan.status === 'draft') {
      await api(`/api/execution-plans/${latestPlan.id}/approve`, { method: 'POST', body: JSON.stringify({ approved_by: 'operator' }) })
    }
    await api(`/api/execution-plans/${latestPlan.id}/execute`, { method: 'POST' })
    setMessage('已确认执行，平台正在准备 Runner 并解题')
    setTimeout(() => refresh(active), 2500)
    setBusy('')
  }

  async function generateReport() {
    if (!active || !requireReady()) return
    const result = await api<{ report_path: string; download_url: string }>(`/api/workspaces/${active.id}/report/generate`, { method: 'POST' })
    setReportUrl(result.download_url)
    setMessage('报告已生成，可点击下载')
    await refresh(active)
  }

  async function saveAiConfig() {
    const saved = await api<AIConfig>('/api/ai/config', { method: 'PUT', body: JSON.stringify(aiForm) })
    setAiConfig(saved)
    setAiOpen(false)
    await refresh()
  }

  function openAiSettings() {
    setAiForm({
      provider: aiConfig?.provider || 'openai',
      api_base: aiConfig?.api_base || aiConfig?.providers?.openai?.api_base || '',
      api_key: '',
      model: aiConfig?.model || aiConfig?.providers?.openai?.model || 'gpt-4.1-mini'
    })
    setAiOpen(true)
  }

  function chooseProvider(provider: string) {
    const defaults = aiConfig?.providers?.[provider]
    setAiForm({
      ...aiForm,
      provider,
      api_base: provider === 'custom' ? aiForm.api_base : defaults?.api_base || '',
      model: defaults?.model || aiForm.model
    })
  }

  function copyFlag(value: string) {
    navigator.clipboard?.writeText(value)
    setMessage('Flag 已复制')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={26} />
          <div>
            <strong>HawkWing</strong>
            <span>AI 解题工作台</span>
          </div>
        </div>
        <button className="primary" onClick={() => { setNewProjectOpen(true) }} disabled={!aiReady?.ready}>
          <FolderPlus size={16} /> 新建项目
        </button>
        <div className="side-caption">项目列表</div>
        <div className="project-list">
          {projects.map((item) => (
            <div key={item.id} className={`project-item ${active?.id === item.id ? 'on' : ''}`}>
              <button className="project-item-btn" onClick={() => setActive(item)}>
                <span>#{item.id}</span>
                <strong>{item.name}</strong>
              </button>
              <button className="project-delete-btn" onClick={(e) => { e.stopPropagation(); deleteProject(item); }} title="删除项目">
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <h1>{active ? active.name : '新项目'}</h1>
            <p>AI 读题、自动扫描、智能评估 Runner、人工确认执行、提取 flag、生成报告。</p>
          </div>
          <div className="top-actions">
            <div className={`ai-state ${aiReady?.ready ? 'ready' : 'blocked'}`}>
              <Bot size={16} />
              <span>{aiReady?.ready ? `AI 已连通 · ${aiReady.provider}` : 'AI 未连通'}</span>
            </div>
            <button onClick={openAiSettings}><Settings size={16} /> AI 配置</button>
          </div>
        </header>

        {!aiReady?.ready && (
          <div className="blocking-banner">
            <strong>AI 未通过连通性检查，项目流程已锁定。</strong>
            <span>{aiReady?.error || '请配置 API Key、Base URL 和模型后重试。'}</span>
          </div>
        )}

        <section className={`flag-strip ${flags.length ? 'found' : ''}`}>
          <div>
            <strong>{flags.length ? '已发现 Flag' : 'Flag 监控'}</strong>
            <span>{flags.length ? '点击复制候选答案，提交前请人工复核。' : 'Runner 找到候选 flag 后会在这里高亮显示。'}</span>
          </div>
          <div className="flag-list">
            {flags.length === 0 && <code>waiting-for-flag</code>}
            {flags.map((item) => (
              <button className="flag-code" key={`${item.job_id}-${item.flag}`} onClick={() => copyFlag(item.flag)}>
                <code>{item.flag}</code>
                <Copy size={14} />
              </button>
            ))}
          </div>
        </section>

        <section className="progress-panel">
          <div className="progress-line">
            {stages.map((stage, index) => (
              <div className={`progress-node ${stage.status}`} key={stage.key}>
                <div className="dot">{stage.status === 'done' ? <CheckCircle2 size={15} /> : index + 1}</div>
                <strong>{progressLabels[stage.key] || stage.label}</strong>
                <span>{statusText[stage.status] || stage.status}</span>
              </div>
            ))}
          </div>
        </section>

        {message && <div className="notice">{message}</div>}

        <section className="work-grid">
          <div className="panel project-panel">
            <div className="panel-head">
              <div className="panel-title"><Clipboard size={18} /> 项目信息</div>
              <button className="primary compact" onClick={startTask} disabled={!active || !aiReady?.ready || busy === 'start'}>
                {busy === 'start' ? <Loader2 className="spin" size={16} /> : <Play size={16} />} Start
              </button>
            </div>
            <input value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="项目名称" />
            <textarea value={projectDesc} onChange={(e) => setProjectDesc(e.target.value)} placeholder="题目描述、目标地址、flag 格式、附件说明" />
            <label className="upload-box">
              <Upload size={18} />
              <span>
                {uploadedCount > 0
                  ? `${uploadedCount} 个附件已上传`
                  : files?.length
                    ? `${files.length} 个附件待上传`
                    : '上传附件'}
              </span>
              <input type="file" multiple onChange={(e) => { setFiles(e.target.files); setUploadedCount(0); }} />
            </label>
          </div>

          <div className="panel targets-panel">
            <div className="panel-title"><Radar size={18} /> AI识别目标</div>
            <div className="scroll-list compact-list">
              {targets.map((item) => (
                <div className="target-row" key={item.id}>
                  <code>{item.value}</code>
                  <span>{item.type}</span>
                </div>
              ))}
              {targets.length === 0 && <p className="empty">AI 读题后会自动生成目标。</p>}
            </div>
          </div>

          <div className="panel findings-panel">
            <div className="panel-title"><Activity size={18} /> 漏洞发现</div>
            <div className="scroll-list">
              {findings.map((finding, index) => (
                <div className="finding-row" key={finding.id}>
                  <span className="number">{index + 1}</span>
                  <span className="risk">{finding.risk_score.toFixed(1)}</span>
                  <div>
                    <strong>{finding.title}</strong>
                    <small>{finding.target} · {finding.severity} · {finding.source_tool}</small>
                  </div>
                </div>
              ))}
              {findings.length === 0 && <p className="empty">扫描完成后按风险排序展示漏洞。</p>}
            </div>
          </div>

          <div className="panel plan-panel">
            <div className="panel-head">
              <div className="panel-title"><Bot size={18} /> AI解题方案</div>
              <button className="primary compact" onClick={approveAndExecute} disabled={!latestPlan || !aiReady?.ready || busy === 'execute'}>
                <Play size={16} /> 确认执行
              </button>
            </div>
            <div className="scroll-list">
              {!latestPlan && <p className="empty">AI 评估漏洞后会在这里给出 Runner 和解题步骤。</p>}
              {latestPlan?.plan.ai_initial_analysis && <div className="analysis-card">{latestPlan.plan.ai_initial_analysis}</div>}
              {latestPlan?.plan.containers?.map((item) => (
                <div className="runner-card" key={item.name}>
                  <strong>{item.runner_profile}</strong>
                  <span>{item.risk_level}</span>
                  <small>{item.image}</small>
                  <p>{item.ai_recommendation?.rationale || '等待 AI 推荐理由'}</p>
                  {item.ai_recommendation?.next_checks?.slice(0, 4).map((step) => <small key={step}>- {step}</small>)}
                </div>
              ))}
            </div>
          </div>

          <div className="panel jobs-panel">
            <div className="panel-title"><Play size={18} /> Runner 执行</div>
            <div className="scroll-list">
              {jobs.map((job) => (
                <div className="job-row" key={job.id}>
                  <strong>#{job.id} · {job.runner_profile}</strong>
                  <span className={`job-status ${job.status}`}>{statusText[job.status] || job.status}</span>
                  <small>{job.result_summary || job.target}</small>
                </div>
              ))}
              {jobs.length === 0 && <p className="empty">人工确认后自动拉取/构建 Runner 并开始解题。</p>}
            </div>
          </div>

          <div className="panel evidence-panel">
            <div className="panel-title"><FileText size={18} /> 证据索引</div>
            <div className="scroll-list">
              {evidence.map((item) => (
                <div className="evidence-row" key={item.id}>
                  <strong>{item.file_type} #{item.id}</strong>
                  <small>{item.path}</small>
                  <div className="row-actions">
                    <code>{item.sha256.slice(0, 18)}</code>
                    <a className="tiny-link" href={`${API}/api/workspaces/${active?.id}/evidence/${item.id}/download`} target="_blank" rel="noreferrer">下载</a>
                  </div>
                </div>
              ))}
              {evidence.length === 0 && <p className="empty">Runner 运行后证据会自动入库。</p>}
            </div>
          </div>

          <div className="panel report-panel">
            <div className="panel-title"><Download size={18} /> 报告</div>
            <p>报告会汇总题目、目标、漏洞、AI 方案、Runner 结果、候选 flag 和证据索引。</p>
            <div className="writeup-links">
              {writeups.map((item) => (
                <a className="download-link" key={item.id} href={`${API}${item.download_url}`} target="_blank" rel="noreferrer">
                  <Download size={16} /> Runner #{item.pentest_job_id} Writeup
                </a>
              ))}
            </div>
            <div className="actions">
              <button onClick={generateReport} disabled={!active || !aiReady?.ready}><FileText size={16} /> 生成报告</button>
              {reportUrl && <a className="download-link" href={`${API}${reportUrl}`} target="_blank" rel="noreferrer"><Download size={16} /> 下载报告</a>}
            </div>
          </div>
        </section>
      </main>

      {newProjectOpen && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="modal-head">
              <h2><FolderPlus size={18} /> 新建项目</h2>
              <button className="icon-button" onClick={() => setNewProjectOpen(false)}><X size={18} /></button>
            </div>
            <label className="field">
              <span>项目名称</span>
              <input value={newProjectName} onChange={(e) => setNewProjectName(e.target.value)} placeholder="输入项目名称" />
            </label>
            <label className="field">
              <span>项目描述</span>
              <textarea value={newProjectDesc} onChange={(e) => setNewProjectDesc(e.target.value)} placeholder="题目要求、靶场地址、flag 格式、附件说明和比赛限制" />
            </label>
            <div className="modal-foot">
              <small>创建后可上传附件并继续配置</small>
              <button className="primary compact" onClick={createProject} disabled={busy === 'create'}>
                {busy === 'create' ? <Loader2 className="spin" size={16} /> : <FolderPlus size={16} />} 创建项目
              </button>
            </div>
          </div>
        </div>
      )}

      {aiOpen && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="modal-head">
              <h2><Bot size={18} /> AI 配置</h2>
              <button className="icon-button" onClick={() => setAiOpen(false)}><X size={18} /></button>
            </div>
            <div className="provider-grid">
              {Object.keys(aiConfig?.providers || {}).map((provider) => (
                <button key={provider} className={aiForm.provider === provider ? 'on' : ''} onClick={() => chooseProvider(provider)}>
                  {aiConfig?.providers?.[provider].label}
                </button>
              ))}
            </div>
            <label className="field">
              <span>API Key</span>
              <input type="password" value={aiForm.api_key} placeholder={aiConfig?.api_key_masked || '必填'} onChange={(e) => setAiForm({ ...aiForm, api_key: e.target.value })} />
            </label>
            <label className="field">
              <span>Base URL</span>
              <input
                disabled={aiForm.provider !== 'custom'}
                value={aiForm.provider === 'custom' ? aiForm.api_base : aiConfig?.providers?.[aiForm.provider]?.api_base || aiForm.api_base}
                onChange={(e) => setAiForm({ ...aiForm, api_base: e.target.value })}
              />
            </label>
            <label className="field">
              <span>Model</span>
              <input value={aiForm.model} onChange={(e) => setAiForm({ ...aiForm, model: e.target.value })} />
            </label>
            <div className="modal-foot">
              <small>{aiReady?.ready ? '连通性正常' : aiReady?.error || '未检查'}</small>
              <button className="primary compact" onClick={saveAiConfig}>保存并检查</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<App />)

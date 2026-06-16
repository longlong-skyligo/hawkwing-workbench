import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, Bot, Boxes, FileText, Link, Play, Radar, ShieldCheck, Workflow } from 'lucide-react'
import './styles.css'

const API = import.meta.env.VITE_API_BASE || ''

type Workspace = { id: number; name: string; description: string; status: string }
type Finding = { id: number; target: string; title: string; severity: string; confidence: number; risk_score: number; status: string; source_tool: string }
type PentestJob = { id: number; finding_id: number; target: string; runner_image: string; runner_profile: string; status: string; result_summary: string }
type Stage = { key: string; label: string; status: string; count: number }
type Evidence = { id: number; file_type: string; path: string; sha256: string; pentest_job_id?: number }
type SessionRef = { id: number; session_type: string; target: string; tool: string; status: string; approval_ref: string; notes: string }
type ExecutionPlan = {
  id: number
  status: string
  risk_summary: string
  plan: {
    recommended_parallelism?: { total_containers: number; max_parallel: number; per_target_limit: number; high_risk_max: number }
    containers?: Array<{ name: string; runner_profile: string; image: string; risk_level: string; tools: string[]; targets: string[] }>
    dynamic_images?: Array<{ name: string; base_image: string; policy_allowed: boolean; policy_reasons: string[] }>
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
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [active, setActive] = useState<Workspace | null>(null)
  const [targets, setTargets] = useState('10.10.10.5\nhttp://target.example')
  const [scenario, setScenario] = useState('External range web validation. Add notes here for AD, forensics, firmware, cloud, pivot, or privesc scenarios.')
  const [findings, setFindings] = useState<Finding[]>([])
  const [jobs, setJobs] = useState<PentestJob[]>([])
  const [plans, setPlans] = useState<ExecutionPlan[]>([])
  const [stages, setStages] = useState<Stage[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [sessions, setSessions] = useState<SessionRef[]>([])
  const [selected, setSelected] = useState<number[]>([])
  const [sessionTarget, setSessionTarget] = useState('10.10.10.5')
  const [sessionTool, setSessionTool] = useState('approved-proxy')
  const [aiConfig, setAiConfig] = useState<Record<string, unknown>>({})
  const [catalogInfo, setCatalogInfo] = useState({ tools: 0, runners: 0, skills: 0 })
  const [message, setMessage] = useState('')

  const selectedCount = useMemo(() => selected.length, [selected])
  const latestPlan = plans[0]

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
    setAiConfig(await api<Record<string, unknown>>('/api/ai/config'))
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

  async function createWorkspace() {
    const ws = await api<Workspace>('/api/workspaces', {
      method: 'POST',
      body: JSON.stringify({ name: `range-${new Date().toISOString().slice(0, 19)}`, description: 'Temporary external range workspace' })
    })
    setActive(ws)
    setMessage(`Workspace #${ws.id} created`)
    await refresh()
  }

  async function importTargets() {
    if (!active) return
    const list = targets.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)
    await api(`/api/workspaces/${active.id}/targets/import`, {
      method: 'POST',
      body: JSON.stringify({ targets: list })
    })
    setMessage(`${list.length} targets imported`)
  }

  async function startScan() {
    if (!active) return
    await api(`/api/workspaces/${active.id}/scan/start`, {
      method: 'POST',
      body: JSON.stringify({ mode: 'standard' })
    })
    setMessage('Scan job queued')
    setTimeout(refresh, 1500)
  }

  async function assessPlan() {
    if (!active || selected.length === 0) return
    const result = await api<{ plan_id: number }>(`/api/workspaces/${active.id}/execution-plans/assess`, {
      method: 'POST',
      body: JSON.stringify({ finding_ids: selected, scenario_text: scenario, allow_dynamic: true })
    })
    setMessage(`Execution plan #${result.plan_id} created`)
    setTimeout(refresh, 800)
  }

  async function approvePlan(planId: number) {
    await api(`/api/execution-plans/${planId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved_by: 'operator' })
    })
    setMessage(`Execution plan #${planId} approved`)
    setTimeout(refresh, 800)
  }

  async function executePlan(planId: number) {
    await api(`/api/execution-plans/${planId}/execute`, { method: 'POST' })
    setMessage(`Execution plan #${planId} submitted`)
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
    setMessage('Session reference registered')
    setTimeout(refresh, 800)
  }

  async function generateReport() {
    if (!active) return
    const result = await api<{ report_path: string }>(`/api/workspaces/${active.id}/report/generate`, { method: 'POST' })
    setMessage(`Report generated: ${result.report_path}`)
  }

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <strong>HawkWing</strong>
            <span>External Range AI Workbench</span>
          </div>
        </div>
        <button className="primary" onClick={createWorkspace}><Play size={16} /> New workspace</button>
        <div className="side-title">Workspaces</div>
        {workspaces.map((ws) => (
          <button key={ws.id} className={`workspace ${active?.id === ws.id ? 'on' : ''}`} onClick={() => setActive(ws)}>
            #{ws.id} {ws.name}
          </button>
        ))}
      </aside>

      <main>
        <header>
          <div>
            <h1>{active ? active.name : 'External Range Workbench'}</h1>
            <p>Scan, review, assess container plans, approve execution, collect evidence, and generate reports.</p>
          </div>
          <div className="header-pills">
            <div className="ai-pill"><Bot size={16} /> AI {aiConfig.api_key_configured ? 'configured' : 'not configured'}</div>
            <div className="ai-pill"><Boxes size={16} /> {catalogInfo.tools} tools / {catalogInfo.runners} runners / {catalogInfo.skills} skills</div>
          </div>
        </header>

        {message && <div className="notice">{message}</div>}

        <section className="panel wide">
          <h2><Workflow size={18} /> Stage Visualization</h2>
          <div className="stage-row">
            {stages.map((stage) => (
              <div className={`stage ${stage.status}`} key={stage.key}>
                <strong>{stage.label}</strong>
                <span>{stage.status}</span>
                <small>{stage.count}</small>
              </div>
            ))}
          </div>
        </section>

        <section className="grid">
          <div className="panel">
            <h2><Radar size={18} /> Targets</h2>
            <textarea value={targets} onChange={(e) => setTargets(e.target.value)} />
            <div className="actions">
              <button onClick={importTargets} disabled={!active}>Import targets</button>
              <button onClick={startScan} disabled={!active}><Activity size={16} /> Start standard scan</button>
            </div>
          </div>

          <div className="panel">
            <h2><Activity size={18} /> Findings</h2>
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
              {findings.length === 0 && <p className="empty">No findings yet. Import targets and start a scan.</p>}
            </div>
          </div>
        </section>

        <section className="panel wide">
          <h2><Workflow size={18} /> Execution Plan Assessment</h2>
          <textarea value={scenario} onChange={(e) => setScenario(e.target.value)} />
          <div className="actions">
            <button onClick={assessPlan} disabled={!active || selectedCount === 0}>Assess plan for selected findings ({selectedCount})</button>
            {latestPlan && latestPlan.status === 'draft' && <button onClick={() => approvePlan(latestPlan.id)}>Approve latest plan #{latestPlan.id}</button>}
            {latestPlan && latestPlan.status === 'approved' && <button onClick={() => executePlan(latestPlan.id)}>Execute latest plan #{latestPlan.id}</button>}
          </div>
          {latestPlan && (
            <div className="plan">
              <strong>Latest plan #{latestPlan.id}: {latestPlan.status}</strong>
              <small>{latestPlan.risk_summary}</small>
              <div className="plan-grid">
                {(latestPlan.plan.containers || []).map((item) => (
                  <div className="plan-item" key={item.name}>
                    <strong>{item.runner_profile}</strong>
                    <span>{item.risk_level}</span>
                    <small>{item.image}</small>
                    <small>{item.tools.slice(0, 6).join(', ')}</small>
                  </div>
                ))}
                {(latestPlan.plan.dynamic_images || []).map((item) => (
                  <div className="plan-item dynamic" key={item.name}>
                    <strong>{item.name}</strong>
                    <span>{item.policy_allowed ? 'policy ok' : 'policy blocked'}</span>
                    <small>{item.base_image}</small>
                    <small>{(item.policy_reasons || []).join('; ') || 'requires approval'}</small>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        <section className="panel wide">
          <h2><Boxes size={18} /> Runner Jobs</h2>
          <div className="job-list">
            {jobs.map((job) => (
              <div className="job" key={job.id}>
                <strong>#{job.id} Finding-{job.finding_id}</strong>
                <span>{job.status}</span>
                <small>{job.runner_profile || job.runner_image}</small>
                <small>{job.result_summary}</small>
              </div>
            ))}
            {jobs.length === 0 && <p className="empty">No runner jobs yet.</p>}
          </div>
        </section>

        <section className="grid">
          <div className="panel">
            <h2><Link size={18} /> Approved Session Registry</h2>
            <div className="session-form">
              <input value={sessionTarget} onChange={(e) => setSessionTarget(e.target.value)} placeholder="target or route" />
              <input value={sessionTool} onChange={(e) => setSessionTool(e.target.value)} placeholder="approved tool" />
              <button onClick={registerSession} disabled={!active}>Register session reference</button>
            </div>
            <div className="mini-list">
              {sessions.map((item) => (
                <div className="mini-item" key={item.id}>
                  <strong>{item.session_type}: {item.target}</strong>
                  <small>{item.tool} / {item.status} / {item.approval_ref || 'no approval ref'}</small>
                </div>
              ))}
              {sessions.length === 0 && <p className="empty">No approved session references yet.</p>}
            </div>
          </div>

          <div className="panel">
            <h2><FileText size={18} /> Evidence Index</h2>
            <div className="mini-list">
              {evidence.slice(0, 12).map((item) => (
                <div className="mini-item" key={item.id}>
                  <strong>{item.file_type} #{item.id}</strong>
                  <small>{item.path}</small>
                  <small>{item.sha256.slice(0, 16)}...</small>
                </div>
              ))}
              {evidence.length === 0 && <p className="empty">Evidence will appear after runner jobs complete.</p>}
            </div>
          </div>
        </section>

        <section className="panel wide">
          <h2><FileText size={18} /> Report</h2>
          <p>Generate a Markdown report from findings, execution plans, runner jobs, and evidence references.</p>
          <button onClick={generateReport} disabled={!active}>Generate Markdown report</button>
        </section>
      </main>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<App />)

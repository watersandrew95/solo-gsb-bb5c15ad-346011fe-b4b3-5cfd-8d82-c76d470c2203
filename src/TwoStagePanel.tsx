import { useMemo, useState } from 'react'
import { parseRulesJson } from './audit/engine'
import { analyzeTwoStage } from './audit/twostage'
import type {
  TwoStageCategory,
  TwoStageCategoryView,
  TwoStageExamplePacket,
  TwoStageInput,
  TwoStageResult,
  TwoStageSubGroup,
  TwoStageTraceStep,
} from './audit/twostage'
import type { ExactRegionGroup, RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="copy-mini"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          setCopied(false)
        }
      }}
    >
      {copied ? '已复制' : '复制'}
    </button>
  )
}

function RegionView({ regions }: { regions: ExactRegionGroup[] }) {
  if (regions.length === 0) {
    return <div className="muted-text">（无单元）</div>
  }
  return (
    <div className="code-list">
      {regions.map((reg) => (
        <div key={reg.protocol} className="line">
          <strong>{reg.protocol}</strong>
          <span className="muted-text">（{formatSize(reg.size)} 条报文空间）</span>
          {reg.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} ×{' '}
              {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function stepText(step: TwoStageTraceStep): string {
  if (step.matchedRuleIndex === null) {
    return `阶段${step.stage}：未命中任何规则 → 阻断`
  }
  const verdict = step.passed ? '放行' : '阻断'
  return `阶段${step.stage}：命中 #${step.matchedRuleIndex + 1} ${step.matchedRuleName}（动作 ${step.action}）→ ${verdict}`
}

function TraceLines({ packet }: { packet: TwoStageExamplePacket }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 4 }}>
      {packet.trace.map((step, i) => (
        <div key={i} className="muted-text" style={{ fontSize: 12, paddingLeft: 24 }}>
          ↳ {stepText(step)}
        </div>
      ))}
    </div>
  )
}

function PacketWithTrace({
  packet,
  tagClass,
  tagText,
}: {
  packet: TwoStageExamplePacket
  tagClass: 'reachable' | 'shadowed'
  tagText: string
}) {
  return (
    <div>
      <div className="packet-box">
        <span className={`tag ${tagClass}`}>{tagText}</span>
        <span>{formatPacket(packet)}</span>
        <span className="arrow-note">{packet.reason}</span>
        <CopyButton text={formatPacket(packet)} />
      </div>
      <TraceLines packet={packet} />
    </div>
  )
}

const CATEGORY_META: Record<
  TwoStageCategory,
  { title: string; statClass: string; tagText: string }
> = {
  passed: { title: '最终通过', statClass: 'ok', tagText: '通过报文' },
  'blocked-stage1': {
    title: '第一阶段阻断',
    statClass: 'danger',
    tagText: '阻断报文',
  },
  'blocked-stage2': {
    title: '第二阶段阻断',
    statClass: 'warn',
    tagText: '阻断报文',
  },
}

function SubGroupCard({ group }: { group: TwoStageSubGroup }) {
  const headline =
    group.kind === 'unmatched'
      ? `阶段${group.stage}未命中任何规则`
      : `阶段${group.stage}首命中动作「${group.action}」不在放行列表`
  return (
    <div className="traffic-card traffic-action-changed">
      <div className="traffic-flow">
        <span className="action-pill">
          {group.kind === 'unmatched' ? '未命中' : group.action}
        </span>
        <span className="traffic-alert">{headline}</span>
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(group.size)} 条报文空间（{formatPercent(group.ratio)}，
          {formatSize(group.cells)} 个原子单元）
        </span>
      </div>
      <div className="goal-block-title">代表报文（可复制复现）</div>
      {group.examples.map((p, i) => (
        <PacketWithTrace key={i} packet={p} tagClass="shadowed" tagText="代表报文" />
      ))}
      <div className="goal-block-title">精确区域（CIDR × 端口）</div>
      <RegionView regions={group.regions} />
    </div>
  )
}

function CategorySection({ view }: { view: TwoStageCategoryView }) {
  const meta = CATEGORY_META[view.category]
  return (
    <div>
      <h3 className="reorder-section-title">
        {meta.title}
        <span className="muted-text" style={{ fontWeight: 400, marginLeft: 8 }}>
          {formatSize(view.size)} 条报文空间（{formatPercent(view.ratio)}，
          {formatSize(view.cells)} 个原子单元）
        </span>
      </h3>

      {view.examples.length > 0 && (
        <>
          <div className="goal-block-title">代表报文（可复制复现，含分阶段命中轨迹）</div>
          {view.examples.map((p, i) => (
            <PacketWithTrace
              key={i}
              packet={p}
              tagClass={view.category === 'passed' ? 'reachable' : 'shadowed'}
              tagText={meta.tagText}
            />
          ))}
        </>
      )}

      {view.groups.length > 0 && (
        <>
          <div className="goal-block-title">
            阻断原因分组（共 {view.groups.length} 类，互斥且完备）
          </div>
          {view.groups.map((g, i) => (
            <SubGroupCard key={i} group={g} />
          ))}
        </>
      )}

      <div className="goal-block-title">该类完整精确区域（CIDR × 端口）</div>
      <RegionView regions={view.regions} />
    </div>
  )
}

function excludedNote(result: TwoStageResult): string {
  const parts: string[] = []
  for (const [label, meta] of [
    ['阶段一', result.stage1],
    ['阶段二', result.stage2],
  ] as const) {
    const bits: string[] = []
    if (meta.invalidExcluded > 0) bits.push(`${meta.invalidExcluded} 条非法规则`)
    if (meta.disabledExcluded > 0) bits.push(`${meta.disabledExcluded} 条停用规则`)
    if (bits.length > 0) parts.push(`${label}已排除 ${bits.join('、')}`)
  }
  return parts.length > 0 ? ` ${parts.join('；')}，均不参与分析。` : ''
}

function RuleHitsTable({ result }: { result: TwoStageResult }) {
  return (
    <div style={{ overflowX: 'auto', marginBottom: 12 }}>
      <table className="rule-table goal-proto-table">
        <thead>
          <tr>
            <th>阶段</th>
            <th>首命中规则</th>
            <th>动作</th>
            <th>命中单元数</th>
            <th>报文空间</th>
            <th>该阶段判定</th>
          </tr>
        </thead>
        <tbody>
          {result.ruleHits.map((h, i) => (
            <tr key={i}>
              <td>阶段{h.stage}</td>
              <td>
                #{h.ruleIndex + 1} {h.ruleName}
              </td>
              <td>{h.action}</td>
              <td className="goal-num">{formatSize(h.cells)}</td>
              <td className="goal-num">{formatSize(h.size)}</td>
              <td>{h.allowed ? '放行（进入下一阶段 / 最终通过）' : '阻断'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TwoStageResultView({ result }: { result: TwoStageResult }) {
  const g = result.goal
  return (
    <div className="goal-result">
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        目标 <span className="mono">{g.cidrText}</span> · 端口{' '}
        {formatPortRange(g.portStart, g.portEnd)} · 协议 {g.protocol} · 目标总空间{' '}
        {formatSize(result.totalSize)}。阶段一基于 {result.stage1.validRuleCount} 条
        合法且启用的当前规则（放行动作：{result.stage1.actions.join(' / ') || '—'}）；
        阶段二基于 {result.stage2.validRuleCount} 条合法且启用的粘贴规则（放行动作：
        {result.stage2.actions.join(' / ') || '—'}）。{excludedNote(result)}
        两阶段逐单元原样重放、报文不改写；结果随当前规则编辑自动重算。
      </div>

      <div className="stats">
        <div className={`stat-card ${CATEGORY_META['passed'].statClass}`}>
          <div className="label">最终通过</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.passed.size)}
          </div>
          <div className="label">{formatPercent(result.passed.ratio)}</div>
        </div>
        <div className={`stat-card ${CATEGORY_META['blocked-stage1'].statClass}`}>
          <div className="label">第一阶段阻断</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.blockedStage1.size)}
          </div>
          <div className="label">{formatPercent(result.blockedStage1.ratio)}</div>
        </div>
        <div className={`stat-card ${CATEGORY_META['blocked-stage2'].statClass}`}>
          <div className="label">第二阶段阻断</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.blockedStage2.size)}
          </div>
          <div className="label">{formatPercent(result.blockedStage2.ratio)}</div>
        </div>
      </div>

      {g.protocol === 'ANY' && (
        <div style={{ overflowX: 'auto', marginBottom: 12 }}>
          <table className="rule-table goal-proto-table">
            <thead>
              <tr>
                <th>协议（ANY 分别检查）</th>
                <th>最终通过</th>
                <th>第一阶段阻断</th>
                <th>第二阶段阻断</th>
              </tr>
            </thead>
            <tbody>
              {result.perProtocol.map((p) => (
                <tr key={p.protocol}>
                  <td>{p.protocol}</td>
                  <td className="goal-num">{formatSize(p.passedSize)}</td>
                  <td className="goal-num">{formatSize(p.blockedStage1Size)}</td>
                  <td className="goal-num">{formatSize(p.blockedStage2Size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {result.ruleHits.length > 0 && (
        <>
          <div className="goal-block-title">
            分阶段命中轨迹汇总（仅统计在该阶段真正参与判定的目标单元）
          </div>
          <RuleHitsTable result={result} />
        </>
      )}

      <CategorySection view={result.passed} />
      <CategorySection view={result.blockedStage1} />
      <CategorySection view={result.blockedStage2} />
    </div>
  )
}

export function TwoStagePanel({ rules }: Props) {
  const [form, setForm] = useState<TwoStageInput>({
    cidr: '10.0.0.0/8',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
    stage1Actions: 'allow',
    stage2RulesJson: '',
    stage2Actions: 'allow',
  })
  const [submitted, setSubmitted] = useState<TwoStageInput | null>(null)

  // 只读分析：纯函数计算，不改动任何规则；rules 变化时自动按最新当前规则重算
  const outcome = useMemo(
    () => (submitted ? analyzeTwoStage(rules, submitted) : null),
    [rules, submitted],
  )

  const patch = (p: Partial<TwoStageInput>) => setForm((f) => ({ ...f, ...p }))

  const stage1Suggestions = useMemo(
    () => [...new Set(rules.map((r) => r.action.trim()).filter(Boolean))],
    [rules],
  )
  const stage2Suggestions = useMemo(() => {
    if (!form.stage2RulesJson.trim()) return []
    const { rules: parsed, errors } = parseRulesJson(form.stage2RulesJson)
    if (errors.length > 0) return []
    return [...new Set(parsed.map((r) => r.action.trim()).filter(Boolean))]
  }, [form.stage2RulesJson])

  const dirty =
    submitted !== null &&
    (form.cidr !== submitted.cidr ||
      String(form.portStart) !== String(submitted.portStart) ||
      String(form.portEnd) !== String(submitted.portEnd) ||
      form.protocol !== submitted.protocol ||
      form.stage1Actions !== submitted.stage1Actions ||
      form.stage2Actions !== submitted.stage2Actions ||
      form.stage2RulesJson !== submitted.stage2RulesJson)

  return (
    <div className="panel goal-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>双级串联策略（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          以当前规则为第一阶段、粘贴同格式 JSON 规则为第二阶段；逐单元原样重放，
          报文不改写。每阶段首命中动作在其放行列表内才继续，未命中也阻断；
          第一阶段阻断者不进入第二阶段。
        </span>
      </div>

      <div className="goal-form two-stage-form">
        <label>
          <span>目标 IPv4 CIDR</span>
          <input
            value={form.cidr}
            onChange={(e) => patch({ cidr: e.target.value })}
            placeholder="10.0.0.0/8"
            spellCheck={false}
          />
        </label>
        <label>
          <span>目标端口区间</span>
          <div className="port-cell">
            <input
              value={form.portStart}
              onChange={(e) => patch({ portStart: e.target.value })}
              placeholder="0"
            />
            <span className="muted-text">–</span>
            <input
              value={form.portEnd}
              onChange={(e) => patch({ portEnd: e.target.value })}
              placeholder="65535"
            />
          </div>
        </label>
        <label>
          <span>协议</span>
          <select
            value={form.protocol}
            onChange={(e) => patch({ protocol: e.target.value })}
          >
            {['ANY', 'TCP', 'UDP'].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>第一阶段放行动作（当前规则）</span>
          <input
            list="twostage-stage1-actions"
            value={form.stage1Actions}
            onChange={(e) => patch({ stage1Actions: e.target.value })}
            placeholder="allow（逗号或空白分隔多个动作）"
          />
        </label>
        <label>
          <span>第二阶段放行动作（粘贴规则）</span>
          <input
            list="twostage-stage2-actions"
            value={form.stage2Actions}
            onChange={(e) => patch({ stage2Actions: e.target.value })}
            placeholder="allow（逗号或空白分隔多个动作）"
          />
        </label>
        <button className="primary" onClick={() => setSubmitted({ ...form })}>
          执行串联分析
        </button>
      </div>
      <datalist id="twostage-stage1-actions">
        {stage1Suggestions.map((a) => (
          <option key={a} value={a} />
        ))}
      </datalist>
      <datalist id="twostage-stage2-actions">
        {stage2Suggestions.map((a) => (
          <option key={a} value={a} />
        ))}
      </datalist>

      <label className="two-stage-json-label">
        <span>
          第二阶段规则 JSON（与「粘贴 JSON 导入」同格式：数组，或 {'{ rules: [...] }'}；
          只读，不写回当前规则）
        </span>
        <textarea
          className="two-stage-json"
          value={form.stage2RulesJson}
          onChange={(e) => patch({ stage2RulesJson: e.target.value })}
          placeholder={'[\n  {\n    "name": "stage2-allow-ssh",\n    "cidr": "10.0.0.0/8",\n    "portStart": 22,\n    "portEnd": 22,\n    "protocol": "TCP",\n    "action": "allow"\n  }\n]'}
          spellCheck={false}
        />
      </label>

      {outcome && !outcome.ok && (
        <div className="notice error">
          {outcome.errors.map((e, i) => (
            <div key={i}>• {e}</div>
          ))}
        </div>
      )}

      {dirty && outcome?.ok && (
        <div className="notice info">
          输入已修改，以下结果仍对应上次分析；点击「执行串联分析」按新输入重算。
        </div>
      )}

      {!submitted && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          填写目标、两阶段放行动作并粘贴第二阶段规则 JSON，然后点击「执行串联分析」。
          动作按文本精确匹配、区分大小写，多个动作用逗号或空白分隔。
          非法规则与停用规则按现有语义从对应阶段排除；JSON 结构错误或目标输入错误会阻止分析。
        </div>
      )}

      {outcome?.ok && <TwoStageResultView result={outcome.result} />}
    </div>
  )
}

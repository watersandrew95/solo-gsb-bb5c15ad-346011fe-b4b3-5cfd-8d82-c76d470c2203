/**
 * 双级串联策略分析（只读）。
 *
 * 两个首命中规则阶段串联，报文不改写、逐单元原样重放：
 *
 *   阶段一：当前规则（主页面可编辑的那一份）
 *   阶段二：粘贴的同格式 JSON 规则（只读，不写回主规则）
 *
 * 每个阶段各自配置一份「放行动作列表」。对目标空间
 * （IPv4 CIDR × 端口区间 × 协议）中的每个原子单元：
 *
 *   1. 在阶段一首条命中：未命中任何规则 → 阻断（第一阶段阻断）；
 *      命中但动作不在阶段一放行动作列表内 → 阻断（第一阶段阻断）；
 *      命中且动作放行 → 原样进入阶段二。
 *   2. 阶段二对进入者再次按首条命中判定：未命中 → 阻断（第二阶段阻断）；
 *      命中但动作不在阶段二放行动作列表内 → 阻断（第二阶段阻断）；
 *      命中且动作放行 → 最终通过。
 *
 * 第一阶段阻断者不进入第二阶段。整个目标被精确且完备地分为三类：
 * 最终通过 / 第一阶段阻断 / 第二阶段阻断。
 *
 * 目标边界与双方规则边界合并进同一套原子切分，两阶段在相同的
 * (ipAtom × portAtom × proto) 单元划分上各构建一张首命中 owner 表，
 * 从而逐单元对齐重放；区域输出复用审计引擎的精确矩形展开。
 *
 * 非法规则与停用规则按既有语义排除（validateRules + activeRules）；
 * 第二阶段 JSON 的结构错误（无法解析、根节点错误、条目非对象等）与
 * 目标输入错误一样阻止分析；阶段二规则内部的非法 CIDR / 端口等
 * 语义错误不阻止分析，而是按现有语义从该阶段排除。
 */
import {
  activeRules,
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  concreteProtocolOf,
  containedIndices,
  exampleIp,
  parseRulesJson,
  protocolDimIndices,
  validatePortRange,
  validateRules,
} from './engine'
import { intToIpv4, parseCidrStrict } from './iputil'
import type { ExactRegionGroup, NormalizedRule, Protocol, RuleInput } from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

/** 面板输入（原始形态：端口与动作列表允许字符串，阶段二为 JSON 文本） */
export interface TwoStageInput {
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  /** 第一阶段放行动作列表（逗号 / 空白分隔的文本） */
  stage1Actions: string
  /** 第二阶段规则：与主规则同格式的 JSON 文本 */
  stage2RulesJson: string
  /** 第二阶段放行动作列表（逗号 / 空白分隔的文本） */
  stage2Actions: string
}

export type TwoStageCategory = 'passed' | 'blocked-stage1' | 'blocked-stage2'

/** 单个阶段的一步命中轨迹 */
export interface TwoStageTraceStep {
  stage: 1 | 2
  /** null = 该阶段未命中任何规则 */
  matchedRuleIndex: number | null
  matchedRuleName: string | null
  action: string | null
  /** 首命中动作是否在该阶段放行动作列表内（未命中恒为 false） */
  passed: boolean
}

/** 可复制的代表报文 + 分阶段命中轨迹 */
export interface TwoStageExamplePacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
  category: TwoStageCategory
  /** 阻断 / 通过原因（展示用单行说明） */
  reason: string
  /** 分阶段命中轨迹：第一阶段阻断者只有一步；其余两步 */
  trace: TwoStageTraceStep[]
}

/** 阻断原因分组：未命中 或 命中动作不在放行列表（按动作聚合） */
export interface TwoStageSubGroup {
  kind: 'unmatched' | 'action'
  stage: 1 | 2
  /** kind=action 时的实际首命中动作 */
  action: string | null
  size: number
  ratio: number
  cells: number
  regions: ExactRegionGroup[]
  /** 每个具体协议一个确定性代表报文 */
  examples: TwoStageExamplePacket[]
}

/** 三大分类之一的完整视图：报文空间、精确区域、代表报文、阻断子分组 */
export interface TwoStageCategoryView {
  category: TwoStageCategory
  size: number
  ratio: number
  cells: number
  /** 该类的完整精确区域（行式矩形，互斥且完备） */
  regions: ExactRegionGroup[]
  /** 每个具体协议一个确定性代表报文（含完整命中轨迹） */
  examples: TwoStageExamplePacket[]
  /** 阻断类的原因子分组；最终通过类恒为空数组 */
  groups: TwoStageSubGroup[]
}

/** 阶段内规则在目标空间上的首命中汇总（分阶段命中轨迹的聚合视角） */
export interface TwoStageRuleHit {
  stage: 1 | 2
  ruleIndex: number
  ruleName: string
  action: string
  /** 该规则在该阶段首命中的目标单元数与报文空间 */
  cells: number
  size: number
  /** 该动作是否属于此阶段放行动作列表（true=放行去向，false=该阶段阻断） */
  allowed: boolean
}

export interface TwoStageStageMeta {
  /** 参与分析的合法且启用规则数 */
  validRuleCount: number
  /** 被排除的非法规则数 */
  invalidExcluded: number
  /** 被排除的停用规则数 */
  disabledExcluded: number
  /** 规范化后的放行动作列表 */
  actions: string[]
}

export interface TwoStagePerProtocol {
  protocol: ConcreteProtocol
  passedSize: number
  blockedStage1Size: number
  blockedStage2Size: number
}

export interface TwoStageResult {
  goal: {
    cidrText: string
    portStart: number
    portEnd: number
    protocol: Protocol
  }
  totalSize: number
  passed: TwoStageCategoryView
  blockedStage1: TwoStageCategoryView
  blockedStage2: TwoStageCategoryView
  /** ANY 目标时按 TCP / UDP 分别统计 */
  perProtocol: TwoStagePerProtocol[]
  /** 两阶段规则在目标空间上的首命中汇总，按阶段 → 空间降序 → 规则序号 */
  ruleHits: TwoStageRuleHit[]
  stage1: TwoStageStageMeta
  stage2: TwoStageStageMeta
}

export type TwoStageOutcome =
  | { ok: true; result: TwoStageResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 输入解析
// ---------------------------------------------------------------------------

/** 放行动作列表文本 → 去重后的动作数组（逗号 / 中文逗号 / 空白分隔，区分大小写） */
export function parseActionList(text: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const token of text.split(/[,，\s]+/)) {
    const action = token.trim()
    if (action && !seen.has(action)) {
      seen.add(action)
      out.push(action)
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// 主分析流程
// ---------------------------------------------------------------------------

export function analyzeTwoStage(
  stage1Rules: RuleInput[],
  input: TwoStageInput,
): TwoStageOutcome {
  const errors: string[] = []

  // --- 目标校验（与规则 / 目标验证同一套严格标准） ---
  let cidr: ReturnType<typeof parseCidrStrict> | null = null
  if (!input.cidr.trim()) {
    errors.push('目标 CIDR 不能为空')
  } else {
    try {
      cidr = parseCidrStrict(input.cidr)
    } catch (err) {
      errors.push((err as Error).message)
    }
  }

  const ports = validatePortRange(
    String(input.portStart).trim(),
    String(input.portEnd).trim(),
  )
  errors.push(...ports.errors)

  let protocol: Protocol | null = null
  const protoUpper = input.protocol.trim().toUpperCase()
  if (!protoUpper) {
    errors.push('协议不能为空')
  } else if (protoUpper !== 'TCP' && protoUpper !== 'UDP' && protoUpper !== 'ANY') {
    errors.push(`协议必须为 TCP / UDP / ANY，收到 “${input.protocol}”`)
  } else {
    protocol = protoUpper as Protocol
  }

  // --- 两阶段放行动作列表 ---
  const stage1Actions = parseActionList(input.stage1Actions)
  const stage2Actions = parseActionList(input.stage2Actions)
  if (stage1Actions.length === 0) errors.push('第一阶段放行动作列表不能为空')
  if (stage2Actions.length === 0) errors.push('第二阶段放行动作列表不能为空')

  // --- 第二阶段 JSON：结构错误阻止分析（与目标输入错误同等对待） ---
  const parsed2 = parseRulesJson(input.stage2RulesJson)
  if (parsed2.errors.length > 0) {
    for (const e of parsed2.errors) errors.push(`第二阶段规则 JSON：${e}`)
  }

  if (errors.length > 0 || !cidr || protocol === null) {
    return { ok: false, errors }
  }

  // --- 非法规则与停用规则按既有语义排除 ---
  const checked1 = validateRules(stage1Rules)
  const active1 = activeRules(stage1Rules)
  const disabled1 = checked1.valid.length - active1.length

  const checked2 = validateRules(parsed2.rules)
  const active2 = checked2.valid.filter((r) => r.enabled)
  const disabled2 = checked2.valid.length - active2.length

  const pass1 = new Set(stage1Actions)
  const pass2 = new Set(stage2Actions)

  // --- 目标 + 双方规则边界合并进同一套原子切分 ---
  const targetIp = { start: cidr.start, end: cidr.end }
  const targetPort = { start: ports.portStart, end: ports.portEnd }
  const ipAtoms = buildIpAtoms([...active1, ...active2], [targetIp])
  const portAtoms = buildPortAtoms([...active1, ...active2], [targetPort])
  // 两阶段在相同单元划分上各跑一次首命中登记，逐单元对齐重放
  const owner1 = buildOwnerMap(active1, ipAtoms, portAtoms)
  const owner2 = buildOwnerMap(active2, ipAtoms, portAtoms)

  const ipIdx = containedIndices(ipAtoms, cidr.start, cidr.end)
  const portIdx = containedIndices(portAtoms, ports.portStart, ports.portEnd)
  const protoIdx = protocolDimIndices(protocol)

  // 分类单元集合
  const catKeys: Record<TwoStageCategory, Set<string>> = {
    passed: new Set(),
    'blocked-stage1': new Set(),
    'blocked-stage2': new Set(),
  }
  // 阻断原因子分组：groupKey -> 单元
  const subSets = new Map<string, Set<string>>()
  // 每（分类, 协议）与（子分组, 协议）的扫描序首个单元 → 确定性代表报文
  const catFirst = new Map<string, string>()
  const subFirst = new Map<string, string>()

  const catSize: Record<TwoStageCategory, number> = {
    passed: 0,
    'blocked-stage1': 0,
    'blocked-stage2': 0,
  }
  const perProto = [
    { passed: 0, b1: 0, b2: 0 },
    { passed: 0, b1: 0, b2: 0 },
  ]

  // 阶段内规则首命中聚合（仅统计该阶段真正进入判定的目标单元）
  const hit1 = new Map<number, { cells: number; size: number }>()
  const hit2 = new Map<number, { cells: number; size: number }>()
  const noteHit = (
    map: Map<number, { cells: number; size: number }>,
    pos: number,
    size: number,
  ) => {
    const cur = map.get(pos)
    if (cur) {
      cur.cells += 1
      cur.size += size
    } else {
      map.set(pos, { cells: 1, size })
    }
  }

  for (const ip of ipIdx) {
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (const proto of protoIdx) {
        const key = `${ip}.${port}.${proto}`

        const pos1 = owner1.get(key)
        let category: TwoStageCategory
        let groupKey: string

        if (pos1 === undefined) {
          category = 'blocked-stage1'
          groupKey = 's1:unmatched'
        } else {
          noteHit(hit1, pos1, size)
          const rule1 = active1[pos1]
          if (!pass1.has(rule1.action)) {
            category = 'blocked-stage1'
            groupKey = `s1:action:${rule1.action}`
          } else {
            // 第一阶段放行：报文不改写，原样进入第二阶段
            const pos2 = owner2.get(key)
            if (pos2 === undefined) {
              category = 'blocked-stage2'
              groupKey = 's2:unmatched'
            } else {
              noteHit(hit2, pos2, size)
              const rule2 = active2[pos2]
              if (!pass2.has(rule2.action)) {
                category = 'blocked-stage2'
                groupKey = `s2:action:${rule2.action}`
              } else {
                category = 'passed'
                groupKey = 'passed'
              }
            }
          }
        }

        catKeys[category].add(key)
        catSize[category] += size
        if (category === 'passed') perProto[proto].passed += size
        else if (category === 'blocked-stage1') perProto[proto].b1 += size
        else perProto[proto].b2 += size

        let set = subSets.get(groupKey)
        if (!set) {
          set = new Set()
          subSets.set(groupKey, set)
        }
        set.add(key)

        if (!catFirst.has(`${category}|${proto}`)) {
          catFirst.set(`${category}|${proto}`, key)
        }
        if (!subFirst.has(`${groupKey}|${proto}`)) {
          subFirst.set(`${groupKey}|${proto}`, key)
        }
      }
    }
  }

  const totalSize = catSize.passed + catSize['blocked-stage1'] + catSize['blocked-stage2']
  const ratioOf = (n: number) => (totalSize === 0 ? 0 : n / totalSize)

  // --- 代表报文与分阶段命中轨迹 ---
  const traceOf = (key: string): TwoStageTraceStep[] => {
    const pos1 = owner1.get(key)
    const rule1: NormalizedRule | undefined =
      pos1 === undefined ? undefined : active1[pos1]
    const entered = rule1 !== undefined && pass1.has(rule1.action)
    const steps: TwoStageTraceStep[] = [
      {
        stage: 1,
        matchedRuleIndex: rule1 ? rule1.index : null,
        matchedRuleName: rule1 ? rule1.name : null,
        action: rule1 ? rule1.action : null,
        passed: entered,
      },
    ]
    if (entered) {
      const pos2 = owner2.get(key)
      const rule2: NormalizedRule | undefined =
        pos2 === undefined ? undefined : active2[pos2]
      steps.push({
        stage: 2,
        matchedRuleIndex: rule2 ? rule2.index : null,
        matchedRuleName: rule2 ? rule2.name : null,
        action: rule2 ? rule2.action : null,
        passed: rule2 !== undefined && pass2.has(rule2.action),
      })
    }
    return steps
  }

  const reasonOf = (groupKey: string): string => {
    if (groupKey === 'passed') return '两阶段首命中动作均在放行列表内'
    if (groupKey === 's1:unmatched') return '第一阶段未命中任何规则'
    if (groupKey === 's2:unmatched') return '第二阶段未命中任何规则'
    const [stage, , action] = groupKey.split(':')
    return stage === 's1'
      ? `第一阶段首命中动作「${action}」不在放行列表`
      : `第二阶段首命中动作「${action}」不在放行列表`
  }

  const packetOf = (
    key: string,
    category: TwoStageCategory,
    groupKey: string,
  ): TwoStageExamplePacket => {
    const [ip, port, proto] = key.split('.').map(Number)
    return {
      srcIp: intToIpv4(exampleIp(ipAtoms[ip])),
      srcPort: portAtoms[port].start,
      protocol: concreteProtocolOf(proto),
      category,
      reason: reasonOf(groupKey),
      trace: traceOf(key),
    }
  }

  const protoList = protoIdx
  const catExamples = (category: TwoStageCategory): TwoStageExamplePacket[] =>
    protoList
      .map((proto) => catFirst.get(`${category}|${proto}`))
      .filter((k): k is string => k !== undefined)
      .map((k) => {
        const gk =
          category === 'passed'
            ? 'passed'
            : [...subSets.entries()].find(([, set]) => set.has(k))![0]
        return packetOf(k, category, gk)
      })

  const buildGroup = (groupKey: string): TwoStageSubGroup => {
    const keys = subSets.get(groupKey)!
    let size = 0
    for (const key of keys) {
      const [ip, port] = key.split('.').map(Number)
      size += atomCellSize(ipAtoms[ip], portAtoms[port])
    }
    let stage: 1 | 2
    let kind: 'unmatched' | 'action'
    let action: string | null
    if (groupKey === 's1:unmatched') {
      stage = 1
      kind = 'unmatched'
      action = null
    } else if (groupKey === 's2:unmatched') {
      stage = 2
      kind = 'unmatched'
      action = null
    } else {
      const [s, , a] = groupKey.split(':')
      stage = s === 's1' ? 1 : 2
      kind = 'action'
      action = a
    }
    const category: TwoStageCategory =
      stage === 1 ? 'blocked-stage1' : 'blocked-stage2'
    const examples = protoList
      .map((proto) => subFirst.get(`${groupKey}|${proto}`))
      .filter((k): k is string => k !== undefined)
      .map((k) => packetOf(k, category, groupKey))
    return {
      kind,
      stage,
      action,
      size,
      ratio: ratioOf(size),
      cells: keys.size,
      regions: buildExactRegions(keys, ipAtoms, portAtoms),
      examples,
    }
  }

  const buildCategory = (category: TwoStageCategory): TwoStageCategoryView => {
    const keys = catKeys[category]
    const groupKeys = [...subSets.keys()].filter((gk) => {
      if (category === 'passed') return gk === 'passed'
      if (category === 'blocked-stage1') return gk.startsWith('s1:')
      return gk.startsWith('s2:')
    })
    return {
      category,
      size: catSize[category],
      ratio: ratioOf(catSize[category]),
      cells: keys.size,
      regions: buildExactRegions(keys, ipAtoms, portAtoms),
      examples: catExamples(category),
      groups:
        category === 'passed'
          ? []
          : groupKeys
              .map(buildGroup)
              .sort(
                (a, b) =>
                  b.size - a.size ||
                  (a.action ?? '').localeCompare(b.action ?? ''),
              ),
    }
  }

  // --- 阶段内规则首命中汇总 ---
  const buildHits = (
    stage: 1 | 2,
    active: NormalizedRule[],
    map: Map<number, { cells: number; size: number }>,
    pass: Set<string>,
  ): TwoStageRuleHit[] =>
    [...map.entries()].map(([pos, v]) => ({
      stage,
      ruleIndex: active[pos].index,
      ruleName: active[pos].name,
      action: active[pos].action,
      cells: v.cells,
      size: v.size,
      allowed: pass.has(active[pos].action),
    }))

  const ruleHits = [
    ...buildHits(1, active1, hit1, pass1),
    ...buildHits(2, active2, hit2, pass2),
  ].sort((a, b) => a.stage - b.stage || b.size - a.size || a.ruleIndex - b.ruleIndex)

  return {
    ok: true,
    result: {
      goal: {
        cidrText: cidr.canonical,
        portStart: ports.portStart,
        portEnd: ports.portEnd,
        protocol,
      },
      totalSize,
      passed: buildCategory('passed'),
      blockedStage1: buildCategory('blocked-stage1'),
      blockedStage2: buildCategory('blocked-stage2'),
      perProtocol: protoList.map((proto) => ({
        protocol: concreteProtocolOf(proto),
        passedSize: perProto[proto].passed,
        blockedStage1Size: perProto[proto].b1,
        blockedStage2Size: perProto[proto].b2,
      })),
      ruleHits,
      stage1: {
        validRuleCount: active1.length,
        invalidExcluded: checked1.invalid.length,
        disabledExcluded: disabled1,
        actions: stage1Actions,
      },
      stage2: {
        validRuleCount: active2.length,
        invalidExcluded: checked2.invalid.length,
        disabledExcluded: disabled2,
        actions: stage2Actions,
      },
    },
  }
}

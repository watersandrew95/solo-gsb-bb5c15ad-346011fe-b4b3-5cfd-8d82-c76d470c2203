/**
 * 双级串联策略分析自检：node --test 风格的轻量断言脚本（零额外依赖）。
 */
import assert from 'node:assert'
import { analyzeTwoStage, parseActionList } from './audit/twostage'
import type { TwoStageInput } from './audit/twostage'
import type { RuleInput } from './audit/types'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput> = {}): RuleInput {
  return {
    id: `r${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

function input(p: Partial<TwoStageInput> = {}): TwoStageInput {
  return {
    cidr: '10.0.0.0/8',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
    stage1Actions: 'allow',
    stage2RulesJson: '',
    stage2Actions: 'allow',
    ...p,
  }
}

const stage2 = (rules: Array<Partial<RuleInput>>) =>
  JSON.stringify(rules.map((r) => rule({ ...r })))

// --- 动作列表解析 ---
test('动作列表：逗号 / 中文逗号 / 空白分隔并去重，区分大小写', () => {
  assert.deepEqual(parseActionList('allow, permit，accept allow'), [
    'allow',
    'permit',
    'accept',
  ])
  assert.deepEqual(parseActionList('  Allow  allow '), ['Allow', 'allow'])
  assert.deepEqual(parseActionList('  '), [])
})

// --- 输入错误阻止分析 ---
test('目标输入错误 / 动作列表为空 / JSON 结构错误 → 阻止分析', () => {
  assert.equal(
    analyzeTwoStage([rule()], input({ cidr: '10.0.0.1/24' })).ok,
    false,
  )
  assert.equal(
    analyzeTwoStage([rule()], input({ portStart: '100', portEnd: '1' })).ok,
    false,
  )
  assert.equal(
    analyzeTwoStage([rule()], input({ protocol: 'ICMP' })).ok,
    false,
  )
  assert.equal(
    analyzeTwoStage([rule()], input({ stage1Actions: '' })).ok,
    false,
  )
  assert.equal(
    analyzeTwoStage([rule()], input({ stage2Actions: '   ' })).ok,
    false,
  )
  assert.equal(
    analyzeTwoStage([rule()], input({ stage2RulesJson: '{not json' })).ok,
    false,
  )
  // 条目非对象属于结构错误，同样阻止
  assert.equal(
    analyzeTwoStage([rule()], input({ stage2RulesJson: '[42]' })).ok,
    false,
  )
})

// --- 基础三分：全通过 ---
test('两阶段 allow 全覆盖目标 → 全部最终通过', () => {
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0' })],
    input({ stage2RulesJson: stage2([{ name: 's2', cidr: '0.0.0.0/0' }]) }),
  )
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  const total = 2 ** 24 * 65536 * 2
  assert.equal(r.totalSize, total)
  assert.equal(r.passed.size, total)
  assert.equal(r.blockedStage1.size, 0)
  assert.equal(r.blockedStage2.size, 0)
  assert.equal(r.passed.cells > 0, true)
  // 三类合计精确等于目标空间
  assert.equal(
    r.passed.size + r.blockedStage1.size + r.blockedStage2.size,
    r.totalSize,
  )
  // 通过报文轨迹含两步，且两步均放行
  assert.equal(r.passed.examples.length, 2) // TCP、UDP 各一
  for (const p of r.passed.examples) {
    assert.equal(p.trace.length, 2)
    assert.equal(p.trace[0].passed, true)
    assert.equal(p.trace[1].passed, true)
    assert.equal(p.trace[0].matchedRuleName, 's1')
    assert.equal(p.trace[1].matchedRuleName, 's2')
  }
})

// --- 第一阶段未命中 ---
test('阶段一未覆盖目标 → 第一阶段阻断（未命中），不进入阶段二', () => {
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '192.168.0.0/16' })],
    input({
      cidr: '10.0.0.0/24',
      stage2RulesJson: stage2([{ name: 's2', cidr: '0.0.0.0/0' }]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  const total = 256 * 65536 * 2
  assert.equal(r.totalSize, total)
  assert.equal(r.blockedStage1.size, total)
  assert.equal(r.passed.size, 0)
  assert.equal(r.blockedStage2.size, 0)
  // 阶段一阻断者轨迹只有一步
  const p = r.blockedStage1.examples[0]
  assert.equal(p.trace.length, 1)
  assert.equal(p.trace[0].matchedRuleIndex, null)
  assert.equal(p.trace[0].passed, false)
  // 唯一阻断分组：阶段一未命中
  assert.equal(r.blockedStage1.groups.length, 1)
  assert.equal(r.blockedStage1.groups[0].kind, 'unmatched')
  assert.equal(r.blockedStage1.groups[0].stage, 1)
  // 阶段二不应有任何命中（没进入）
  assert.ok(r.ruleHits.every((h) => h.stage !== 2))
})

// --- 第一阶段动作不放行 ---
test('阶段一命中 deny 且 deny 不在放行列表 → 第一阶段阻断', () => {
  const out = analyzeTwoStage(
    [rule({ name: 'deny-all', cidr: '0.0.0.0/0', action: 'deny' })],
    input({
      stage2RulesJson: stage2([{ name: 's2', cidr: '0.0.0.0/0' }]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  assert.equal(r.blockedStage1.size, r.totalSize)
  const g = r.blockedStage1.groups
  assert.equal(g.length, 1)
  assert.equal(g[0].kind, 'action')
  assert.equal(g[0].action, 'deny')
  assert.equal(g[0].examples[0].trace[0].matchedRuleName, 'deny-all')
})

// --- 第一阶段放行、第二阶段未命中 ---
test('阶段一放行、阶段二未覆盖 → 第二阶段阻断（未命中）', () => {
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0' })],
    input({
      cidr: '10.1.0.0/16',
      stage2RulesJson: stage2([{ name: 's2', cidr: '192.168.0.0/16' }]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  assert.equal(r.blockedStage2.size, r.totalSize)
  assert.equal(r.passed.size, 0)
  const g = r.blockedStage2.groups
  assert.equal(g.length, 1)
  assert.equal(g[0].kind, 'unmatched')
  assert.equal(g[0].stage, 2)
  // 轨迹两步：阶段一放行、阶段二未命中
  const p = r.blockedStage2.examples[0]
  assert.equal(p.trace.length, 2)
  assert.equal(p.trace[0].passed, true)
  assert.equal(p.trace[1].matchedRuleIndex, null)
})

// --- 第一阶段放行、第二阶段动作不放行 ---
test('阶段一放行、阶段二命中 deny → 第二阶段阻断', () => {
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0' })],
    input({
      stage2RulesJson: stage2([
        { name: 's2-deny', cidr: '0.0.0.0/0', action: 'deny' },
      ]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  assert.equal(r.blockedStage2.size, r.totalSize)
  assert.equal(r.blockedStage2.groups[0].action, 'deny')
  const p = r.blockedStage2.examples[0]
  assert.equal(p.trace[1].matchedRuleName, 's2-deny')
  assert.equal(p.trace[1].passed, false)
})

// --- 综合三分：同一目标内三种结局并存，且精确完备 ---
test('三分并存：阶段一部分放行，阶段二只放通部分端口；大小合计精确', () => {
  // 阶段一：10.0.0.0/24 allow（目标 10.0.0.0/16 内其余部分未命中 → 一阶段阻断）
  // 阶段二：仅 TCP 22 allow（阶段一进入者中只有 TCP/22 最终通过，
  //         TCP/UDP 其余端口与 UDP 全部 → 二阶段未命中阻断）
  const out = analyzeTwoStage(
    [rule({ name: 's1-24', cidr: '10.0.0.0/24', action: 'allow' })],
    input({
      cidr: '10.0.0.0/16',
      protocol: 'ANY',
      stage2RulesJson: stage2([
        { name: 's2-ssh', cidr: '10.0.0.0/24', portStart: 22, portEnd: 22, protocol: 'TCP', action: 'allow' },
      ]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  const target = 65536 * 65536 * 2 // 65536 IPs × 65536 ports × 2 proto
  assert.equal(r.totalSize, target)

  // 最终通过：256 IP × 1 端口 × TCP
  assert.equal(r.passed.size, 256)
  // 第一阶段阻断：目标中不在 10.0.0.0/24 的 IP（65536-256）× 全端口 × 2 协议
  assert.equal(r.blockedStage1.size, (65536 - 256) * 65536 * 2)
  // 第二阶段阻断：/24 内除 TCP/22 外的全部
  //   256 IP × (65536 端口 × 2 协议 - 1)
  assert.equal(r.blockedStage2.size, 256 * (65536 * 2 - 1))
  assert.equal(
    r.passed.size + r.blockedStage1.size + r.blockedStage2.size,
    target,
  )

  // 第二阶段阻断仅一个分组：未命中
  assert.equal(r.blockedStage2.groups.length, 1)
  assert.equal(r.blockedStage2.groups[0].kind, 'unmatched')

  // 通过代表报文只有 TCP（UDP 无任何通过单元）
  assert.deepEqual(
    r.passed.examples.map((p) => p.protocol),
    ['TCP'],
  )
  const ssh = r.passed.examples[0]
  assert.equal(ssh.srcPort, 22)
  assert.equal(ssh.trace.length, 2)
  assert.equal(ssh.trace[0].matchedRuleName, 's1-24')
  assert.equal(ssh.trace[1].matchedRuleName, 's2-ssh')

  // 精确区域：通过区 TCP × 端口 22 × 10.0.0.0/24
  const passRegions = r.passed.regions
  assert.equal(passRegions.length, 1)
  assert.equal(passRegions[0].protocol, 'TCP')
  assert.equal(passRegions[0].rows.length, 1)
  assert.equal(passRegions[0].rows[0].portStart, 22)
  assert.equal(passRegions[0].rows[0].portEnd, 22)
  assert.deepEqual(passRegions[0].rows[0].cidrs, ['10.0.0.0/24'])
  assert.equal(passRegions[0].size, 256)

  // ANY 分协议统计自洽
  for (const p of r.perProtocol) {
    assert.equal(
      p.passedSize + p.blockedStage1Size + p.blockedStage2Size,
      65536 * 65536,
    )
  }
})

// --- 首命中语义：阶段内遮蔽按上方规则动作判定 ---
test('阶段二首命中：被遮蔽规则不影响判定结果', () => {
  // 阶段二：第一条 deny 0/0，第二条 allow 0/0 被完全遮蔽 → 全阻断
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0' })],
    input({
      stage2RulesJson: stage2([
        { name: 's2-deny', cidr: '0.0.0.0/0', action: 'deny' },
        { name: 's2-allow', cidr: '0.0.0.0/0', action: 'allow' },
      ]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  assert.equal(r.blockedStage2.size, r.totalSize)
  assert.equal(r.blockedStage2.groups[0].action, 'deny')
  // 只有 s2-deny 出现在命中轨迹（s2-allow 从未首命中）
  const s2Hits = r.ruleHits.filter((h) => h.stage === 2)
  assert.deepEqual(s2Hits.map((h) => h.ruleName), ['s2-deny'])
})

// --- 多放行动作 ---
test('放行列表含多个动作，大小写精确匹配', () => {
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0', action: 'permit' })],
    input({
      stage1Actions: 'allow, permit',
      stage2RulesJson: stage2([
        { name: 's2', cidr: '0.0.0.0/0', action: 'Allow' },
      ]),
      stage2Actions: 'Allow',
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  assert.equal(out.result.passed.size, out.result.totalSize)

  // 大小写不同：allow ≠ Allow
  const out2 = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0', action: 'allow' })],
    input({
      stage1Actions: 'Allow',
      stage2RulesJson: stage2([{ name: 's2', cidr: '0.0.0.0/0' }]),
    }),
  )
  if (!out2.ok) throw new Error(out2.errors.join(';'))
  assert.equal(out2.result.blockedStage1.size, out2.result.totalSize)
})

// --- 非法 / 停用规则按既有语义排除 ---
test('非法规则与停用规则不参与分析，结构仍可分析', () => {
  const out = analyzeTwoStage(
    [
      rule({ name: 'disabled', cidr: '0.0.0.0/0', enabled: false }),
      rule({ name: 'bad-cidr', cidr: '999.0.0.0/8' }),
      rule({ name: 's1', cidr: '10.0.0.0/8', action: 'allow' }),
    ],
    input({
      cidr: '10.0.0.0/8',
      stage2RulesJson: stage2([
        { name: 's2-disabled', cidr: '0.0.0.0/0', enabled: false },
        { name: 's2', cidr: '0.0.0.0/0', action: 'allow' },
      ]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  assert.equal(r.stage1.validRuleCount, 1)
  assert.equal(r.stage1.invalidExcluded, 1)
  assert.equal(r.stage1.disabledExcluded, 1)
  assert.equal(r.stage2.validRuleCount, 1)
  assert.equal(r.stage2.disabledExcluded, 1)
  // 阶段一只有 s1 覆盖 10/8 → 全部通过
  assert.equal(r.passed.size, r.totalSize)
})

// --- 第二阶段空规则集是合法输入：进入者全部二阶段阻断 ---
test('第二阶段规则为空数组（合法 JSON）→ 进入者全部第二阶段阻断', () => {
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0' })],
    input({ stage2RulesJson: '[]' }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  assert.equal(r.stage2.validRuleCount, 0)
  assert.equal(r.blockedStage2.size, r.totalSize)
  assert.equal(r.blockedStage2.groups[0].kind, 'unmatched')
})

// --- 支持 { rules: [...] } 包装 ---
test('第二阶段 JSON 支持 { rules: [...] } 与数组两种形态', () => {
  const wrapped = JSON.stringify({
    rules: [rule({ name: 's2', cidr: '0.0.0.0/0' })],
  })
  const out = analyzeTwoStage(
    [rule({ name: 's1', cidr: '0.0.0.0/0' })],
    input({ stage2RulesJson: wrapped }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  assert.equal(out.result.passed.size, out.result.totalSize)
})

// --- 目标边界落在规则原子块内部仍被精确切开 ---
test('目标边界精确切分：跨规则区域的 CIDR 边界两侧分类正确', () => {
  // 阶段一：10.0.0.0/25 allow；目标 10.0.0.0/24 恰好一半通过进入阶段二、一半未命中
  const out = analyzeTwoStage(
    [rule({ name: 's1-half', cidr: '10.0.0.0/25' })],
    input({
      cidr: '10.0.0.0/24',
      protocol: 'TCP',
      stage2RulesJson: stage2([{ name: 's2', cidr: '0.0.0.0/0' }]),
    }),
  )
  if (!out.ok) throw new Error(out.errors.join(';'))
  const r = out.result
  const half = 128 * 65536
  assert.equal(r.passed.size, half)
  assert.equal(r.blockedStage1.size, half)
  // 阻断区精确为后半 /25
  const b1Regions = r.blockedStage1.regions
  assert.deepEqual(b1Regions[0].rows.flatMap((row) => row.cidrs), [
    '10.0.0.128/25',
  ])
})

console.log(`\ntwostage: ${passed} 项自检通过`)

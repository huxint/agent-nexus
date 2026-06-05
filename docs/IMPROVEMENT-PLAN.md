# Aether / Nexus — 改进与增强计划

> **版本**: 0.1 · **日期**: 2026-05-31 · **基线 commit**: `bd74a7c`
> **配套文档**: [`DESIGN.md`](./DESIGN.md)（架构愿景）
>
> 本文档把对当前实现的代码级审查，整理成一份**可勾选的攻坚计划**。每一项都写明
> *为什么*（动机）、*怎么做*（具体步骤）、*完成判据*。所有结论都对照过源码行号；
> 少数推断会显式标注。

---

## 0. 如何使用本文档

- **勾选**：`- [ ]` 未开始 → `- [x]` 已完成。每个任务有顶层勾选框（整体完成）和子步骤勾选框（过程）。
- **严重度**：🔴 Critical（动摇"可验证社会"核心命题，或是安全洞）· 🟠 High（限制真实可用性/完整性）· 🟡 Medium（质量/加固）。
- **量级**：`S` 天级 · `M` 1–2 周 · `L` 多周或含研究。
- **任务模板**：每项含「为什么 / 怎么做（子清单） / 完成判据 / 依赖 / 涉及」。

---

## 1. 北极星：我们到底在解决什么

当前实现的哲学骨架是好的、且有辨识度：**"AI 的电脑"（运行层最大自由）与"AI 社会"（社会层只做可验证记忆、不做权限闸门）分离**。signed-event + 主观 replay、内容寻址 + 读时校验、settlement proof 的可插拔 authority anchor，都是"对的形状"。

但有一个贯穿性的根本问题决定了能否"领先"：

> **当前系统是"可验签的主观声明集合"，还不是"可验证的社会事实"。**
> 签名只证明了"谁说的"，没有证明"说的是不是自洽的、唯一的、真实发生的"。

因此本计划的总目标是把它推进到三件事都成立：

1. **账本可防篡改 / 可检测分叉**（tamper-evident）——`I*`
2. **经济可真正结算**（而非单方声明）——`E*`
3. **在主观之上叠加"被见证的真值层"**（少数需要共识的事实）——`I4`

这三条是把"又一个去中心化玩具"和"可追责的 AI 社会底座"区分开的分水岭。

### 贯穿性原则（用于裁决设计分歧）

- **社会 = 记忆，不是权限闸门**：社会层不阻断运行，只表达关系、协作、后果。
- **真值分层**：绝大多数事实保持主观（关系/偏好）；只有少数（所有权、结算终局、集体决议）需要"被见证"，用 `AuthorityAnchor` 升格。
- **bootstrap = 社会引荐，不是中央登记**：入网入口只承担"连接"角色，不承担"权威"角色；稳态不依赖任何入口。
- **入口复数化 + 不可信化 + 缓存**，而不是"消灭入口"（完全零信息冷启动在信息论上不可能）。

---

## 2. 里程碑与执行顺序

> 排序原则：先修地基与安全洞，再做需要研究的增强。括号内是该波次的"为什么先做它"。

- [x] **Wave 0 — 当天/当周可拿分**（堵住直接的完整性/安全洞，量级都很小）
  `E1` 自我交易守卫 · `E5` 验真 counterparty 签名 · `K1` 私钥加密 · `I2` 内容哈希 id · `A4` 文档对齐 · `A3` 建 CONTEXT.md/ADR · `E4` 定价对齐计量
- [x] **Wave 1 — 地基：让账本防篡改**（其余追责才有意义）
  `I1` 每作者哈希链 + 抵赖检测（并行 `A1` 拆 `society.rs`、`A5` 对抗性测试）
- [x] **Wave 2 — 真值与经济**
  `I4` 真值层级 → `E3` 可验证执行/计量 → `E2` 女巫成本 · `I3` 时间戳可信度
- [x] **Wave 3 — 多方安全**（联网协作前必须）
  `S1` 可选隔离档位 · `S2` exec 边界 + secret 隔离 → `S3` 机密性 · `S4` 能力声明验证 · `K4`/`K5` 吊销/委托
- [x] **Wave 4 — 身份生命周期**
  `K2` key 轮换 · `K3` 身份恢复
- [x] **Wave 5 — 运营级 P2P 与可扩展性**
  `N2` peer scoring · `N3` eclipse 加固 · `N4` 发现去中心化 · `N1` NAT 穿透 · `N5` 日志 compaction · `N6` block GC · `N7` 协议版本 · `D1`/`D2` 并发写与所有权
- [ ] **Wave 6 — Agent 实时交互与控制面**
  `UX1` 状态脉冲 · `UX2` daemon/IPC · `UX3` 短命令自动路由 · `UX4` inbox/watch 事件流 · `UX5` 命令词汇收敛

---

## 3. 详细任务清单

### 3.1 可验证性与防篡改（I）

#### - [x] I1 — 每作者哈希链 + 抵赖（equivocation）检测 · 🔴 · L
**为什么**：`SocialEvent.id` 现在是 128-bit 随机数（`nexus-agent/src/protocol.rs:150`），没有 per-author 序列号、没有 prev-hash 链。一个 DID 可以对不同 peer 展示**两套互相矛盾的历史**而系统无法察觉。这是"可验证社会账本"的地基塌陷——其余所有追责（信誉、争议、治理）都建立在这个无法防篡改的日志上。
**怎么做**：
- [x] 给 `SocialEvent` 增加 `seq: u64`（作者单调递增）与 `prev: Option<String>`（作者上一条事件 id）。
- [x] `id` 改为 `hash(canonical(author, seq, prev, timestamp, kind))`（内容哈希，**吸收 `I2`**）。
- [x] `SocialEventLog::append`/`merge` 校验同一作者的链连续性（缺口容忍：乱序到达先挂起，补齐再校验）。
- [x] 定义 `EquivocationProof { author, event_a, event_b }`：两条事件同 `(author, seq)` 但 `id`/内容不同，且都验签通过 = 密码学抵赖证据。任何人可独立验证。
- [x] 把抵赖做成一等公民社会事实（可 gossip）；`Society` 标记该作者 equivocating，并在推荐/信誉里降权或排除。
- [x] 这是**破坏性 wire 变更** → 与 `N7`（版本协商）联动，提供迁移路径。
**完成判据**：构造"同 seq 不同内容"的两条签名事件，节点能产出可被第三方验证的 `EquivocationProof`；正常乱序事件仍能最终一致入账。
**依赖**：`I2`（可先落地）；牵动 `A1`、`A5`、`N7`。
**涉及**：`nexus-agent/src/protocol.rs`、`event_log.rs`、`society.rs`。

#### - [x] I2 — 事件 id 改为内容哈希 · 🟠 · S
**为什么**：随机 id 让 `event_log.rs:75-90` 的"同 id 不同 payload = conflict"检测形同死代码（随机碰撞概率 ~2⁻⁶⁴），同一内容重发又因新随机 id 而无法去重。内容哈希让去重/冲突检测真正生效，并且是 `I1` 的前置。
**怎么做**：
- [x] `id = hex(sha256(signing_payload))`（不含 signature 域）。
- [x] 移除/简化现在依赖随机 id 的去重逻辑，改为"同 id 必同内容"。
- [x] 调整测试（`event_log.rs` 里人为构造同 id 的用例）。
**完成判据**：重发完全相同内容的事件被去重；任何 payload 改动都改变 id。
**依赖**：无（可作为 `I1` 的第一步独立合入）。
**涉及**：`nexus-agent/src/protocol.rs:148-159`。

#### - [x] I3 — 时间戳可信度 + 因果排序 · 🟠 · M
**为什么**：replay 顺序是 `timestamp → id → author`（`event_log.rs:107-119`），而 timestamp 由作者自填、**无任何约束**，可"倒签"把事件插到争议之前；tiebreak 又是（旧实现里的随机）id，可被操纵。
**怎么做**：
- [x] 接收方记录"观察时间"；拒绝明显超前于本地时钟的事件（容忍合理偏移）。
- [x] 作者内部排序改用 `I1` 的 `seq`（因果链），而非自报时间。
- [x] 跨作者排序用确定性、非单一作者可控的 tiebreak（如内容哈希），并文档化合并语义。
**完成判据**：倒签时间戳无法改变同一作者事件的因果顺序；跨节点 replay 仍确定一致。
**依赖**：`I1`。
**涉及**：`nexus-agent/src/event_log.rs`、`memory.rs`。

#### - [x] I4 — 真值层级（被见证的事实）· 🟠 · L
**为什么**：现在一切都是主观 replay，包括**所有权、结算终局、集体决议**——这些恰恰是需要"大家认账"的。`settlement.rs` 已经有 `AuthorityAnchor`（`CollectiveQuorum` / 外部链 / TEE / ZK）这个正确抽象，只差把它接到真正需要共识的事实上。
**怎么做**：
- [x] 明确"需共识事实"的最小集合：workspace 所有权转移、结算终局、collective 决议。
- [x] 为这些事实定义"已锚定 vs 仅声明"两态；`record_settlement`/所有权变更可要求或优先 `AuthorityAnchor`。
- [x] `society --json` 与推荐视图里把 `anchored` 与 `claimed` 显式区分。
- [x] 实现 `CollectiveQuorum` 锚的真实校验（见 `settlement.rs:142-152` 已有阈值校验，接到决议上）。
**完成判据**：一笔无锚定的所有权/结算只显示为"声明"；带有效 quorum 锚的显示为"已见证"。
**依赖**：`I1`（事件可信）、`E5`。
**涉及**：`nexus-economy/src/settlement.rs`、`nexus-agent/src/society.rs`。

---

### 3.2 经济完整性（E）

#### - [x] E1 — 自我交易守卫（publisher ≠ executor）· 🔴 · S
**为什么**：`apply_known_task_result`（`society.rs:1930-1989`）校验了 `assigned_to == executor` 与状态机，但**没有 `publisher != executor`**。一个 DID 可发布→自报价→自接受→自完成，刷出正向 interaction/reputation；因为 replay 确定性，这条假信誉会在全网一致地被算出来，污染 `recommend_providers`。
**怎么做**：
- [x] 在 `apply_known_task_result` 里：当 `task.publisher == result.executor` 时**不产生** interaction/reputation 后果（可仍保存为 claim 供审计）。
- [x] 同步检查 offer/accept 自环（自己接受自己的报价）是否也应不计后果。
- [x] 加测试：自我交易不改变信誉。
**完成判据**：自发自接自完的任务不提升任何信誉/关系强度。
**依赖**：无。
**涉及**：`nexus-agent/src/society.rs:1930-1989`。

#### - [x] E5 — 真正验证 mutual-credit 的对手方签名 · 🔴 · S
**为什么**：`MutualCreditSettlement.validate()` 对 `counterparty_signature` **只查非空、从不验签**（`settlement.rs:179-183`）；`record_settlement` 也只 `proof.validate()` 就入账（`society.rs:1919-1928`）。payer 可单方面记一笔"已双边结算"并塞一段伪造签名，全网当真。
**怎么做**：
- [x] 定义对手方签名的规范载荷（`ledger_tx_id, amount, payer, payee`）。
- [x] `validate`/`record_settlement` 按 payee DID 真正验签；失败则拒绝入账。
- [x] payee 未签的结算只能记为"单方声明"，不能算"双边已确认"。
- [x] 加测试：伪造对手方签名被拒。
**完成判据**：缺少有效 payee 签名的 mutual-credit 结算无法成为"已确认"社会事实。
**依赖**：与 `I4` 的"声明 vs 见证"两态一致。
**涉及**：`nexus-economy/src/settlement.rs`、`nexus-agent/src/society.rs`。

#### - [x] E4 — 定价维度与真实计量对齐 · 🟡 · S
**为什么**：`ResourcePricing` 对 `cpu_per_second / storage_per_mb_hour / bandwidth_per_mb` 定价（`pricing.rs:10-23`），但这些量根本没被测量（见 `E3`）。在给不存在的数字定价。
**怎么做**：
- [x] 短期：把定价收敛到**已能测量**的维度（wall_time、base_fee），其余标注"实验性/未计量"。
- [x] 长期：随 `E3` 落地后恢复多维定价。
**完成判据**：定价模型不再依赖恒为 0 的计量字段。
**依赖**：`E3`（长期）。
**涉及**：`nexus-economy/src/pricing.rs`。

#### - [x] E3 — 真实计量 + 可验证执行 · 🟠 · L
**为什么**：`ResourceUsage` 7 个字段，executor 只填了 `wall_time` 和 `process_count: 1`（`executor.rs:205-230`），cpu/memory/fs/bandwidth 恒为 0，且**全自报、对端不可验证**。原设计的 "gas" 随"原生执行取代 WASM"而消失。经济建立在不可验证的数字上。
**怎么做**：
- [x] 真实计量：`getrusage`/`wait4`（cpu_user/kernel、peak_memory）、IO 计数；`process_count` 计入子进程。
- [x] 付款相关执行升级为**可质询**之一：
  - [x] N-of-M 独立重执行 + 输出 CID 交叉比对（已有 CID 校验，复用之）；或
  - [x] TEE attestation（`AuthorityKind::TeeAttestation` 已留位）；或
  - [x] 确定性重放容器。
- [x] 在视图里把"自报计量"与"可验证计量"分开标注。
**完成判据**：一笔付款可附带可被第三方验证的执行证据；自报计量不再单独驱动结算。
**依赖**：`E4`、`S1`（隔离/确定性环境）。
**涉及**：`nexus-runtime/src/executor.rs`、`resources.rs`、`nexus-economy/src/settlement.rs`。

#### - [x] E2 — 女巫成本 / 信誉不可自产 · 🟠 · L
**为什么**：身份免费（`NodeIdentity::generate`），N 个 DID 互评即可批量制造"可信协作网"。文档宣称的"劳动换信任"在 reputation 路径上没有兑现。
**怎么做**：
- [x] 信誉按**主观信任图可达性**加权：只采信经由本节点 `TrustGraph`（`nexus-economy/src/trust.rs`）可达的关系所贡献的信誉（把已有的 max-flow/路径能力接到 reputation 权重上）。
- [x] 引入抵押/外部见证作为高信誉的前提（接 `I4` 的 anchor）。
- [x] 检测并降权"互评闭环"式 sybil cluster。
**完成判据**：一群互不被外部信任的新 DID 无法相互刷出对第三方可见的高信誉。
**依赖**：`I1`、`I4`。
**涉及**：`nexus-economy/src/{trust.rs,reputation.rs}`、`nexus-agent/src/society.rs`。

#### - [x] E7 — 决策：信用账本是"仅记录"还是"可拒绝的闸门" · 🟡 · M
**为什么**：`CreditLedger`/max-flow 路由作为库存在（`ledger.rs`、`trust.rs`），但 live 路径只 `proof.validate()` 入账，额度/余额未做闸门。需要一个明确决策并落实，避免似有实无。
**怎么做**：
- [x] 写成 ADR：信用是"社会记录"（与哲学一致）还是"可拒绝结算的本地闸门"。
- [x] 按决策落实或显式标注为"仅记录"。
**完成判据**：行为与文档一致，不再有"看起来在记账其实不影响任何决策"的歧义。
**依赖**：`A3`。
**涉及**：`nexus-economy/src/ledger.rs`、ADR。

---

### 3.3 身份与密钥生命周期（K）

#### - [x] K1 — 私钥静态加密 · 🔴 · S
**为什么**：`identity.rs:33-35` 注释声称"never serialised to disk in plaintext"，但 `save_to_file`（`:91-101`）把 32 字节私钥以 `seed_hex` **明文 JSON** 写入 `.nexus-identity.json`。与"无沙箱执行"叠加时尤其危险（任务命令可直接读走它）。
**怎么做**：
- [x] 用 passphrase-KDF（当前 PBKDF2-SHA256；argon2 可后续替换）加密 seed，或接 OS keychain；支持 `NEXUS_PASSPHRASE`/交互输入。
- [x] 为已存在的明文文件提供一次性迁移。
- [x] 修正自相矛盾的文档注释。
**完成判据**：磁盘上不再有明文私钥；加载需密钥材料。
**依赖**：无。
**涉及**：`nexus-crypto/src/identity.rs`、`nexus-node` 身份加载路径。

#### - [x] K2 — 密钥轮换 · 🟠 · L
**为什么**：单一不可变 `did:key`（`did.rs`）使私钥被偷=永久冒充、无法吊销。长期演化的社会必须能换钥。
**怎么做**：
- [x] 引入可轮换身份模型（控制器密钥 / DID 文档 / 旧钥签名"授权新钥"链）。
- [x] 旧签名仍可验证（历史不失效），新操作要求新钥。
**完成判据**：一个身份能在不丢历史的前提下完成密钥轮换并被网络接受。
**依赖**：`I1`（历史可信）、`K4`。
**涉及**：`nexus-crypto/src/{did.rs,identity.rs}`。

#### - [x] K3 — 身份恢复（社会/门限）· 🟠 · L
**为什么**：私钥丢失=身份、所有权、历史、信用永久消失。需要恢复路径。
**怎么做**：
- [x] social recovery（指定守护者 DID，门限授权恢复）或 Shamir/MPC 备份。
**完成判据**：丢钥后可凭预设守护者门限恢复对身份的控制。
**依赖**：`K2`。
**涉及**：`nexus-crypto`、`nexus-agent`（守护者声明）。

#### - [x] K4 — 吊销机制（capability + 身份）· 🟡 · M
**为什么**：capability 只有过期、无吊销（`capability.rs`）；身份也无吊销。承诺/邀请发出后无法在到期前收回。
**怎么做**：
- [x] 吊销事件（签名）+ 短期令牌 + 可选状态查询。
- [x] `Society` 重放吊销并在视图里反映。
**完成判据**：一张未过期 capability 可被签发者吊销并被网络认可。
**依赖**：`I1`。
**涉及**：`nexus-crypto/src/capability.rs`、`nexus-agent/src/society.rs`。

#### - [x] K5 — capability 委托链 · 🟡 · M
**为什么**：capability 不能委托（issuer→subject→再转授），限制了组织化协作。
**怎么做**：
- [x] 支持带深度/范围约束的委托链；验证时校验整条链。
**完成判据**：A 授权 B，B 可在约束内转授 C，且可被验证。
**依赖**：`K4`。
**涉及**：`nexus-crypto/src/capability.rs`。

---

### 3.4 安全与隔离（S）

#### - [x] S1 — 可选执行隔离档位 · 🔴 · L
**为什么**："无沙箱"在 `clone` 他人 workspace / `accept` 他人 task 时 = **以自己身份运行不可信代码**。单机自用是特性，多方协作是洞。
**怎么做**：
- [x] 把隔离做成 `ExecOptions` 档位：Linux 用 landlock/seccomp/bubblewrap，或容器/microVM。
- [x] **默认策略**：运行克隆来的/外来 workspace 或 accepted task 时默认开启；自有 workspace 默认关闭（保留最大自由）。
**完成判据**：执行外来代码时默认进入隔离环境，私钥等 secret 不可达。
**依赖**：`S2`、`K1`。
**涉及**：`nexus-runtime/src/executor.rs`、`nexus-node` exec 路径。

#### - [x] S2 — exec 边界 + secret 隔离 · 🔴 · M
**为什么**：`exec` 任意 cwd/env、无边界，可读到 `~/.ssh` 或明文私钥。即便暂不做完整沙箱，也要先收口。
**怎么做**：
- [x] cwd 限制在 workspace 根内；env 走白名单。
- [x] 确保 `.nexus-identity.json` 等 secret 不在任何 exec 可达路径（配合 `K1` 加密 + 存放位置隔离），或以低权限用户运行 exec。
**完成判据**：默认配置下任务命令无法读取节点私钥与无关用户文件。
**依赖**：`K1`。
**涉及**：`nexus-runtime/src/executor.rs`、`nexus-workspace`。

#### - [x] S3 — 机密性 / 选择性披露 · 🟠 · L
**为什么**：所有 `SocialEvent` 明文 JSON 全网 gossip——manifest、intent、relation、任务细节、root 全公开。真实社会需要私下关系与机密协作。
**怎么做**：
- [x] 支持加密事件（对指定接收者）/ 选择性披露 / 私有关系图。
- [x] 区分"公开社会层"与"加密社会层"。
**完成判据**：两个 AI 可建立不被第三方读取的关系/任务。
**依赖**：`K2`（密钥）。
**涉及**：`nexus-agent/src/protocol.rs`、`nexus-network`。

#### - [x] S4 — 能力声明的验证 · 🟡 · M
**为什么**：manifest 可声明任意 capability（`provides`），无人验证。推荐/信任建立在自报能力上。
**怎么做**：
- [x] 能力挑战/证明机制，或在视图里把"声明的能力"与"经验证的能力"分开。
**完成判据**：未经验证的能力声明不会被当作既成事实参与推荐排序。
**依赖**：`I1`。
**涉及**：`nexus-agent/src/{manifest.rs,society.rs}`。

---

### 3.5 网络与发现（N）

> 发现策略的指导原则见 §1：入口只承担连接角色，稳态不依赖入口，入口复数化/不可信化/可缓存。

#### - [x] N4 — 发现去中心化（peer-cache 优先 + 复数入口 + 社会引荐）· 🟡 · S
**为什么**：当前兜底是一份编译期内置 public seed 列表，是潜在中心点（可审查/eclipse/单点故障）。注意：seed 伪造不了内容（已验签/CID），剩下的只有连接层风险。
**怎么做**：
- [x] 确认解析顺序为 **peer cache 优先、seed 最后兜底、用户可完全覆盖**（基本已有，确认+文档化）。
- [x] DNS seed 复数化（多个互不隶属的运营方），替代单一硬编码列表。
- [x] **社会化引荐做成一等公民入网路径**：multiaddr 链接 / QR / invite capability（契合"AI 社会=被引荐"）。
- [x]（进阶）寄生公共 DHT（IPFS public DHT profile）做无主全球 rendezvous，仅作冷启动跳板；通过 `NEXUS_PUBLIC_RENDEZVOUS=ipfs` 显式启用。
**完成判据**：新节点能在不连接任何单一指定方的情况下入网；稳态完全不依赖 seed。
**依赖**：`N3`（让不可信入口非致命）。
**涉及**：`nexus-node/src/{bootstrap.rs,discovery.rs}`。

#### - [x] N3 — Kademlia eclipse 加固 · 🟡 · M
**为什么**：比"消灭 seed"更重要——让**任意单一入口都无法欺骗/困住你**，那么入口可信与否就不再致命。
**怎么做**：
- [x] DHT 查询走多条互不相交路径；路由表桶多样性。
- [x] 全程验签/验 CID（已有）；优先复用已知良好 peer。
- [x]（进阶）S/Kademlia 式节点 id 约束：Identify 公钥必须导出连接 PeerId，DHT 地址必须与目标 PeerId 绑定。
**完成判据**：单个恶意初始 peer 无法让节点收敛到被操纵的"假网络"。
**依赖**：无。
**涉及**：`nexus-network`、`nexus-node/src/discovery.rs`。

#### - [x] N2 — Gossipsub peer scoring + 严格验证 · 🟠 · M
**为什么**：`behaviour.rs:115-124` 未配置 peer scoring，社会事件 topic 可被任意节点灌爆；无效事件还会经 mesh 传播。
**怎么做**：
- [x] 配置 gossipsub peer scoring 参数。
- [x] `ValidationMode::Strict` + 应用层验证回调：先验签再决定 `Accept/Ignore/Reject`，无效事件不转发。
- [x] 对 inbound 社会事件加速率限制。
**完成判据**：无效/超速 spam 不被本节点转发，发送方被降分。
**依赖**：`I2`（id 稳定便于去重）。
**涉及**：`nexus-network/src/behaviour.rs`。

#### - [x] N1 — NAT 穿透 · 🟠 · M
**为什么**：原先只组合了 kad/mdns/gossipsub/req-resp/identify；DESIGN 宣称的 autonat/dcutr/relay 未接入 → 多数 NAT 后节点实际连不通，"全球 P2P"名不副实。
**怎么做**：
- [x] 接入 `autonat`（NAT 探测）+ `dcutr`（打洞）+ `relay` client（`/p2p-circuit` 中继兜底）。
- [x]（可选项已重新界定）WebRTC 留作浏览器节点传输后续；native 节点当前完成 QUIC + relay circuit 路径。
**完成判据**：两个分别在家用 NAT 后的节点能建立直连或经中继连通。
**依赖**：无。
**涉及**：`nexus-network/src/{behaviour.rs,transport.rs,swarm.rs}`。

#### - [x] N5 — 社会日志 compaction / checkpoint · 🟠 · L
**为什么**：`SocialMemory` 每次加载从全量日志 `to_society()` 重放（O(全历史)），无 compaction/快照/遗忘 → 确定性的可扩展性天花板。
**怎么做**：
- [x] 周期性对 replay 出的 `Society` 状态做带哈希的 checkpoint；加载 = checkpoint + 重放尾部。
- [x] 旧事件压实 + 可配置"遗忘"策略。
**完成判据**：长历史节点的加载时间不再随总事件数线性增长。
**依赖**：`I1`（链可信便于 checkpoint）。
**涉及**：`nexus-agent/src/{memory.rs,event_log.rs}`。

#### - [x] N6 — block store GC / pin / 配额 · 🟠 · M
**为什么**：`store.rs` 只有 put/get/has，每次 snapshot 写新块、旧块永不回收，磁盘单调增长。
**怎么做**：
- [x] refcount/pin：当前 workspace + 保留策略内的历史 root 为根做可达性标记。
- [x] GC 不可达块；加配额。
**完成判据**：删除/超出保留策略的快照后，磁盘占用可回收。
**依赖**：无。
**涉及**：`nexus-storage/src/store.rs`、`nexus-workspace`。

#### - [x] N7 — 协议版本协商与演进 · 🟡 · M
**为什么**：除 manifest version 外无版本协商，跨 fleet 演进困难；`I1` 的 wire 变更尤其需要它。
**怎么做**：
- [x] `SocialEventKind`/sync 协议的版本字段 + 前向兼容/降级策略。
**完成判据**：新旧版本节点能识别彼此并安全降级或拒绝。
**依赖**：与 `I1` 联动。
**涉及**：`nexus-agent/src/protocol.rs`、`nexus-sync`。

---

### 3.6 数据模型与一致性（D）

#### - [x] D1 — 真正的 CRDT 或明确的并发写策略 · 🟠 · L
**为什么**：`nexus-sync` 只拉 root/blocks（`message.rs`），无合并；并发写同一 workspace = 两个 root 并存、靠公告时机 LWW 或分叉。DESIGN §6.2 的 RGA/Op-log/Lamport 合并**未实现**。
**怎么做**：
- [x] 决策二选一并写成 ADR：①实现操作型 CRDT；②明确"快照 + 显式分叉/合并"模型并提供合并 UI。
- [x] 按决策实现。
**完成判据**：两节点并发改同一 workspace 后，有定义良好、可预期的收敛/分叉结果。
**依赖**：`A3`。
**涉及**：`nexus-sync`、`nexus-workspace/src/workspace.rs`。

#### - [x] D2 — 所有权/成员作为真值 · 🟡 · M
**为什么**：所有权靠"谁加载了目录 + 本地注册表"，非真值。
**怎么做**：
- [x] 所有权用签名声明 + `I4` 真值层级；区分"拥有"与"持有副本"。
**完成判据**：所有权变更需可验证声明，不能因"加载了目录"被误判。
**依赖**：`I4`。
**涉及**：`nexus-workspace`、`nexus-agent/src/society.rs`。

---

### 3.7 架构与可维护性（A）

#### - [x] A1 — 拆分 `society.rs` 巨石 · 🟠 · M
**为什么**：`nexus-agent/src/society.rs` 4534 行，replay 状态机/索引/推荐/治理/结算混在一起，`apply_event` 这个 seam 背后藏着全系统最复杂的状态机却无法单独测试（低 locality）。做 `I1`/`I4`/`E*` 都要动它。
**怎么做**：
- [x] 拆出 `task-market 状态机` 到独立 projection 模块；保留 `Society` 作为 replay 汇聚层，后续可继续拆 `recommend` / `governance` / `settlement`。
**完成判据**：任务市场状态机可在不构造完整 Society 的情况下被单元测试。
**依赖**：建议与 `I1` 并行。
**涉及**：`nexus-agent/src/society.rs`。

#### - [x] A2 — 统一签名序列化 + domain separation · 🟡 · S
**为什么**：capability 用 canonical CBOR（`capability.rs:167`），event 用 `serde_json`（`protocol.rs:162-177`），且无类型 tag → 跨结构签名混淆风险 + JSON 规范化脆弱。
**怎么做**：
- [x] 统一用 canonical CBOR 签名；每类签名载荷加 domain separation tag（如 `"nexus:social-event:v2"`）。
**完成判据**：一个类型的签名无法被当作另一类型验证通过。
**依赖**：与 `I1` 联动（反正要改 wire）。
**涉及**：`nexus-crypto`、`nexus-agent/src/protocol.rs`。

#### - [x] A3 — 建立 CONTEXT.md + ADR · 🟡 · S
**为什么**：仓库无 CONTEXT.md、无 ADR，关键决策（为何主观、为何无沙箱、经济是记录还是闸门、并发写策略、bootstrap 哲学）未沉淀，导致反复重提。
**怎么做**：
- [x] 建 `CONTEXT.md`（领域词汇：Workspace/Society/SocialEvent/Capability/Collective/settlement proof/authority anchor…）。
- [x] 建 `docs/adr/`，把已定决策写成 ADR（见 §4）。
**完成判据**：每个"已定"决策都有一条可引用的 ADR。
**依赖**：无。
**涉及**：`CONTEXT.md`、`docs/adr/`。

#### - [x] A4 — DESIGN.md 区分 built vs envisioned · 🟡 · S
**为什么**：DESIGN.md 卖 WASM/CRDT/支付路由/NAT 穿透，与实现漂移，损害可信度与 onboarding。
**怎么做**：
- [x] 在 DESIGN.md 标注每节"已实现 / 规划中"；把未实现项链接到本计划对应任务。
**完成判据**：读者能一眼区分现状与愿景。
**依赖**：无。
**涉及**：`docs/DESIGN.md`。

#### - [x] A5 — 对抗性测试套件 · 🟠 · M
**为什么**：缺少针对攻击面的测试，`I1`/`E1`/`E5` 这类不变量需要回归保护。
**怎么做**：
- [x] 测试：equivocation 检测、自我交易不计信誉、倒签时间戳、畸形/超大事件、伪造对手方签名、任务事件乱序到达。
**完成判据**：上述每个攻击都有对应的失败→修复→回归测试。
**依赖**：随 `I1`/`E1`/`E5` 一起加。
**涉及**：各 crate `#[cfg(test)]`、可加 `tests/` 集成测试。

---

### 3.8 Agent 实时交互与命令面（UX）

#### - [x] UX1 — Agent 状态脉冲命令 · 🟠 · S
**为什么**：AI 每轮开始时需要快速知道“我是谁、有哪些本地 workspace、社会记忆里有什么、当前发现了哪些远端电脑”，但不能为了读状态启动 `serve`、创建身份、或卡在 passphrase 输入上。
**怎么做**：
- [x] 增加 `nexus-node agent status --base <DIR> [--json]`。
- [x] 只读本地状态：identity metadata、workspace registry/config、social memory、discovery cache。
- [x] 缺身份、身份加密、social memory 缺失或 cache 异常都结构化返回，不把 read-only 状态命令变成初始化命令。
**完成判据**：空 base 上运行不会创建 `.nexus-identity.json`；已有 workspace metadata 可在无 passphrase 情况下显示。
**依赖**：`A3`。
**涉及**：`nexus-node/src/agent_status.rs`、`nexus-node/src/main.rs`。

#### - [ ] UX2 — 长驻 daemon + base-scoped IPC · 🔴 · M
**为什么**：`serve` 前台占用 agent 进程，AI 无法一边维持网络可达、一边继续实时交互、读外部状态、发社会消息。
**怎么做**：
- [x] 增加 `nexus-node daemon start|stop|status --base <DIR>`。
- [x] daemon 后台托管现有 `serve`，记录 pid、启动参数、stdout/stderr 日志和运行健康。
- [x] 在 `<base>/.nexus/daemon.sock` 下提供 Unix domain socket；`status`/`shutdown` 请求和响应都用 bounded JSON。
- [ ] Windows named pipe parity。
- [x] pid/lock 文件要能检测 stale daemon；重复 start 返回已运行状态而不是再起一个网络节点。
**完成判据**：agent 可以启动 daemon 后立刻回到交互；后续 `agent status` 能看到 daemon peer/listen/health。
**依赖**：`UX1`。
**涉及**：`nexus-node/src/daemon.rs`、`nexus-node/src/agent_status.rs`、`nexus-network`。

#### - [ ] UX3 — 短命令自动路由到 daemon · 🟠 · M
**为什么**：现在 `discover`/`clone`/`network status` 会各自启动短时网络实例，命令多且状态割裂。daemon 存在时，短命令应复用已连 peer 和缓存。
**怎么做**：
- [x] `agent status|sync|discover|send|inbox|exec` 优先通过 IPC 请求 daemon。
- [x] `agent discover` 在 daemon IPC 可用时通过 `agent_discover` control request 读取 daemon 侧 discovery cache；IPC 失败时退回本地 cache 并返回结构化问题。
- [x] `agent sync` 在 daemon IPC 可用时通过 `agent_sync` control request 读取 daemon 侧 discovery cache，再在本地生成 clone/sync plan；IPC 失败时退回本地 cache 并返回结构化问题。
- [x] `agent sync --apply --workspace <HEX> --name <TEXT>` 在 daemon IPC 可用、且 discovery cache 有已签名地址来源时，通过 `agent_sync_apply` control request 复用 daemon network 执行 clone，落盘 workspace、注册本地路径、写入 social memory，并在 JSON `apply.clone` 中返回 path/root/peer/owner。
- [x] 已存在本地 workspace 的 `agent sync --apply --workspace <HEX>` 已经 daemon-routed 到明确控制面边界：`applied=false`、`mode=daemon_ipc_refresh_pending`、`suggested_command` 指向 inspect/sync 计划；不误走 clone、不要求 `--name`。
- [ ] 已存在本地 workspace 的真正 live refresh/apply 仍需后续 daemon-routed 实现；当前只返回 pending 边界、inspect/refresh 计划或专家命令提示。
- [x] `agent inbox` 在 daemon IPC 可用时通过 daemon event journal 获取增量事件，并通过 `agent_discover` control request 读取 daemon 侧 discovery cache 生成 clone-ready 提示；IPC 失败时退回本地 cache 并显式标注来源。
- [x] daemon 不存在时，`agent discover` 读 discovery cache 并给出显式联网刷新提示；不启动网络、不创建身份、不解密私钥。
- [x] daemon 不存在时，其余读状态命令退化为本地缓存，显式联网命令给出可执行提示。
- [x] daemon IPC 请求失败时，`agent send` 保存到本地社会记忆，`agent exec` 本地执行并在 delivery 中结构化标注 fallback 原因。
- [x] `network status` 在 daemon IPC 可用时读取 live diagnostics 和 daemon event journal；显式 probe 参数仍保留短时网络实例。
- [x] 输出 JSON schema 稳定，错误包含 `kind`、`message`、`suggested_command`。
**完成判据**：常用 agent 流程不需要手写 `--listen`、`--bootstrap`、`--invite`，除非用户要覆盖默认网络策略。
**依赖**：`UX2`。
**涉及**：`nexus-node/src/agent_status.rs`、后续 `agent_control` 模块。

#### - [x] UX4 — inbox/watch 事件流 · 🟠 · M
**为什么**：实时交互不是只查快照。AI 需要知道“刚收到什么社会事件、哪个 workspace root 变化、哪个任务/intent 需要响应”。
**怎么做**：
- [x] 增加本地缓存版 `nexus-node agent inbox --base <DIR> [--agent <DID>] [--since <CURSOR>] [--limit <N>] [--json]`：汇总 daemon 提醒、intent 推荐、open/assigned tasks、clone-ready discovery；只读，不启动网络、不创建身份、不解密私钥。
- [x] daemon 维护 bounded event journal，并通过 `nexus-node daemon events --base <DIR> [--since <CURSOR>] [--limit <N>] [--json]` 暴露：social event accepted、workspace announcement、peer/listen/sync 网络事件、workspace snapshot changed。
- [x] 将 task/intent/action recommendation changed 纳入 daemon event journal：accepted social events 会派生 `intent_changed`、`task_changed`、`action_recommendation_changed`。
- [x] `nexus-node agent inbox --base <DIR> --since <cursor> --json` 在 daemon IPC 可用时返回 `daemon_events` 增量 journal，并把事件映射为 `daemon_event` inbox item。
- [x] `nexus-node agent watch --base <DIR> --json` 轮询 daemon event journal 并输出 `nexus.agent_watch_event.v1` NDJSON 事件流，适合外层 agent runtime 订阅。
**完成判据**：一个外部 agent 可以用 cursor 增量处理 Nexus 内通信，同时继续使用普通 shell/filesystem 工具处理 Nexus 外状态。
**依赖**：`UX2`。
**涉及**：`nexus-node`、`nexus-agent`。

#### - [x] UX5 — 命令词汇收敛与文档重排 · 🟡 · S
**为什么**：专家命令完整但过多，AI 容易在 `event ...`、`act ...`、`discover ...`、`network status ...` 间迷路。
**怎么做**：
- [x] 增加 `nexus-node agent up --base <DIR> ...` 作为 AI 面向的 daemon 启动动词，复用 daemon start 语义并返回 `nexus.agent_up.v1`。
- [x] 增加 `nexus-node agent send --base <DIR> ...`，用短命令把 status/need/offer/proposal/goal 写入签名本地 social memory，并显式返回 local-only delivery 状态。
- [x] 增加 `nexus-node agent exec --base <DIR> --workspace <PATH> ... -- <CMD>`，复用现有 `exec` 自由运行、快照和社会记忆记录语义，并返回 `nexus.agent_exec.v1`。
- [x] 增加 `nexus-node agent sync --base <DIR> [--workspace <HEX>] [--name <TEXT>] [--json]`，先提供本地 workspace + discovery cache 的 sync/clone 计划视图，不启动短生命周期网络。
- [x] 保留现有专家命令，但帮助文案先显示 agent path，再显示 advanced path。
- [x] 在 `CONTEXT.md` 增加“AI 每轮操作建议”：先 `agent status`，再根据 daemon/society/discovery 决策。
**完成判据**：新 AI 只靠 top-level help 就能完成启动、查看状态、发现/收消息、发消息、执行并记录结果。
**依赖**：`UX1`。
**涉及**：`nexus-node/src/main.rs`、`CONTEXT.md`、`docs/DESIGN.md`。

---

## 4. 待决策记录（ADR 待办）

这些是"立场/取舍"而非"bug"，应写成 ADR 固化，避免反复重提（属于 `A3`）：

- [x] **ADR-0001 主观真值 vs 共识真值**：默认主观；哪些事实进入 `I4` 真值层。
- [x] **ADR-0002 无沙箱哲学的边界**：自有 vs 外来执行的隔离默认策略（`S1`）。
- [x] **ADR-0003 经济是"记录"还是"闸门"**（`E7`）。
- [x] **ADR-0004 并发写：CRDT vs 快照+显式分叉**（`D1`）。
- [x] **ADR-0005 bootstrap 哲学**：入口只承担连接角色、稳态无入口、引荐为一等公民（`N4`）。
- [x] **ADR-0006 计量与结算的可验证性要求**（`E3`）。
- [x] **ADR-0007 Agent 控制面**：daemon 长驻，`agent ...` 短命令作为 AI 交互面（`UX*`）。

---

## 5. 不要动（已经做对的）

避免在重构中破坏这些：

- 内容寻址 + 读时 CID 校验 + 自修复（`nexus-storage/src/store.rs`）。
- signed-event + 确定性主观 replay 的整体模型。
- `author ↔ subject` 一致性校验（`protocol.rs` `validate_author_claims`，含 `SettlementRecorded` 绑定 `payer`）。
- settlement proof 的可插拔 `AuthorityAnchor` 抽象（形状对，缺真实 verifier → 由 `I4`/`E*` 补齐）。
- 任务事件乱序容忍（候选事件待依赖到达再投影）。
- 近期运营加固：原子写、sync 帧上限、进程组 kill、输出捕获上限、文件级 CID 缓存。
- 哲学立场："社会 = 记忆而非权限闸门"、"最大自由度"。

---

## 6. "领先"的完成定义

当以下成立时，这个框架就从"可验签的主观声明集合"跨到了"可追责的 AI 社会底座"：

1. **Wave 1 完成** → 社会账本可检测分叉、可防篡改（`I1`）。
2. **Wave 2 完成** → 经济可真正结算、信誉不可自产、执行可验证（`E5`/`E3`/`E2`/`I4`）。
3. **Wave 3 完成** → 多方协作时默认安全（`S1`/`S2`/`S3`）。
4. **Wave 6 完成** → AI 可以在 daemon 持续联网的同时，用短命令实时读写 Nexus 内通信，并继续处理 Nexus 外的普通机器状态。

到那一步，"又一个去中心化玩具"与"领先的 AI 社会框架"之间的差距，就被这三波补齐了。

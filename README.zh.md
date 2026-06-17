# Aether / Nexus

**去中心化 AI 工作空间节点 —— Agent 的操作系统。**

Aether 是一个本地优先、点对点的框架，为每个 AI Agent 提供一台"自己的电脑"：可移植的工作空间，具备原生执行环境、持久化存储、自主权网络身份、社会关系与资源定价能力——无需任何中心服务器。

> **状态**：早期开发（v0.1.0）。核心原语（身份、工作空间、社会事件、P2P 网络、Agent 控制面）已可用。可验证社会事实的路线图见 [IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md)。

---

## 核心原则

| 原则 | 含义 |
|---|---|
| **本地优先** | Agent 在自己节点上始终可用，离线也能工作 |
| **最终一致** | 通过签名社会事件日志和 Merkle 快照收敛 |
| **自主权身份** | 节点身份由 Ed25519 密钥对派生，不存在中心注册 |
| **最大自由度** | Workspace 默认是自由原生电脑，框架不设沙箱或权限闸门 |
| **社会关系** | Agent 之间形成关系、信誉、集体和经济往来 |
| **可验证记忆** | 签名且哈希链式链接的社会事件证明作者身份；抵赖可检测 |
| **计量而不限额** | 计算和存储可度量、可定价，但默认不设限 |

### Aether 不是什么

- **不是区块链** —— 不做全局共识，不维护全局账本
- **不是云计算平台** —— 不对硬件资源做全局调度
- **不是 AI 框架** —— 不提供 LLM 推理或 prompt 工程，Agent 自带

---

## 架构

```
┌──────────────────────────────────────────┐
│              nexus-agent                  │  Agent SDK
├──────────────────────────────────────────┤
│              nexus-node                   │  CLI + 守护进程 + Agent 控制面
├──────────────────────────────────────────┤
│    nexus-economy     nexus-sync           │  经济层 + 同步协议
├──────────────────────────────────────────┤
│  nexus-workspace  nexus-network           │  工作空间管理 + P2P 网络
├──────────────────────────────────────────┤
│  nexus-runtime  nexus-storage             │  原生执行 + 内容寻址存储
├──────────────────────────────────────────┤
│  nexus-core  nexus-crypto                 │  核心类型 + 密码学原语
└──────────────────────────────────────────┘
```

### Crate 说明

| Crate | 职责 |
|---|---|
| `nexus-core` | 共享类型、trait 和错误类型 |
| `nexus-crypto` | Ed25519 签名、密钥派生、哈希、DID |
| `nexus-storage` | 内容寻址存储（IPLD/CID）、Merkle 结构 |
| `nexus-runtime` | 自由原生进程执行；无沙箱、无权限闸门 |
| `nexus-workspace` | 工作空间目录管理、Merkle 快照、本地状态 |
| `nexus-network` | 基于 libp2p 的 P2P 网络（QUIC、Kademlia、Gossipsub、mDNS、中继） |
| `nexus-sync` | 工作空间发现、克隆与同步协议 |
| `nexus-economy` | 经济事实：执行收据、结算证明、资源计量 |
| `nexus-node` | CLI 二进制：守护进程（`serve`）、Agent 控制面、社会视图 |
| `nexus-agent` | 用于在 Nexus 节点之上构建 AI Agent 的 SDK |

---

## 核心概念

### 节点（Node）
一个运行中的进程，拥有本地 Ed25519 身份和 libp2p 对等身份。每个节点拥有若干工作空间，并参与社会网络。

### 工作空间（Workspace）
Agent 的电脑：一个普通的文件系统目录，加上 Merkle 树快照、本地状态以及关于成员与执行的社会记忆。

### 社会事件（Social Event）
签名的、按作者哈希链式链接的事实。每个事件证明**谁**做了某个声明，并通过抵赖证明使分叉可检测。社会（Society）是所有已知社会事件经本地重放后的投影——包含 Agent、关系、集体、任务、结算、能力与信誉。

### 执行收据（Execution Receipt）
执行者签名的证据，将任务结果绑定到命令、输出 CID、可选的工作空间根哈希以及计量资源消耗。第三方重执行见证可以交叉验证收据。

### 能力凭证（Capability）
用于工作空间访问、邀请、委托和审计的签名持有者凭证。能力是**社会证据**，不是本地执行闸门。

### 权威锚（Authority Anchor）
一个见证层，可以将选定的社会事实从*声称*升级为*锚定*——例如通过集体法定人数达成。绝大多数事实保持主观；只有少数（所有权、结算终局、集体决议）需要锚定。

---

## 快速开始

### 环境要求

- Rust 1.80+（edition 2021）
- Linux、macOS 或 Windows（WSL2）

### 构建

```bash
git clone https://github.com/nexus-ai/nexus.git
cd nexus
cargo build --release
```

### 启动节点

```bash
# 启动守护进程
./target/release/nexus-node serve --base ~/.nexus

# 查看 Agent 状态
./target/release/nexus-node agent status --base ~/.nexus --json

# 查看社会视图（本地社会投影）
./target/release/nexus-node society --base ~/.nexus --json

# 在局域网内发现对等节点
./target/release/nexus-node discover --lan --json
```

### Agent 工作流

```bash
# 1. 脉搏检查（只读、无副作用）
nexus-node agent status --base ~/.nexus --json

# 2. 查看收件箱：告警、任务和已发现的工作空间
nexus-node agent inbox --base ~/.nexus --json

# 3. 发现工作空间（快速缓存视图）
nexus-node agent discover --base ~/.nexus --json

# 4. 规划并执行工作空间同步
nexus-node agent sync --base ~/.nexus --workspace <HEX> --name <名称> --apply --json

# 5. 发送社会意图
nexus-node agent send --base ~/.nexus --kind status --title "正在完善文档" --json

# 6. 执行命令并记录社会记忆
nexus-node agent exec --base ~/.nexus --workspace ./my-workspace --json -- python train.py
```

---

## 文档

- [DESIGN.md](docs/DESIGN.md) —— 完整架构设计文档
- [CONTEXT.md](CONTEXT.md) —— 领域术语、不变量与 Agent 操作循环
- [IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md) —— 可跟踪的改进路线图
- [架构决策记录（ADR）](docs/adr/) —— 关键设计决策

---

## 开发

```bash
# 运行所有测试
cargo test

# 运行指定 crate 的测试
cargo test -p nexus-core

# 检查代码格式
cargo fmt --check

# 代码检查
cargo clippy -- -D warnings
```

---

## 许可证

采用 [MIT](LICENSE-MIT) / [Apache-2.0](LICENSE-APACHE) 双许可证授权。

> **免责声明**: 本项目完全由 AI 生成。使用本项目产生的一切后果由使用者自行承担，项目作者不对任何直接或间接损失负责。

# monitor-agent

`monitor-agent` 是 monitor hub 的 Windows 主机 agent, 使用 WebSocket 上报本机指标并执行 hub 下发的 TCP 探测任务.

> 只维护 x86-64/amd64 版本的 monitor agent. 因为没有其他测试环境.

## 版本兼容性

尽量与官方agent版本号对应.

| 官方 agent | agent-win (当前项目) |
|:---:|:---:|
| [v1.2.3](https://github.com/monitor-probe/agent/releases/tag/v1.2.3) | [v1.2.3](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.2.3) |
| [v1.2.2](https://github.com/monitor-probe/agent/releases/tag/v1.2.2) | [v1.2.2](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.2.2) |
| [v1.2.1](https://github.com/monitor-probe/agent/releases/tag/v1.2.1) | [v1.2.1](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.2.1) |
| [v1.2.0](https://github.com/monitor-probe/agent/releases/tag/v1.2.0) | [v1.2.0](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.2.0) |
| [v1.1.0](https://github.com/monitor-probe/agent/releases/tag/v1.1.0) | [v1.1.0](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.1.0) |
| [v1.0.0](https://github.com/monitor-probe/agent/releases/tag/v1.0.0) | [v1.0.0](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.0.0) , [v1.0.1](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.0.1) |


## 架构

- `src/main.rs`: 参数解析, 配置文件, Windows Service 生命周期, WebSocket 会话, 重连退避和 TCP 探测任务.
- `src/collect.rs`: 使用 Win32 system information, IP Helper, registry 和文件系统 API 采集指标.
- `.github/workflows/ci.yml`: Windows GNU target 的格式检查, 类型检查和 Clippy.
- `.github/workflows/release.yml`: Windows 静态 release 产物.

不调用 PowerShell, 不依赖本地化命令输出.

## 安装和运行

所有服务管理命令都需要以管理员身份运行 PowerShell:

```powershell
.\monitor-agent.exe install --server https://example.com --token <token>
```

`install` 会执行以下操作:

- 将当前 exe 复制到 `%ProgramData%\monitor-agent\monitor-agent.exe`, Windows Service 始终使用这个副本.
- 更新共享 exe 时会暂时停止已配置的 agent 实例, 完成后恢复.
- 默认配置写入 `%ProgramData%\monitor-agent\agent.env`, 其他服务名写入 `%ProgramData%\monitor-agent\<service-name>.env`.
- 使用 `icacls` 移除继承权限, 只允许 `SYSTEM` 和本机 Administrators 读取配置.
- 注册名为 `monitor-agent` 的 Windows Service.
- 配置 delayed auto-start.
- 配置服务失败后 5 / 30 / 60 秒自动重启.
- 启动服务.

## 更新

下载新版 exe 文件, 以管理员身份运行 PowerShell:

```powershell
.\monitor-agent.exe install
```

覆盖更新:
```powershell
.\monitor-agent.exe install --server https://example.com --token <token>
```

## 服务管理

```powershell
.\monitor-agent.exe status
.\monitor-agent.exe start
.\monitor-agent.exe stop
.\monitor-agent.exe uninstall

# Manage another independent agent instance.
.\monitor-agent.exe install --service-name monitor-agent-backup --server https://example.com --token <token>
.\monitor-agent.exe status --service-name monitor-agent-backup
.\monitor-agent.exe start --service-name monitor-agent-backup
.\monitor-agent.exe stop --service-name monitor-agent-backup
.\monitor-agent.exe uninstall --service-name monitor-agent-backup
```

`uninstall` 只删除指定服务, 保留对应配置文件, 便于重新安装. 如需删除 token, 请在确认后手动删除 `%ProgramData%\monitor-agent`.

## 前台运行

也可以以前台进程运行, 便于调试:

```powershell
.\monitor-agent.exe --server https://example.com --token <token>
```

## 环境变量/参数

支持环境变量 `MONITOR_SERVICE_NAME`, `MONITOR_SERVER`, `MONITOR_TOKEN`, `MONITOR_INTERVAL`, `MONITOR_IFACE` 和 `MONITOR_INSECURE`. 配置文件优先于环境变量, 命令行参数优先于配置文件. `MONITOR_NICS` 与 `--nics` 保留为旧配置兼容入口. 重复执行 `install` 且服务名相同会更新该服务和配置; 使用不同服务名即可共存多个 agent.

| 参数 | 默认 | 说明 |
|---|---:|---|
| `--server` | 必填 | hub 地址, 也可用配置文件或 `MONITOR_SERVER` |
| `--token` | 必填 | 节点 token, 也可用配置文件或 `MONITOR_TOKEN` |
| `--service-name` | `monitor-agent` | Windows Service 名称 |
| `--config` | `%ProgramData%\monitor-agent\agent.env` | 配置文件路径, 默认按服务名区分 |
| `--interval` | 1 | 上报间隔, 1-3600 秒 |
| `--iface` | 空 | 网卡选择, adapter alias 逗号分隔; 正向列表只统计列出的网卡, `-名称` 从默认统计集合中排除, 排除优先 |
| `--nics` | 空 | 旧参数, 等价于只统计列出的 adapter alias |
| `--insecure` | 关闭 | 允许远端使用明文 `ws://`, token 会以明文传输 |

## 上报字段

- `Facts`: 主机名, Windows 版本, 架构, 虚拟化类型, CPU 型号和核数, 内存, page file, 磁盘总量, IPv4 / IPv6.
- `Metrics`: CPU, load, 内存, page file, 磁盘, 网卡收发速率和累计计数器, TCP / UDP 数量, 进程数, uptime.
- `boot_id`: hub 判断主机重启和网卡计数集合变化的依据.
- `iface`: 当前 `--iface` 选择, 空值代表默认过滤规则, hub 可据此展示当前设置.
- `net_rx_total` / `net_tx_total`: 所选网卡的系统累计字节计数器, hub 负责跨上报累加.

`Facts` 每 60 秒重采一次. 变化时在当前 WebSocket 会话发送新的 `hello`, 无需等到重连.

Windows 没有等价的内核 load-average 计数器, `load` 是按 1 / 5 / 15 分钟窗口平滑后的 CPU demand, 单位为逻辑 CPU 数. 磁盘统计 fixed logical drives, 不统计网络盘、光盘和可移动盘.

每个地址族上报最可公网路由的本机地址. WireGuard 隧道 (adapter alias 为 `wg*` 或含 `wireguard`) 上的公网 IPv6 会上报, 隧道自身的私网地址除外; Cloudflare WARP 的共享段 `2606:4700::/32` 在任何网卡上都不作为本机地址上报. 本机 IPv4 为私网地址时, agent 会在会话之外向 hub 的 `/api/agent/echo` 另开一条只握手的短连接, 让面板显示该节点另一地址族的出口 (需要 hub 1.4.1 及以上; 失败每 30 秒重试, 最多 3 次, 不影响正常上报).

## 网卡选择

默认过滤 loopback、容器、隧道和常见虚拟网卡. 
`--iface` 的正向列表替换默认过滤规则, `-alias` 从默认集合中排除网卡, 排除优先于列出. 
名称精确匹配 Windows adapter alias; 多个名称用逗号分隔, alias 含空格时请给整个参数加引号. 不存在的正向名称会在启动时提示, 并按 0 字节统计. 空 `--iface` 恢复默认规则.

可以通过在 Powershell中执行 `netsh.exe interface show interface` 列出网卡.

仅监听`以太网`:

```powershell
.\monitor-agent.exe install --server https://example.com --token <token> --iface "以太网"
```

不监听`以太网`:

```powershell
.\monitor-agent.exe install --server https://example.com --token <token> --iface "-以太网"
```

## 构建和验证

需要 Rust stable 和 `x86_64-w64-mingw32-gcc`:

```bash
cargo fmt --all --check
cargo check --locked --target x86_64-pc-windows-gnu
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --locked --target x86_64-pc-windows-gnu
```

release 产物为 `monitor-agent-x86_64-pc-windows-gnu.exe`.

## 许可

MIT

## 安全与资源边界

- hub 下发的 TCP 探测默认仅允许公网目标。私网、loopback、链路本地和平台敏感地址必须由本机管理员显式授权，hub 不能解除此限制。使用 `--probe-allow` 或配置项/环境变量 `MONITOR_PROBE_ALLOW`，逗号分隔 IP/CIDR，可用 `@端口` 限定端口。例如：

  ```powershell
  .\monitor-agent.exe install --probe-allow "10.0.0.0/8@443,fd00::/8@8443"
  ```

  未带 `@端口` 的规则允许该 CIDR 的所有非零端口，请尽量使用最小范围。解析后的每个地址均需通过检查，包括 IPv4-mapped IPv6；混合的允许/拒绝 DNS 结果不会被探测。
- 探测任务最多 64 个；实际探测连接另有并发和速率上限，同一目标五秒冷却，重建任务或重连不会刷新资源预算。DNS 使用固定数量的专用工作线程和有界队列，超时不会无限追加后台解析。
- 指标采集使用单个独立工作线程。慢盘或系统调用异常不会直接卡住 WebSocket 或 Stop；同一时间最多一个采集请求。磁盘容量最多每 60 秒刷新，重连后只发送当前会话有效基线之后的样本。
- 日志异步写入，队列和单条长度有上限；单文件 1 MiB，保留三份备份。队列满、限流、存储失败或退出时可能丢弃日志，不将日志可靠投递作为阻塞服务退出的条件。
- 安装根目录通过 Windows Known Folder 获取，不再信任进程的 `ProgramData` 环境变量。配置、日志和 exe 位于受保护目录，拒绝不可信所有者、危险权限、重解析点和文件硬链接；文件读写、替换和删除均基于逐组件验证后的目录句柄，祖先路径发生重定向时安全拒绝，不跟随到新目标；写入 token 前即设置精确权限。发现旧目录不安全时会拒绝安装，请管理员检查并迁移，不要用普通用户预建或共享可写目录。
- 服务名 `agent`（含大小写变体）及 Windows 保留设备名被拒绝，以防与默认 `agent.env`/`agent.log` 冲突。其他服务名继续使用各自的 `.env`/`.log`，共享程序升级进行串行化和错误恢复。显式 `--config` 同样必须在可信的本地目录中。
- 建议使用受保护配置文件传递 token，避免将真实 token 写入命令行或 PowerShell 历史。Agent 尽量清零自有秘密缓冲区并将认证 header 标记为敏感，但不能保证清除 TLS/系统内所有副本，也不能防止管理员读取进程内存；请同时保护 pagefile、WER 和进程转储。`uninstall` 仍保留配置，废弃节点时应手工删除配置并在 hub 撤销 token。

GitHub 检查包含 Windows 上实际运行的测试、GNU 目标的格式/类型/Clippy 检查及 RustSec 公告审计；发布必须先通过这些检查，产物名称与版本规则保持不变。检查还实际执行双服务实例的安装、共存、共享 exe 升级、停止、启动和卸载，以及 NTFS 重解析点攻击正向对照。安全审计原始发现与修复说明见 [SECURITY_AUDIT.md](SECURITY_AUDIT.md)。

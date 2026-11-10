# monitor-agent Windows 安全与资源风险审查

- 日期：2026-11-10
- 版本：1.2.3；审查基线：`eb0d281`
- 范围：`src/main.rs`、`src/collect.rs`、Cargo 配置及锁文件、CI/release 工作流、README；并核对锁定的 Tokio、Tungstenite、windows-service 和 if-addrs 相关实现。
- 本次不修改业务代码。以下位置均对应审查基线。
- P1：优先修复，可能造成提权、敏感配置泄露或显著资源滥用。P2：中风险，需要特定故障、输入或环境。P3：防御性改进。
- “源码确认”不等于在 Windows 上完成利用验证。安装 ACL、重解析点、SCM 行为尚需 Windows 集成测试；本次没有对真实目标进行扫描或攻击。

## 结论摘要

确认存在 **4 项 P1、7 项 P2**，另有敏感数据生命周期、性能和测试覆盖方面的改进点。没有发现由本项目代码直接造成的远程命令执行、明确的 use-after-free/double-free、关闭 TLS 校验、生产路径中由网络输入直接触发的 `unwrap/expect`。

最重要的结论：

1. 安装目录、共享 exe、固定中间文件未构成完整的权限和防篡改边界；在非特权用户可预建/控制目录的条件下，有 LocalSystem 代码执行和文件破坏风险。
2. 配置先写 token 再设置 ACL，且现有命令不会清除其他显式 ACE，无法保证“仅 SYSTEM 和 Administrators”。
3. 探测任务数有上限，但更换任务可反复触发立即执行，绕过五秒间隔；已用隔离测试复现。
4. DNS 等待超时不会终止已开始的系统解析；异步任务数上限不等于实际解析线程/工作队列上限。

## 详细发现

### F01 / P1：高权限安装路径和共享 exe 缺少可信目录边界

**位置**：`src/main.rs:178-186, 333-339, 358-392, 411-413`。

**证据与触发条件**：

- `%ProgramData%` 来自环境变量；`create_dir_all` 创建或复用目录，但不验证目录所有者、DACL、祖先目录或重解析点。
- 仅配置文件调用权限加固；安装目录、共享 exe、日志和 `monitor-agent.exe.new` 没有对应的显式保护。
- 固定 `.exe.new` 路径执行存在性检查、删除、复制、再次按路径复制，既非互斥事务，也没有防止重解析点/硬链接/并发替换的措施。
- 服务账户为 `None`，按 SCM 默认语义以 LocalSystem 运行。
- 如果普通用户事先建好了这个子目录并保有修改权限，管理员安装不会将目录转为可信：用户可以替换共享 exe，在下次启动时取得高权限。路径被重定向时，管理员的配置/日志/二进制写入也可能破坏其他文件。

**影响**：条件性本地提权、token 泄露、任意可写目标文件损坏、多实例被同一 exe 劫持。不是已在本机验证的默认 Windows ACL 利用。

**修复**：

- 使用 Known Folder API 获取 ProgramData，不把高权限服务的安装根目录交给环境变量。
- 通过安全描述符在创建目录时设置精确的受保护 DACL；现有目录必须验证/修正所有者及权限，并拒绝不可信目录或路径重定向。
- 使用受保护目录内随机且 `create_new` 的中间文件；通过句柄核对文件类型、重解析属性及必要的硬链接信息；不能只做字符串 canonicalize 后再按路径打开。
- 同时保护共享 exe、日志、配置和中间文件；共享目录默认不允许普通用户写入。
- 使用互斥锁串行化不同服务实例的安装/升级；停止实例后再执行原子替换。
- 可进一步评估使用 LocalService/专用低权限账户，减少采集和探测功能的宿主机权限。

**验收**：普通用户预建目录、目录 junction、文件链接、并发安装、环境变量重定向均不能导致受保护目录外写入或替换服务 exe。

### F02 / P1：配置写入先于 ACL 收紧，且没有清除已有显式授权

**位置**：`src/main.rs:261-278, 297-306`。

**证据**：`fs::write` 在 `harden_config` 之前执行。`/inheritancelevel:r` 只移除继承 ACE；`/grant:r` 只替换指定 SID 的显式允许权限，不会删除 Users、Everyone 或某个用户已有的显式授权。若权限命令失败，写入的明文 token 仍留在文件中。

**影响**：新文件在继承权限过宽的目录中出现泄露窗口；已有显式读/写授权会持续保留，可能泄露 token 或允许修改 hub 地址以窃取后续连接携带的 token。

**修复**：在受保护目录中用精确安全描述符创建新文件，写入前即限制访问；现有文件用 Win32 安全 API 设置 `PROTECTED_DACL_SECURITY_INFORMATION` 和只含两个授权主体的 DACL，再核验实际描述符。临时文件同样保护，成功后原子替换。加固失败时不得留下新写入的未保护秘密。保留现有 `GetSystemDirectoryW` 绝对定位 icacls 的防劫持设计。

**验收**：预先为配置显式授权 Users 读取/修改后执行安装，最终该 ACE 必须消失；模拟 ACL 设置失败，不能留下普通用户可读的新 token。

### F03 / P1：任务更新绕过探测间隔，且没有会话级消息速率限制

**位置**：`src/main.rs:998-1008, 1177-1206, 1288-1293`。

**证据**：任务 ID、目标或原始 interval 改变就中止旧任务并创建新 ticker；Tokio `interval` 第一 tick 立即就绪。64 个是当前任务循环数上限，并非连接次数/秒上限。原始 interval 即使不同但 clamp 后相同，也会导致重建。

**复现**：抽取原调度函数到隔离测试，以计数器代替真实探测，20 次更新不同 ID、配置 interval=3600；结果为 `probe starts=20, elapsed=0ns, running=1`。证明不需要等待五秒即可反复触发。

**影响**：恶意/被攻陷 hub 可以驱动连接洪泛、内网端口探测、DNS 工作提交洪泛、任务频繁分配及日志放大。WebSocket 单条 64 KiB 限制不限制每秒累计输入。

**修复**：

- 在真正解析/连接前执行跨任务、跨任务重建且最好跨会话的全局 token bucket；64 个循环之外另设实际连接 semaphore。
- 每目标冷却时间与任务生命周期解耦；更新任务不补发一次即时探测，先规范化 interval 再比较。
- 设置每秒控制消息数及累计字节预算；超限合并为最新配置或断开，相关日志限流。
- 即使短暂中止后尚未完成取消的任务存在，实际连接许可也不能超限。

**验收**：连续更新 ID、目标、interval 或重连均不突破设定的连接/秒、DNS/秒和并发连接预算。

### F04 / P1：解析超时不取消底层工作，可积累阻塞线程/排队任务并拖延退出

**位置**：`src/main.rs:573-576, 631-643, 1100-1104, 1131-1134, 1264-1277`。

**证据**：锁定的 Tokio 1.54.1 对非 IP 字符串通过 `spawn_blocking` 调用系统 `ToSocketAddrs`；0.9 秒 timeout 仅放弃等待，已运行的工作继续。阻塞线程默认上限为 512，提交队列没有对应的应用层容量限制。每五秒及 F03 的更新都会重新提交。`abort()` 旧探测也不终止已开始的解析。runtime 默认 drop 会等待已启动的阻塞工作结束。

**影响**：解析慢/卡住时，线程、栈、域名字符串及待处理工作积压，影响主会话解析、其他任务和服务停止；在提交速率持续超过完成速率时队列可增长。不能断言每个正常 DNS 故障都会耗尽 512 线程，其程度取决于系统解析耗时。

**修复**：

- 使用有超时、并发上限和有界队列的解析组件，或专用、有限数目的解析 worker；完成前保留 in-flight 许可，调用者 timeout 不能提前释放代表真实后台工作的许可。
- 不能仅在 `lookup_host` 外包一个 timeout 或 semaphore 后在超时立即释放；也不能仅降低 `max_blocking_threads` 而保留无界提交。
- 同一目标禁止重复未完成解析；正/负缓存需容量和 TTL，不能引入新的无界缓存。
- 使用明确 runtime 关闭期限；`shutdown_timeout` 只能限制等候，不是真正取消底层系统解析。

**验证**：已核对锁定依赖源码，并用隔离测试验证已启动的 `spawn_blocking` 在 timeout 返回后仍继续并完成。未人为造成真实 Windows DNS 卡死。

### F05 / P2：hub 可要求访问任意 TCP 目的地，没有宿主机侧出站策略

**位置**：`src/main.rs:727-731, 1264-1293`。

**证据**：target 直接传递系统解析，解析后的地址未限制 loopback、RFC1918、ULA、链路本地、云 metadata 地址及端口。

**影响和边界**：这是探测 agent 的预期能力，但被攻陷 hub 可以将 agent 用作内网 TCP 连通性探测器，收到端口是否可达及延迟。它只建立 TCP 连接，没有发送 HTTP 请求体；不能据此声称能直接读取 metadata 凭据或返回任意内网内容。仍可能触发连接即产生副作用的服务和网络告警。

**修复**：添加本地管理员控制的目标 CIDR/域名和端口 allowlist；默认至少拒绝敏感链路本地和 metadata 地址，合法私网探测显式授权。每次 DNS 结果在 connect 前执行策略，处理 IPv4-mapped IPv6，禁止仅按字符串域名判断以免 DNS rebinding 绕过。策略不能由 hub 远程解除。

### F06 / P2：日志无限追加且同步落盘，hub 输入可放大日志

**位置**：`src/main.rs:333-341, 821-822, 1177-1180, 1207-1214`。

**证据**：每条日志重新创建目录、打开文件、追加并输出 stderr，没有大小/保留份数/总量上限。hub 每发一次超长任务列表就记录一条；任务重建还会重置 DNS 慢速日志标志。target 未限制控制字符，特定解析超时路径会将其原样写入日志。

**影响**：长期故障或恶意更新填满系统盘，阻塞单线程运行时；控制字符可伪造/污染文本日志。没有每条 fsync，不应将其误报为强制同步磁盘刷写。

**修复**：设置文件大小、备份数量和总字节硬上限；日志限流/采样，转义控制字符并限制字段长度；使用有界日志队列交给专用 writer，队列满时丢弃低优先级记录并统计。文件轮转和 writer 也要纳入 F01 的权限保护。BufWriter 只能减少写调用，不能替代轮转和容量上限。

### F07 / P2：升级不是事务，错误路径可能让多个服务永久停止或留下半写入 exe

**位置**：`src/main.rs:375-392, 448-468, 486-533`。

**证据**：先覆盖配置，再准备程序并停止多个服务；任意 `?` 都会跳过末尾 `restart_services`。`stop_running_services` 在停止部分服务后失败也不会返回已停列表供恢复；`restart_services` 本身遇到一个错误就不再尝试后续服务。共享 exe 使用 `fs::copy` 覆盖而非完整文件的原子替换，失败可能留下截断/部分文件。`.exe.new` 在失败路径无清理 guard。

**影响**：单次磁盘不足、权限错误、SCM 错误或进程中断导致所有实例失联；失败后有残留 staging 文件。自定义目录配置不在默认根目录扫描中，还可能漏停持有共享 exe 的实例。

**修复**：安装互斥；先验证并暂存配置和 exe；通过 SCM 枚举/可信登记确定使用共享路径的实例；记录原配置和状态；原子切换，失败回滚。用显式 finally/guard 尽力恢复所有原运行实例，汇总错误而不是提前返回。故障注入覆盖每一个步骤。

### F08 / P2：合法服务名 `agent` 与默认实例共享配置和日志路径

**位置**：`src/main.rs:178-195, 323-330`。

**证据**：默认 `monitor-agent` 使用 `agent.env` 和 `agent.log`；合法的其他服务名 `agent` 同样派生为 `agent.env` 和 `agent.log`。Windows 大小写不敏感，`AGENT` 等变体同样冲突。

**影响**：安装第二个合法命名的实例覆盖第一个实例的 token、server 和网卡设置；第一个实例下次启动可能连接到错误 hub。配置内 `MONITOR_SERVICE_NAME` 被覆盖还可能影响升级时实例发现。这不需要路径遍历。

**修复**：为非默认实例采用不会冲突的独立目录；或至少保留/拒绝 `agent` 的大小写不敏感别名，并检查配置和日志最终路径唯一性。Windows 保留设备名也应拒绝，避免 AUX、CON、COM1 等产生意外 I/O 行为。服务名与已有非本产品服务冲突时，不应未经身份核对直接改写对方配置。

**验收**：默认名、`agent`、大小写变体以及常见保留名称的路径唯一性/拒绝测试；两个实例升级重启互不影响。

### F09 / P2：单线程异步主循环直接执行可能阻塞的系统采集与日志 I/O

**位置**：`src/main.rs:631-632, 901, 947, 958, 965`；`src/collect.rs:220-245, 543-560, 590-615`。

**证据**：当前线程 runtime 内同步调用盘符容量、注册表、网卡枚举及日志写入。磁盘采集每秒最多查询 26 个 fixed 盘符；不是递归全盘扫描，但损坏/慢盘、驱动或杀毒拦截可令调用长时间阻塞。

**影响**：即使 TCP/TLS 都有 timeout，阻塞在同一线程时 timer 和 Stop 通知也无法及时处理，造成上报失联和退出超时。

**修复**：使用专用且有界的采集 worker，最多一个 in-flight 采样，主循环读取最近结果；慢磁盘容量降低刷新频率。超时后不要每秒再创建一个 `spawn_blocking` 工作，避免复制 F04。日志独立 writer。记录样本年龄，故障按业务约定返回空/0，不让可选采集故障退出主循环。

### F10 / P2：配置整体读取和注册表长度分配缺乏应用层上限

**位置**：`src/main.rs:231-242, 422-445`；`src/collect.rs:590-615`。

**证据**：`read_to_string` 整体读取配置，将所有未知键值复制入 HashMap；扫描目录时每个 `.env` 都这样读取。注册表 `bytes` 不设最大值即分配 Vec，且 CPU 名字符串在 `update_load` 中每次采样都会重新读取。

**影响和条件**：大配置可在启动/升级消耗大量内存；恶意或异常注册表字符串可造成大分配，OOM 在 release 下终止进程。这通常需要本地配置写权限、显式指定异常文件，或较高权限修改 HKLM；不是未鉴权远程直接读文件漏洞。

**修复**：配置通过有界 reader 最多读例如 64 KiB + 1，超限拒绝，限制行/键/值数及长度、只接受已知字段；不能仅 metadata 检查后无界读取。限制安装扫描数量，并拒绝非普通文件/重解析路径。注册表字符串设合理上限，例如 16 KiB；二次调用成功后重新验证类型、偶数长度和 `bytes <= data.len()`，异常返回 None。缓存稳定的 CPU 型号和核数。

### F11 / P2：echo 任务脱离会话生命周期，可重叠并在断线后继续携带 token 访问

**位置**：`src/main.rs:919-922, 969-970, 1081-1096`。

**证据**：`tokio::spawn(glimpse(...))` 的 JoinHandle 被丢弃；会话结束时只 abort ping tasks。每个 echo 最长约 3×15 + 2×30 = 105 秒；会话重连或地址变化可在前一任务结束前启动新任务。

**影响和边界**：不是单个任务永久泄漏，也不应说完全无界——每个任务有重试/时间上限，重连有退避。但没有显式全局数量上限和会话取消，旧任务可累积重叠、持有 token 副本并消耗 DNS/TLS 资源。

**修复**：使用会话拥有的 JoinSet/取消令牌，或全 agent 按地址族唯一的受控任务；网络地址变化时先取消并等待旧任务，再创建替代；统一连接/解析预算。测试断线/Stop 后不再发旧 echo。

## 其他改进与数据正确性问题

### A01 / P3：秘密生命周期没有特殊保护

`Args.token` 是 String；配置 HashMap、序列化内容、Bearer header 和 echo 的 token clone 会产生副本；未 zeroize，可能残留在堆、pagefile、进程转储中。CLI `--token` 也可能出现在 PowerShell 历史和允许读取进程命令行的工具中。没有发现目前日志主动打印正常 token，`Args` 也没有 Debug derive；不要误报为已确认日志 token 泄露。

建议：优先使用受保护配置/安全交互输入，文档明确 CLI 历史风险；secret wrapper/Zeroizing 尽量缩短明文寿命、避免多余 clone，Authorization HeaderValue 标为 sensitive，保证以后 Debug/诊断不泄露；精确保护 WER/转储存储。zeroize 不能保证清除所有隐式副本，也不能防止具有足够权限的实时内存读取。保留 JSON 既有字段，不向 Facts/Metrics 加入认证信息。

### A02 / P2（数据正确性）：重连后的 load 仍带入断线期间 CPU 平均值

`src/main.rs:947` 的基线通过 `collect()` 取得，但 `Collector.prev_cpu/load/load_at` 未重置；`src/collect.rs:282-299` 会先将上次连接以来的 CPU 平均值用于 load 平滑，再在一秒后上报。CPU/网速的下一份差分已经由基线刷新，但 load 的历史污染仍存在，与“不得上报断线期间平均值”的业务约束不一致。首次初始化 load 也基于 CPU 尚无差分时的 0。

建议：提供专门的 `begin_session_baseline`，重置或隔离会话差分状态；load 必须只用有效的一秒差分初始化/更新，不能拿断线区间均值更新。用可控时钟测试断线十分钟后首份上报。

### A03 / P3：现有 tests 未在 CI 中真正执行；供应链持续检查不足

CI 做 fmt/check/clippy，没有运行 Windows tests。Linux 上交叉 Clippy 的 `--all-targets` 只编译测试，不能替代运行。release 使用 mutable action 引用和 stable 工具链，未见 RustSec 扫描、签名/构建来源证明。锁文件和 release job 最小权限是已有优点。

建议：添加 Windows runner 运行测试和 SCM/ACL 集成测试；引入 cargo-audit 或 cargo-deny（带更新的公告库）、定期依赖更新；固定审核过的 actions commit，发布校验和及构建来源证明，按分发需求评估 Authenticode。此次未完成 RustSec 在线公告比对，不宣称依赖无 CVE。

## unsafe 逐项审查

以下覆盖本项目全部显式 unsafe 位置。结论依赖 Windows API 按约定返回可信长度和结构，不将“没有证明漏洞”写成无条件内存安全保证。

| 位置 | 调用与边界 | 审查结果 / 建议 |
|---|---|---|
| main.rs:284 | GetSystemDirectoryW，Vec<u16>、容量参数 | 缓冲区存活、成功长度判断合理；API 要求更大容量时扩容。建议为异常长度设置小而明确的上限，并添加 SAFETY 注释。 |
| collect.rs:341 | GetComputerNameExW，固定 256 u16 | 正常 API 成功长度受容量约束；失败回退。可用 `buffer.get(..size as usize)` 防御式校验。 |
| collect.rs:352 | RtlGetVersion | 正确初始化结构大小并检查状态；未见越界或生命周期错误。 |
| collect.rs:362 | GlobalMemoryStatusEx | 正确设置 dwLength，失败返回 0；饱和减法规避下溢。 |
| collect.rs:378 | GetSystemTimes | 三个 FILETIME 均为有效栈对象，失败返回 None。 |
| collect.rs:401, 458 | GetTickCount64 | 无指针；单位转换/饱和乘法合理。 |
| collect.rs:417-425 | NtQuerySystemInformation / 自定义 repr(C) boot 环境结构 | x86-64 布局与预期字段一致、缓冲区大小固定；依赖较底层系统信息类，建议校验返回长度并做多 Windows 版本测试。 |
| collect.rs:430-444 | NtQuerySystemInformation / SYSTEM_TIMEOFDAY_INFORMATION | 固定结构，成功后从 Reserved1 固定偏移解释字段；未见越界，主要风险是版本语义变化而非已确认 UB。建议用明确 repr(C) 结构/布局断言和返回长度验证。 |
| collect.rs:456 | GetSystemTimeAsFileTime | FILETIME 可写且存活；未见内存问题。估算仅作为最后回退，不是常规 boot_id 来源。 |
| collect.rs:514, 519-520 | GetIfTable2、from_raw_parts、FreeMibTable | 成功且非空后读取，用系统 NumEntries 建切片，复制完成后只释放一次；未见返回悬垂指针、UAF/double-free。建议 RAII guard 封装 FreeMibTable，限制异常条数并验证长度计算/布局。 |
| collect.rs:544, 552, 556 | GetLogicalDrives/GetDriveTypeW/GetDiskFreeSpaceExW | 路径 NUL 终止、输出地址有效，26 次循环有界。主要风险是同步阻塞，见 F09。 |
| collect.rs:569, 573 | TCP/UDP statistics | 输出结构类型/大小正确，失败不累加。 |
| collect.rs:583 | GetPerformanceInfo | 设置 cb、有效指针和正确结构大小，失败回退 0。 |
| collect.rs:594, 601, 603, 608-609 | RegOpen/Query/Close | 正常与提前返回路径均关闭已打开 key；不存在已确认句柄泄漏。两阶段查询有大小变动可能，API 成功语义保证正常写入；建议 F10 的容量、类型及实际长度复核和 RAII 关闭。 |

没有发现 `Box::leak`、`mem::forget`、Rc/Arc 循环或项目自己调用 malloc/free。CPUID 调用在当前工具链上不需要 unsafe；固定 12 字节签名拼装无外部长度输入。不能用 catch_unwind 修补 release panic，因为 release 配置是 `panic = "abort"`。

### 相关依赖的额外风险

锁定的 `if-addrs 0.15.0` Windows 实现使用 HeapAlloc/HeapFree；正常路径与错误路径有释放，成功对象 Drop 释放。它在分配失败时 panic，且 `GetAdaptersAddresses` 返回缓冲区不足时循环扩容、没有重试次数/容量上限；本项目的 `unwrap_or_default()` 只处理 Err，不处理 panic/OOM。网卡快速变动或资源压力下属于健壮性风险，而不是已确认的常规远程利用。建议替换/修补为有界重试、有容量上限的枚举实现，分配/采集失败返回错误，不终止主循环。

## 已存在且有效的防护 / 未发现问题

- 主会话 WebSocket message/frame 均限制 64 KiB；result channel 为 64，当前探测任务为 64，单次探测至多 3 个地址；这些防护有效，但不能替代全局速率和 DNS 后台工作上限。
- Tokio ticker 使用 Delay 而非 Burst，报告间隔 1-3600 秒，探测间隔 5-3600 秒；重连退避 1-60 秒。未见普通故障时的纯 busy loop。可加 jitter 防止大规模 agent 同时重连。
- 主连接建立有 120 秒总期限、候选地址回退通常 5 秒、主会话静默/写入共享 90 秒预算；echo 有 15 秒单次、3 次上限；成功/失败 socket 通过所有权 drop 关闭。同步阻塞和系统 DNS 的例外已单列。
- 锁定 Tungstenite 0.30.0 的 HTTP upgrade parser 自带约 64 KiB 字节上限、124 个 header 槽及读轮数/慢小包检查。不能将 WebSocketConfig 不控制 HTTP header 误报为当前依赖的“完全无界握手内存”。
- serde_json 当前保留默认递归深度限制，且网络输入先受 64 KiB 限制；未见关闭深度保护。解析时的 Value 和 Vec 会产生有界多份分配，任务截断在反序列化之后，但不能据此声称单条消息导致无限内存。
- TLS 使用 rustls + webpki roots，未见关闭证书/域名验证。Authorization 由 HTTP header 值解析，CR/LF 不会被当作任意 header 注入。token 不拼接 URL。
- 显式远程明文 ws 默认拒绝；仅 `--insecure` 或 loopback 例外。localhost 例外还依赖名称解析保持本机，建议在实际 connect 前核验其解析结果是 loopback；该项不是已复现远程绕过。
- 使用手动 `TcpStream` + `client_async_tls_with_config`；未见自动 HTTP 重定向或读取 HTTP_PROXY 的路径，不能声称 Authorization 会自动跟随重定向泄露。
- 生产代码没有监听 socket/HTTP 服务，不存在生产监听 0.0.0.0 问题；测试中的 listener 只绑定 loopback。
- 唯一外部命令为绝对路径 icacls，参数由 Command 分开传入，没有 shell 拼接；windows-service 依赖会转义 exe 路径及参数，未发现 unquoted service path 问题。
- 服务名字符集不允许斜杠/反斜杠，无直接 `../` 路径遍历；但合法名仍有 F08 的路径冲突。显式 `--config` 本来允许管理员指定任意路径，其安全问题是高权限按不可信链接写入，而非简单“未 canonicalize 就一定遍历”。
- `prev_net` 每轮整体替换，不永久保留已删除网卡；未发现增长不退的网络指标缓存。采集 Vec 由系统网卡数限制，非远端请求直接控制。
- 网络计数器使用饱和加减；延迟转换先 min，interval 先 clamp；未见不可信数值直接造成 release 溢出/切片 panic。`reconnect_wait(previous * 2)` 的 previous 在当前调用链最多 60，并非实际外部可控 u64 溢出。
- 生产代码无 unwrap/expect；此类调用主要位于 tests。没有正则表达式/灾难性回溯、全文件树递归扫描、每条 flush/fsync 或网络错误返回内网路径的服务端响应。
- 采集数据包含主机名、内网地址、硬件及 OS 信息，是明确的遥测业务输出，应按敏感资产信息保护 hub 的授权、保留和备份；当前序列化结构未包含认证 token。

## 建议实施顺序和回归标准

1. **先封住权限边界**：F01/F02；Windows 标准用户和管理员双身份测试目录预创建、显式 ACE、junction/hardlink、权限失败和文件替换。
2. **再封住远程资源预算**：F03/F04/F05/F06；模拟恶意 hub 快速更新、重复 ID、极长/控制字符 target、DNS 慢解析、黑洞地址和慢读；对解析 in-flight、队列、线程、连接/秒、日志总量设置断言。
3. **确保安装和服务可靠**：F07/F08/F09/F11；磁盘满、SCM 错误、复制中断、多实例并发安装、Stop/Shutdown 故障注入；恢复所有原运行实例。
4. **消除剩余内存和指标隐患**：F10、A01/A02；大配置/异常注册表测试，断线后的第一份样本业务断言。
5. **建立持续验证**：Windows runner 运行测试、依赖公告检查和安全发布策略。

## 本次验证记录与限制

- `cargo fmt --all --check`：通过。
- `cargo check --locked --target x86_64-pc-windows-gnu`：尝试；补齐 Rust Windows target 后，仍在 ring 构建阶段因缺少 `x86_64-w64-mingw32-gcc` 失败；不能声称 Windows 类型检查通过。
- Clippy/release build：未完成，同样缺少交叉 C 工具链；未运行 Windows Service/ACL 测试。
- 隔离 Rust 测试：任务 ID 更新触发即时探测、timeout 后 blocking 工作继续，两项通过。调度测试抽取原函数并替换真实 TCP，未进行真实连接洪泛。
- 临时复现工程位于 `/tmp/monitor-agent-audit.NEQLMU`，不属于仓库修改。
- 未完成在线 RustSec 全量审计；没有将“未查询到”当成“无漏洞”。

## 修复进度（2026-11-10）

本报告前文保留原始基线发现，不能用于判断当前代码仍存在相同问题。修复位于 `codex/security-hardening` 分支，未修改版本号和发布产物名称。

| 原发现 | 当前措施 |
|---|---|
| F01/F02 | Known Folder 安装路径；严格目录所有者、祖先权限、重解析点与硬链接检查；逐组件、目录句柄相对的打开/替换/删除，避免祖先在检查后被重定向；创建时精确受保护 DACL；随机独占 stage；配置在信任前拒绝非受信主体可修改的显式 ACE。 |
| F03/F04 | 进程级滑动窗口限流、真实 socket 许可、目标冷却、延迟首次探测；有界控制消息；固定两个 DNS worker 和 16 项队列，超时不解除真实 in-flight。 |
| F05 | 默认公网探测策略；本地 `--probe-allow` / `MONITOR_PROBE_ALLOW` CIDR/IP 可选 `@port` 追加授权；DNS 后校验和 mapped IPv6 处理。 |
| F06 | 非阻塞有界日志队列、限长和控制字符转义、限流、1 MiB × 4 文件容量边界、安全文件打开与独占 writer。 |
| F07 | 安装互斥；原子替换；完整 SCM 属性快照；持久化受保护恢复记录和旧配置，普通错误立即恢复，进程中断后下一次 install 重放；有界过期 stage 清理。 |
| F08 | 拒绝 `agent` 大小写变体、Windows 设备名及保留路径冲突，核验已有服务身份。 |
| F09/F10 | 单采集 worker、一个真实 in-flight、超时缓存回退；磁盘60秒缓存、CPU信息缓存；配置和注册表限长；有界原生地址枚举取代 if-addrs。 |
| F11 | echo 任务归属会话；变化时取消并等待替代；退出自动取消。 |
| A01/A02/A03 | 自有秘密缓冲 zeroize、敏感认证 header；当前会话有效基线和首份差分门槛；Windows实际测试、管理员安全回归、GNU严格检查和静态构建、RustSec及发布门槛。 |

### 故障边界

- 系统 DNS、磁盘驱动及其他 OS 调用不能由 Rust 强制终止；固定 worker 数量确保不无限增长，worker 卡死可能使对应功能停止采样/解析。
- 日志为尽力投递，过载或退出允许丢弃。秘密清零不能清除所有系统/TLS副本，也不能防御管理员内存读取。
- 安装中断恢复在下一次管理员执行 `install` 时进行；不宣称断电后无需人工动作即自动完成多文件/SCM事务。恢复失败保留记录并明确报错，不启动配置可能不匹配的目标实例。
- 原生 NTFS 回归发现，metadata-only 句柄和目录共享限制不能阻止 `WRITE_ATTRIBUTES` 句柄设置重解析点；不得将句柄持有误当成“路径冻结”。当前改用逐组件 RootDirectory 相对打开以及按句柄重命名/删除，并保留攻击正向对照测试。
- 路径保护以 SYSTEM、Administrators 和必要的系统祖先 TrustedInstaller 为信任边界，不试图防御同等高权限恶意操作。
- 本地不安装交叉编译器；实际编译和 Windows 回归由 GitHub 执行。首轮 `ff54635` 已通过 GNU 类型检查、Windows tests、管理员文件系统回归及 RustSec；Clippy strict 发现的问题正在后续检查中收敛。最终通过状态以分支最新提交对应的 GitHub 结果为准。

# vuln-template-scanner-go

声明式模板驱动的漏洞扫描引擎。规则以 YAML 模板描述，引擎负责模板加载、
变量派生、并发执行、命中判定、断点续扫与结构化导出。扫描目标为本地回环
HTTP 服务即可，不依赖外部网络与真实凭据。

## 构建与运行

```bash
go build ./cmd/scan
./scan -templates templates/examples \
       -targets http://127.0.0.1:8080,http://127.0.0.1:8081 \
       -severity medium,high -tags exposure \
       -checkpoint scan.cp.json -o report.json
```

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-templates` | `templates` | 模板目录（递归加载 `*.yaml`/`*.yml`） |
| `-targets` / `-targets-file` | | 目标列表，逗号分隔或每行一个 |
| `-concurrency` | 16 | 全局工作协程数 |
| `-per-target-concurrency` | 4 | 单目标并发请求上限 |
| `-rate` | 0（不限） | 单目标每秒请求数上限 |
| `-timeout` | 10 | 单请求超时秒数 |
| `-max-variants` | 256 | 单模板派生请求数上限 |
| `-checkpoint` / `-resume` | | 检查点文件与断点恢复 |
| `-seed` | 1 | 固定随机种子，保证可复现 |
| `-severity` / `-tags` | | 结果过滤（标签大小写不敏感） |
| `-o` | 标准输出 | 结构化 JSON 报告输出文件 |

运行中按 `Ctrl-C`（SIGINT/SIGTERM）即中断：正在执行的请求被及时取消，
已提交的进度写入检查点，报告状态为 `interrupted`，可用 `-resume` 继续。

## 模板结构

```yaml
id: exposed-admin-panel        # 必填，全局唯一标识
version: 2                     # 模板格式版本，缺省为 1
info:
  name: Exposed Admin Panel
  severity: medium             # info|low|medium|high|critical，缺省 info
  tags: [exposure, panel]
variables:                     # v2：变量取值列表，派生请求变体
  base: [admin, manage]
requests:
  - method: GET                # 缺省 GET
    path: /{{base}}/           # {{变量名}} 占位符
    headers: {X-Probe: scanner}
    body: ""
match:
  combinator: all              # any|all，缺省 any
  conditions:
    - id: ok                   # 缺省自动编号 c0,c1,...
      type: status             # status|header|body
      status: [200]
    - id: title
      type: body
      contains: ["Admin"]      # 子串，任一命中
      regex: ["Dash+board"]    # 正则，任一命中；与 contains 之间亦为“或”
    - id: no-redirect
      type: header             # v2 起支持
      header: Location
      contains: ["login"]
      negate: true             # 取反
```

### 版本兼容

- `version: 1`（或缺省）：支持 `status`/`body` 条件；`combinator` 缺省 `any`，
  不支持 `header` 条件（使用会给出可读错误）。缺少新版字段的旧模板照常加载执行。
- `version: 2`：支持变量、变体、`header` 条件、`negate` 与 `combinator`。
- 未知字段一律忽略，不会导致加载失败；不支持的版本号报可读错误。
- 目录批量加载时，单个模板失败会记录 `文件路径 + 原因`，不影响其余模板。

### 变量与变体

- 变体 = 请求定义 × 变量取值的笛卡尔积。派生顺序稳定：请求定义顺序为主序，
  变量按名字字典序排列、末位变量变化最快，取值按声明顺序。
- 派生总数超过 `-max-variants`（默认 256）或变量取值列表为空时，该模板被
  隔离为模板级错误（`kind: template`），其余模板不受影响。
- 未定义的 `{{占位符}}` 保留原文，行为可预期。

## 扫描语义

### 命中判定

- 支持响应状态码、响应头（名称大小写不敏感）、响应正文的子串/正则匹配，
  条件间支持 `any`/`all` 组合与 `negate` 取反。
- 每条命中携带 `matched_conditions`（命中的条件 ID）与 `evidence`
  （命中位置附近的证据片段），判定可解释。
- 响应正文按 `io.LimitReader` 限长读取（默认 1MiB），绝不整段载入内存；
  按 `Content-Type` 字符集（UTF-8/GBK/GB2312/GB18030/Big5/Latin-1/UTF-16）
  解码后再匹配。
- 请求失败（超时、连接中断、上游异常）只记录错误，绝不判定为命中。

### 并发与限速

- 全局工作协程池 + 单目标并发信号量 + 单目标请求间隔限速。
- 取消/超时通过 context 传导，进行中的请求被及时中断；所有协程在
  `Run` 返回前退出，响应体与空闲连接均关闭，无残留。
- 每个 `(目标, 模板)` 对独立执行，目标之间进度互不阻塞。

### 确定性

- 同一模板集合、同一目标响应、固定种子下，多次扫描的命中集合与输出
  顺序完全一致：命中按 `(模板, 目标, 变体)` 去重（重复命中合并条件 ID），
  再按 `严重级别降序 → 模板 → 目标 → 变体键` 排序，与并发调度顺序无关。

### 中断与恢复

- 每个 `(目标, 模板)` 对完成后原子提交检查点（临时文件 + rename），
  内容含状态（`running`/`completed`）、已完成对、已产出命中与错误。
- `-resume` 时跳过已完成对，加载既有命中继续扫描；中断中部分执行的对
  会重跑，最终去重保证命中不重复、不丢失，结果与一次完整扫描一致。
- 已完成与未完成的扫描通过检查点 `state` 字段区分；恢复已完成的扫描
  不会重复发出请求。

### 错误隔离与结果

- 单个模板或单个目标的错误、超时与运行期崩溃（panic 自动恢复）不会
  中止整体扫描。错误归因到具体模板与目标，`kind` 区分
  `timeout`/`connection`/`panic`/`template`/`cancelled`。
- 报告为结构化 JSON：`state`（`completed`/`interrupted`）、`findings`
  （模板标识、目标、严重级别、标签、变体键、命中条件、证据）与 `errors`。

## 测试

```bash
go test ./...          # 单元与端到端测试（本地回环 httptest）
go test ./... -race    # 竞态检测
```

覆盖：模板版本兼容与未知字段、单模板失败隔离、匹配组合与取反、字符集
解码、大响应截断、变体派生顺序与上限、单目标并发与限速、取消与超时、
断点恢复一致性、崩溃/连接异常隔离、结果确定性。

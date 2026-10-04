# 模板格式与扫描语义

本引擎使用声明式 YAML/JSON 模板描述 HTTP 请求与命中条件。模板文件放在同一目录下，
引擎递归加载所有 `.yaml` / `.yml` / `.json` 文件。单个模板加载失败不会影响其他模板。

## 模板结构

### v2（当前格式）

```yaml
schema_version: "2"
id: admin-panel-exposed            # 必填，模板唯一标识
info:
  name: Exposed Admin Panel        # 名称
  author: scanner-team             # 作者
  severity: high                   # 严重级别: info/low/medium/high/critical
  tags: [web, panel]               # 标签，用于过滤
  description: ...                 # 描述
variables:                         # 变量定义（列表或 map 均可）
  paths:
    values: [admin, manage]        # 显式取值
  ids:
    range: {min: 1, max: 10, step: 1}   # 整数区间
  token:
    random: {type: string, length: 8, count: 2}  # 确定性随机值
variants:                          # 请求变体；缺省时使用 request 作为 default 变体
  - id: panel
    request:
      method: GET
      path: /{{paths}}             # {{变量名}} 占位符会被替换
      headers:
        X-Token: "{{token}}"
      body: ""
matchers:                          # 命中条件，顶层多个条件为“或”关系
  - id: status-ok
    type: status
    status: [200]
  - id: markers
    type: word
    part: body                     # body/header/all
    words: ["admin", "login"]
    operator: or                   # and/or，默认 or
    case: insensitive              # sensitive/insensitive，默认 sensitive
  - id: not-404
    type: logic
    operator: not                  # and/or/not
    matchers:
      - id: s404
        type: status
        status: [404]
```

### v1（旧格式，兼容）

旧模板没有 `schema_version` 与 `info` 块，字段平铺在顶层。加载时自动归一化：

```yaml
id: env-file-exposure
name: Exposed Environment File
severity: critical
tags: [exposure]
request:
  method: GET
  path: /.env
matchers:
  - type: status
    values: [200]        # v1 用 values，加载时归一化为 status
  - type: word
    words: ["APP_KEY="]
```

旧模板缺少新字段（如 `variants`、`variables`）时按默认值处理：自动生成
`default` 变体，`severity` 默认为 `info`。未知字段直接忽略，不会导致加载失败。

## 匹配器类型

| type | 说明 | 关键字段 |
|------|------|----------|
| `status` | 响应状态码命中列表中的任意一个 | `status: [200, 201]` |
| `word` | 子串匹配，支持与/或、大小写忽略 | `words`, `part`, `operator`, `case` |
| `regex` | 正则匹配，语法为 Go 标准 RE2 | `regex`, `part`, `operator`, `case` |
| `header` | 响应头存在性或值匹配 | `header`, `words`, `exists` |
| `logic` | 组合子条件 | `operator: and/or/not`, `matchers` |

任意匹配器都可以加 `negate: true` 取反。

匹配结果会保留证据（evidence）：命中的匹配器 id、类型、说明与命中片段，
`logic` 类型保留子条件证据树。

## 扫描语义

- **请求派生**：每个变体与变量取值做笛卡尔积，按模板中变量声明顺序稳定展开，
  派生 id 形如 `v#0`、`v#1`。派生总数有上限（默认 256，`--max-variants`），
  超出上限或变量配置非法时，该模板以可定位的错误跳过，不影响其他模板。
- **并发与限速**：多个目标并发扫描；每个目标有独立的并发信号量（`--concurrency`）
  与速率限制器（`--rate`，单位 请求/秒）。目标之间互不阻塞。
- **超时与取消**：每个请求带独立超时（`--timeout`）；整体取消时正在执行的请求
  会被及时中断并关闭空闲连接，协程不残留。
- **错误隔离**：模板编译/派生错误、请求超时、连接中断、运行期 panic 都被捕获并
  归因到具体目标与模板，以 `phase`（compile/derive/request/execute）区分。
  上游连接中断不会被判定为命中。
- **确定性**：固定随机种子（`--seed`）下，派生结果确定；命中先按
  (目标, 模板, 变体, 证据) 排序，再按 (目标, 模板, 变体, 匹配器) 去重，
  输出顺序不随并发调度变化。
- **检查点续扫**：`--checkpoint` 指定检查点文件。每个任务完成后原子提交；
  中断后重启自动跳过已完成任务、合并已有命中，结果与一次完整扫描一致。
  检查点状态区分为 `running` 与 `completed`。

## CLI

```bash
vuln-scanner --templates ./examples/templates \
  --targets http://127.0.0.1:8080,http://127.0.0.1:8081 \
  --concurrency 4 --rate 20 --timeout 10s \
  --seed 42 --checkpoint ./scan.checkpoint.json \
  --severity high,critical --tags web \
  --output ./result.json
```

目标使用本地回环 HTTP 服务，不依赖外部网络与真实凭据。

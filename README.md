# LicenseGate — 开源依赖许可审查 Web 应用

基于 **FastAPI + SQLite** 的自托管工具：上传包含包名、版本、许可证与依赖关系的
JSON 清单，选择项目许可策略后，系统解析完整**传递依赖图**，按内置许可证
**兼容矩阵**标出冲突，为每个冲突给出：

* **结论**：`冲突(deny)` / `待审查(review)` / `兼容(allow)`；
* **触发规则**：矩阵规则（`MATRIX`）或策略规则（`POLICY_DENY` / `POLICY_ALLOW` / `UNKNOWN_LICENSE`）及触发的许可证；
* **最短依赖路径**：从直接依赖（根）到冲突包的最短路径（BFS）与引入深度；
* **多制品审查**：一个清单可声明多个 `distributions` 制品（各自名称、项目许可证、直接依赖），
  在同一张依赖图上分别遍历判定，总览按最严重结论聚合并列出受影响制品；
* **例外确认**：在页面上对任意冲突包填写理由并"确认例外"（多制品模式可按制品分别确认），
  结果实时重新计算，可随时撤销；
* **审查版本对比**：选择两个已保存项目（基线 → 当前），按 `name@version` 对齐依赖结果，
  报告新增 / 移除依赖、许可证或结论（触发规则）变化；每个**新增冲突**给出当前制品、
  触发规则与当前最短依赖路径；多制品清单按同名制品分别对比；
* **依赖裁剪试算（只读模拟）**：在已保存项目详情中勾选一条或多条
  "父包 → 子包" 依赖边，基于**原清单临时移除**所选边后重新计算可达性与许可结论；
  多制品项目按各制品根分别计算，报告每个制品**被消除 / 仍存在的冲突**、因失去全部路径
  而**不再纳入审查的包**及每项变化前后的最短路径；同一包仍可经其他路径到达时**不会误报
  已消除**。试算不写回清单、策略、例外或数据库，支持一键清空方案；
* **JSON 报告导出**：一键下载完整审查报告（多制品时含分制品明细）。

> ⚠️ 内置矩阵覆盖 MIT / Apache-2.0 / BSD / ISC / MPL-2.0 / LGPL-2.1 / LGPL-3.0 /
> GPL-2.0 / GPL-3.0 / AGPL-3.0 / Proprietary 等常见许可证（含 GPL 单向兼容、
> Apache↔GPL2 专利冲突、AGPL 网络条款等），仅作工程辅助，**不构成法律意见**。

---

## 一键启动（Docker Compose）

```bash
# 在项目根目录执行
docker compose up -d --build
```

启动后访问：

| 项目 | 地址 |
| --- | --- |
| Web 页面 | <http://localhost:8000/> |
| 健康检查 | <http://localhost:8000/api/health> |
| 策略列表 | <http://localhost:8000/api/policies> |
| 许可证矩阵 | <http://localhost:8000/api/licenses> |
| OpenAPI 文档 | <http://localhost:8000/docs> |

**端口**：容器内固定监听 `8000`；宿主机端口默认 `8000`，可通过环境变量修改：

```bash
LICENSEGATE_PORT=9000 docker compose up -d --build
# 然后访问 http://localhost:9000/
```

停止 / 清理：

```bash
docker compose down          # 停止（数据保留在命名卷 licensegate-data 中）
docker compose down -v       # 停止并删除数据库卷
```

---

## 本地开发运行（不用 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements.txt
export LICENSEGATE_DB=./data/licensegate.db   # SQLite 文件路径，默认 /data/licensegate.db
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

运行测试：

```bash
pip install pytest
pytest -q
```

---

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LICENSEGATE_DB` | `/data/licensegate.db`（容器内） | SQLite 数据库文件路径；设为 `:memory:` 使用内存库（测试用） |
| `LICENSEGATE_PORT` | `8000` | **宿主机**映射端口（docker-compose 变量，仅影响 `-p` 映射） |

容器内数据目录 `/data` 挂载到 Docker 命名卷 `licensegate-data`，容器重建后项目与
例外记录不会丢失。

---

## 清单文件格式

上传一个 UTF-8 编码的 JSON 文件（参考 [`examples/manifest.example.json`](examples/manifest.example.json)）：

```json
{
  "project": { "name": "my-app", "version": "1.4.0" },
  "project_license": "MIT",
  "direct_dependencies": ["web框架"],
  "packages": [
    {
      "name": "web框架",
      "version": "2.3.1",
      "license": "MIT",
      "dependencies": ["json工具@1.0.0", "日志库@0.9.2"]
    },
    {
      "name": "json工具",
      "version": "1.0.0",
      "license": "(MIT OR Apache-2.0)",
      "dependencies": []
    }
  ]
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `packages[].name` | 是 | 包名 |
| `packages[].version` | 否 | 版本，缺省记为 `0.0.0` |
| `packages[].license` | 是 | 许可证；支持 SPDX 标识与 SPDX 复合表达式 `AND` / `OR` / `WITH` / 括号 |
| `packages[].dependencies` | 否 | 依赖引用：`名字` 或 `名字@版本`；同名包仅一个版本时可省略版本 |
| `project.name` / `project.version` | 否 | 项目元信息 |
| `project_license` | 否 | 项目许可证（派生作品分发许可证），缺省取策略默认值 |
| `direct_dependencies` | 否 | 显式直接依赖（图的根）；缺省时以"入度为 0 的包"为根 |
| `distributions` | 否 | 多制品数组（见下）；提供后进入多制品审查模式 |

解析特性：

* 同一 `name@version` 重复出现会自动合并依赖边；
* 引用了不存在的包 → 记为"悬空引用"在页面提示，不中断分析；
* 循环依赖通过 Tarjan 算法检出并提示，BFS 不会死循环；孤立环中的包标记为"不可达"；
* 许可证别名自动规范化（`apache2` → `Apache-2.0`、`agpl` → `AGPL-3.0` 等），无法识别
  时按策略判为"待审查"或"冲突"。

### SPDX 复合表达式语义

* `A OR B`：被许可方可二选一，按**最兼容**分支判定；
* `A AND B`：条款同时适用，按**最严格**分支判定。

---

## 多制品审查（distributions）

一个仓库可能同时构建多个对外分发的制品（SDK、CLI、服务端……），它们共享同一张依赖图，
但**根集合与项目许可证不同**。清单可提供可选的 `distributions` 数组（参考
[`examples/manifest.multi.example.json`](examples/manifest.multi.example.json)）：

```json
{
  "project": { "name": "example-monorepo", "version": "3.0.0" },
  "packages": [ /* 所有制品共享的完整依赖图 */ ],
  "distributions": [
    { "name": "sdk-mpl",      "project_license": "MPL-2.0",  "direct_dependencies": ["sdk-main"] },
    { "name": "cli-gpl3",     "project_license": "GPL-3.0",  "direct_dependencies": ["cli-main"] },
    { "name": "service-agpl", "project_license": "AGPL-3.0", "direct_dependencies": ["service-main"] }
  ]
}
```

| `distributions[]` 字段 | 必填 | 说明 |
| --- | --- | --- |
| `name` | 是 | 制品唯一名称，重复会报错 |
| `project_license` | 是* | 该制品的项目许可证；可省略并回退到顶层 `project_license` 或策略默认值，仍需在所选策略允许范围内 |
| `direct_dependencies` | 是 | 非空字符串数组，该制品的遍历根（`名字` 或 `名字@版本`） |

语义：

* **同一依赖图、分别遍历**：后端只构建一次图，然后从每个制品自己的根分别执行 BFS 最短路径遍历，
  按**该制品的项目许可证**与所选策略判定；每个制品只统计从其根**可达**的包；
* **悬空根定位到制品**：某个制品的根引用无法解析时，记录在该制品的 `unresolved_roots`，
  同时进入全局 `unresolved_refs`，页面顶部明确标出是哪个制品的哪个根悬空；
* **公共包独立结论**：被多个制品共享的包，保留每个制品下独立的最短路径、结论、触发规则与
  例外状态（例如同一 LGPL 包在 MPL 制品下"待审查"、在 AGPL 制品下"兼容"）；
* **总览聚合**：`overview` 对每个包按**最严重结论**（deny > review > exception > allow）聚合，
  并在 `affected` 中列出各受影响制品的结论、规则、深度与路径；对所有制品都不可达的包
  （孤立环 / 未被引用）列入 `unreachable_packages`，不计入任何制品统计；
* **例外按规则生效**：在某制品下确认例外时，保存该制品当时的触发规则（`rule`）与制品名，
  重新计算时**只覆盖同 `package_id` 且规则相同**的制品结论——规则不同的制品（许可证不同）
  不受影响，规则相同的其他制品结论一并标记为例外；
* 多制品模式下不再支持统一覆盖"项目许可证"（每个制品以自己的许可证为准）；
* **未提供 `distributions` 的旧清单**：响应 `mode` 为 `single`，结构与行为与旧版完全一致。

页面在结果区提供"总览 / 各制品"切换标签：总览按最严重结论列出冲突与每个受影响制品的路径，
可直接对具体制品确认例外；制品标签只展示该制品可达的包及其制品内最短路径。

> 注意：各策略限定了不同的项目许可证范围（如 copyleft 策略只接受 GPL/AGPL/LGPL/MPL），
> 多制品清单中**所有制品**的 `project_license` 都必须落在所选策略的允许范围内，
> 否则上传/切换策略时返回 400。

---

## 审查版本对比（基线 → 当前）

两个已保存项目可进行版本对比：页面中部"审查版本对比"卡片选择**基线项目**（旧版本）与
**当前项目**（新版本）后点击"开始对比"。后端重新按各自**保存时的策略与例外状态**计算审查结果，
然后按 `name@version` 精确对齐两份依赖清单：

* **新增 / 移除依赖**：当前有、基线无（含版本升级——`lib@1.0` 移除、`lib@2.0` 新增）；
* **许可证变化**：同一 `name@version` 的声明许可证（原始文本）发生变化；
* **结论 / 触发规则变化**：结论（兼容 / 待审查 / 冲突 / 例外）或触发规则（`rule`）变化；
* **新增冲突**：当前版本新出现的 `deny` / `review`（或仍为冲突但触发规则改变），每条给出：
  * **当前制品**（多制品模式标明 distribution，单制品为 `null`）；
  * **触发规则**与说明（如 `MATRIX:GPL-2.0!GPL-3.0` / `POLICY_DENY:strong_copyleft`）；
  * **当前最短依赖路径**与引入深度（从该制品根 BFS 得到）；
  * 原因：`added`（新增包 / 新增制品引入）、`newly_reachable`（该制品内新可达）、
    `changed`（结论或规则由非冲突变为冲突）；
* **已消除冲突**：基线冲突在当前消失，原因含 `changed` / `removed` /
  `no_longer_reachable`（该制品内不再可达）/ `distribution_removed`（制品整体移除）。

**多制品清单按制品分别对比**：以同名制品对齐（名称是对齐键），逐制品统计新增可达包、
不再可达包、结论变化与新增冲突；新增 / 移除的制品本身也会报告，并提供"总览 / 各制品"
切换标签。图级别（跨制品）另有一份新增 / 移除 / 许可证变化清单。一个单制品项目与一个
多制品项目结构不同，不能互相比较（API 返回 400）。

对比是只读操作，**不影响**两个项目已保存的上传、例外与导出数据。

### 对比 API

```
POST /api/compare
Content-Type: application/json

{"baseline_id": 12, "current_id": 15}
```

返回 `licensegate-compare/v1` 报告：`mode`（single|multi）、两端项目元信息（含策略 /
项目许可证，不同时会标注）、`summary` 计数、`added` / `removed` / `license_changes` /
`verdict_changed` / `new_conflicts` / `resolved_conflicts`；多制品时额外包含
`distributions_added` / `distributions_removed` 与逐制品 `distributions[]` 明细
（每个 section 含自己的 `summary`、`common`、`added`、`removed`、`verdict_changed`、
`new_conflicts`、`resolved_conflicts`）。基线与当前为同一项目时返回 400，项目不存在返回 404。

---

## 依赖裁剪试算（只读 what-if）

在**已保存项目**的详情页底部"依赖裁剪试算"卡片中，勾选一条或多条
`父包 → 子包` 依赖边（支持全选 / 全不选），点击"发起只读试算"即可模拟
"如果不再通过这些边引入依赖"后的审查结论：

* **后端先校验边真实存在**：每条边都必须是原清单解析后的依赖图中实际存在的边
  （合并声明的重复包、`name` / `name@version` 引用均按原解析规则定位）；
  父包 / 子包不存在、边不存在或同一条边重复提交均返回 400；
* **基于原清单临时移除后重算**：不改动保存的清单，只在内存中的临时副本上移除所选边，
  重新执行 BFS 可达性遍历并按项目**保存时的策略与已确认例外**重新判定许可结论；
* **多制品项目按各制品根分别计算**：每个制品只统计从自己的根可达的包；
  只在部分制品下失去路径的包，只影响对应制品；在所有制品下都失去路径时才进入
  `newly_unreachable_packages`；
* **逐制品给出变化前后的最短路径**：
  * **被消除的冲突**：该制品下试算前为 `deny` / `review`，试算后因**失去全部路径**
    而不可达；
  * **仍存在的冲突**：裁剪后仍可达且仍为冲突——即使原路径被裁，只要同一包**仍可经其他
    路径到达**就只列在本节并给出新的最短路径，**绝不会误报为已消除**；
  * **不再纳入审查的包**：该制品下从可达变为不可达的全部包（含原本兼容的包）；
  * **最短路径变化**：仍可达、但 BFS 最短路径与试算前不同的包（可能改走其他路径）；
  * 多制品报告额外给出**跨制品总览变化**（最严重结论 / 可达制品集合变化）；
* **隐式根冻结**：未声明 `direct_dependencies` 的单制品清单，其根（入度为 0 的包）
  在试算中保持不变，避免删除唯一入边后子包被错误地"晋升"为新根；
* **一键清空方案**：点击"一键清空方案"（或全不选）即清除勾选与试算结果，回到原始审查视图。

试算是纯只读操作：**不会写回**清单、策略、例外，也不写数据库；重新打开项目或切换
策略 / 确认例外后，旧试算方案自动失效。

### 试算 API

```
POST /api/projects/{id}/pruning-sim
Content-Type: application/json

{"edges": [{"from": "web框架@2.3.1", "to": "网络内核@3.1.0"},
           {"from": "rpc工具包@5.0.0", "to": "网络内核@3.1.0"}]}
```

返回 `licensegate-pruning/v1` 报告：`read_only: true`、`removed_edges`、总览 `summary`
（`eliminated_conflicts` / `remaining_conflicts` / `dropped_packages` /
`changed_paths` / `conflicts_before` / `conflicts_after` / `newly_unreachable`）、
`newly_unreachable_packages`、逐制品 `scopes[]`（每项含四类变化清单与每项的
`before_shortest_path` / `after_shortest_path`）、多制品时的 `overview` 总览变化，
以及完整的 `baseline` / `simulated` 两份标准审查结果。`edges` 可为空（等价于不裁剪）；
项目不存在返回 404，边不合法返回 400。

---

## 许可策略

策略在兼容矩阵之上叠加两层规则：

1. **策略禁止家族**（`POLICY_DENY`，最高优先级）——即使矩阵判兼容也按冲突处理；
2. **策略预放行家族**（`POLICY_ALLOW`）——矩阵建议"待审查"时可自动放行；
   矩阵明确"冲突"的组合**永远不会被降级**。

| 策略 | 默认项目许可证 | 行为摘要 |
| --- | --- | --- |
| `permissive` 宽松商业友好 | MIT | 允许宽松/MPL；LGPL 预放行（仍建议确认链接方式）；GPL/AGPL/专有拒绝 |
| `copyleft` Copyleft 开放专享 | GPL-3.0 | 允许开源/ copyleft 许可证；专有拒绝；矩阵不兼容组合拒绝 |
| `strict` 严格白名单 | MIT | 仅允许公共领域与宽松许可证；MPL/LGPL/GPL/专有及**无法识别的许可证**全部拒绝 |
| `proprietary` 专有闭源商业 | Proprietary | 仅允许宽松/Apache；MPL 待审查；LGPL/GPL/AGPL 拒绝 |

每个策略限定了可选的"项目许可证"范围；上传时也可以在页面上覆盖项目许可证并重新计算。

---

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/analyze` | 即时分析（JSON body，不落库） |
| `POST` | `/api/projects` | 上传清单（`multipart/form-data`：`file`、`policy_key`、`project_license`），创建项目并返回分析结果 |
| `GET` | `/api/projects` | 项目列表 |
| `GET` | `/api/projects/{id}` | 获取项目最新分析结果（可带 `?policy_key=&project_license=`） |
| `POST` | `/api/projects/{id}/reanalyze` | 切换策略/项目许可证后重新计算 |
| `POST` | `/api/projects/{id}/exceptions/{package_id}` | 确认例外（body：`{"note": "理由", "distribution": "制品名"}`），自动重新计算。多制品模式必须带 `distribution`，后端按该制品当前触发规则保存 |
| `DELETE` | `/api/projects/{id}/exceptions/{package_id}` | 撤销例外，自动重新计算；多制品模式需带查询参数 `?distribution=制品名` |
| `DELETE` | `/api/projects/{id}` | 删除项目 |
| `POST` | `/api/compare` | 审查版本对比（body：`{"baseline_id": 旧ID, "current_id": 新ID}`），按 `name@version` 对齐，新增冲突含当前制品 / 触发规则 / 最短路径 |
| `POST` | `/api/projects/{id}/pruning-sim` | 依赖裁剪只读试算（body：`{"edges": [{"from": "父@ver", "to": "子@ver"}]}`）：校验边存在后基于原清单临时移除并重算，逐制品给出消除/仍存在冲突、不再纳入审查的包与变化前后最短路径，不写回任何数据 |
| `GET` | `/api/projects/{id}/export` | 下载 JSON 报告（`license-report-{id}.json`），多制品时含 `distributions` 分制品明细与总览 |
| `GET` | `/api/policies` · `/api/licenses` · `/api/health` | 元数据 |

`package_id` 即 `name@version`（URL 中需编码，前端已处理）。

导出报告（`licensegate-report/v1`，含 `mode: single|multi`）包含：项目与策略信息、统计摘要、
每个包的结论 / 触发规则 / 最短路径 / 例外信息、冲突列表、循环依赖、悬空引用以及原始清单。
多制品报告额外包含 `distributions`（每个制品独立的摘要、包结论、冲突、根、悬空根）与
总览 `packages[].affected`（每个受影响制品的结论、规则、路径）。

---

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由与静态页
│   ├── analyzer.py    # 清单解析、依赖图、BFS 最短路径、环检测、单/多制品冲突分析
│   ├── compare.py     # 审查版本对比：按 name@version 对齐两份结果，逐制品报告差异与新增冲突
│   ├── pruning.py     # 依赖裁剪只读试算：校验/临时移除依赖边后重算，逐制品报告冲突消除与路径变化
│   ├── licenses.py    # SPDX 规范化、表达式解析、兼容性矩阵
│   ├── policies.py    # 四种许可策略与判定叠加规则
│   └── db.py          # SQLite 持久化（项目 + 按 (包,规则) 维度的例外，含旧库迁移）
├── static/index.html  # 单页前端（原生 JS，无构建步骤，含制品切换、总览、版本对比与裁剪试算）
├── examples/          # 示例清单（manifest.example.json 单制品 / manifest.multi.example.json 多制品）
├── tests/             # 85 个单元/接口测试（含多制品引擎、版本对比、裁剪试算与端到端用例）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

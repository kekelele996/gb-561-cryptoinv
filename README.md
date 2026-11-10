# cryptoinv · 密码学资产盘点与迁移清单台

> 云栖省政务云密码应用中心：把「Excel 台账 + Nginx grep 找证书 + 老同事记到期」换成可举证的密码学资产盘点与国密迁移清单。
> **5 服务全栈**：Vue 3 + TS + Vite（Nginx） / FastAPI / Celery worker / PostgreSQL 16 / Redis 7。

## 1. 真实场景

- **模拟客户**：云栖省政务云密码应用中心，承载 **60 个厅局系统 / 320 个对外域名**，正在做等保 2.0 密评，国密改造窗口 **2027Q1**。
- **现有工作流**：证书台账靠 Excel 人工登记；Nginx 配置里 grep 证书路径；到期靠几个老同事记；密评前一个月突击盘点。
- **3 个痛点**：
  1. 去年线上证书过期 2 次（其中一次 0 天到期 P0），没有统一预警；
  2. 算法强度无法举证（RSA-1024、SHA-1 仍在用），密评一问就哑；
  3. 国密改造没有迁移清单与优先级，各厅局各自摸。
- **上下游**：上游「各厅局 TLS 端点扫描结果 + 证书 PEM 导入」→ 本系统 → 下游「厅局整改/到岸材料 + 密评报告」。

### 角色权限

| 角色 | 演示账号 | 权限 | 典型动作 |
|---|---|---|---|
| `admin` | `admin@cryptoinv.demo` | 全部读写 + 导出审批 | 导入证书、创建全量导出记录、看审计日志 |
| `engineer` | `engineer@cryptoinv.demo` | 录入、扫描、评估、生成迁移项、导出迁移 CSV | 解析证书、跑全量评估、推进迁移状态 |
| `owner` | `owner@cryptoinv.demo`（省人社厅） | 只读本厅局 + 确认本厅局迁移窗口 | 看本厅局台账、把 P0 迁移项置为已排期 |

- 口令统一 `Demo@2026`；`owner` 登录后行级过滤到 `省人社厅`，且**不能做全量导出 / 生成清单**（403，审计留痕）。
- 越权尝试会写 `audit_logs`（`action=authz.denied`）。

## 2. 快速启动

```bash
cd batch-20261110c/projects/gb-561
cp .env.example .env

docker compose config --quiet          # 通过
docker compose up -d --build           # 5 服务全部 healthcheck
docker compose ps                      # 期望 5/5 (healthy)

# 手动重跑幂等 seed（SEED_DEMO=true 时 backend 启动已自动跑过一次）
docker compose exec -T backend python -m scripts.seed_demo
```

- 前端：<http://localhost:18234>
- 后端直连：<http://localhost:19234/api/health>
- 数据库（宿主）：`localhost:17734`，库/用户/口令见 `.env.example`

收尾：

```bash
docker compose down -v --remove-orphans
```

## 3. 技术栈

| 层 | 选型 |
|---|---|
| 前端 | Vue 3.5 + TypeScript + Vite 5 + Pinia + Vue Router + axios |
| 后端 | Python 3.11 + FastAPI + SQLAlchemy 2.0 + Alembic + PyJWT |
| 任务 | Celery 5.4（worker 容器跑真实评估任务，Redis 作 broker/backend） |
| 数据库 | PostgreSQL 16 |
| 缓存/限流 | Redis 7 |
| 网关 | Nginx 1.27（`/api/` 反代 + SPA 回落） |
| 视觉 | 航海勘测图/海图：深青底 + 米色纸 + 罗盘铜色 + 经纬网格；Cormorant Garamond + Space Mono |

## 4. 核心算法（Python 真算，前端只渲染）

### 算法 1 · X.509 解析与链/时效校验（`backend/src/services/x509_audit.py`）

- **输入**：证书 PEM（`backend/fixtures/certs/` 下 11 个真实 PEM + seed 确定性生成 41 张）。
- **真解析**：`cryptography.x509.load_pem_x509_certificate`，取 subject/issuer DN+CN、SAN、
  serial、有效期、公钥算法与位数、`signatureAlgorithm` OID → 名称（`utils/oid_map.py`）、SKI/AKI、BasicConstraints。
- **链构建**：从叶证书出发，按 `issuer DN == subject DN` 在同端点候选池（端点证书 + 全局 CA 池）找签发者；
  双方都有 AKI/SKI 时要求 `child.aki == parent.ski`；追到自签根即链完整，最多 8 层防环。
- **链校验**（优先级从高到低）：`expired` > `incomplete` > `name_mismatch` > `is_valid`。
  `name_mismatch` = SAN 不含端点 hostname（支持 `*.` 单层通配）。
- **时效分级**：`days_left = (not_after - now).days` → 已过期 / ≤30 天 / ≤90 天 / 正常（台账看板四档）。
- **失败态**：PEM 非法 → `PemUnparsable`（进 `unparsable` 清单，不落库）；
  含 `PRIVATE KEY` → `PemPrivateKeyRejected`（**私钥一律拒绝，绝不入库/入仓库**）；
  SM2/国密曲线不被本镜像 OpenSSL 支持 → 证书字段照常解析，`unsupported_by_crypto_lib=true`，
  公钥算法按签名 OID 识别为 `SM2`，评分按 `unknown_algo` 处理（诚实边界，见 §9）。

### 算法 2 · 强度评分与迁移优先级（`backend/src/services/strength.py`）

```
strength_score = 0.35*key_strength + 0.25*sig_strength + 0.15*validity
               + 0.15*chain_trust + 0.10*agility        (0..100)
```

| 分量 | 口径 |
|---|---|
| `key_strength` | RSA≥2048=1.0 / RSA-1024=0.35 / RSA<1024=0.1 / ECDSA P-256、P-384=1.0 / SM2=1.0 / 未知=0.0 |
| `sig_strength` | SHA256+=1.0 / SHA1=0.2 / MD5=0.0 / SM3=1.0 / 未识别 OID=0.0 |
| `validity` | 正常=1.0 / ≤90 天=0.8 / ≤30 天=0.5 / 已过期=0.0 |
| `chain_trust` | 链完整已验证=1.0 / incomplete 或 name_mismatch=0.5 / self_signed=0.3 |
| `agility` | 国密（SM2/SM3）=1.0 / 支持 TLS1.3 的现代算法=0.6 / 其余=0.4 |

- **风险标签**：`weak_key`（RSA<2048）、`sha1`、`expired`、`self_signed`、
  `quantum_vulnerable`（RSA/ECDSA 全部标注，SM2 不标）、`unknown_algo`。
- **合规结论**：硬性标签（weak_key/sha1/expired/unknown_algo）→ `non_compliant`；
  否则 `score>=80 且非自签` → `compliant`；`score>=60` → `grace`；其余 `non_compliant`。
- **迁移优先级**（各分量归一化到 0..100）：

```
priority_score = 0.4*(100-strength_score) + 0.3*urgency + 0.2*dept_risk + 0.1*exposure
urgency   : 已过期/≤30天=100, ≤90天=80, ≤180天=50, ≤365天=30, 其余=10
dept_risk : A=100 / B=70 / C=40      （计划口径 A=1 / B=0.7 / C=0.4，×100 归一化）
exposure  : internet_facing=100 / 内网=30
→ P0≥70 / P1 50~70 / P2 30~50 / P3<30
批次窗口  : urgency=100 → 2026Q4；=80 → 2027Q1；其余 → 2027Q2
目标算法  : weak_key/sha1/未知 → SM2-SM3；量子脆弱 → ECDSA-P256；其余 → RSA-2048+
```

- **失败态**：无法识别的算法（`unknown_algo`，如 SM2 曲线）score 记 0、**不参与优先级**，
  由迁移生成流程放入 `manual_review` 人工清单（seed 里 `gm.mz.yunqi-gov.example` 就是这一条）。
- **落库**：`algorithm_assessments`（含五个分量，可复核）、`chain_records`、`migration_items`。

### 算法产出可复核

`backend/scripts/seed_demo.py` 打印的 `SEED_SUMMARY` 里带全部桶计数与优先级分布，例如：
`expired=12 soon30=8 soon90=10 normal=22 chain_incomplete=3 migration_p0=4 migration_p1=5`。
两次运行逐字一致。

## 5. 页面（6）

| 路由 | 页面 | 要点 |
|---|---|---|
| `/login` | 登录 | 三演示账号一键填充；页面明确声明数据为合成样本 |
| `/certs` | 证书台账 | 到期看板四档计数 + 筛选（时效/算法/风险标签/检索）+ 跑全量评估 |
| `/certs/:id` | 证书详情 | 解析字段 + 链视图（节点依次点亮）+ 有效期条 + 强度评分 + 风险标签 + 迁移项 |
| `/endpoints` | TLS 端点 | 40 端点列表 + **模拟扫描**（醒目标注）+ 扫描结果（证书真解析） |
| `/matrix` | 算法风险矩阵 | algo × dept 热力（平均分 / 不合规数 / 弱算法数）+ 厅局/算法排行 |
| `/migration` | 迁移计划 | P0-P3 + 批次窗口 + 状态流转 + 生成/刷新清单 + 导出 CSV |

共用业务组件（≥2 页复用）：`ExpiryBar`（台账/详情）、`RiskTagChip`（详情/矩阵）、
`ChainViewer`（详情）、`ScoreGauge`（详情/矩阵语义）、`AppShell`、`Pagination`、`EmptyState`、`PageHead`。

## 6. 目录

```
projects/gb-561/
├── docker-compose.yml          # name: cryptoinv，无 version，5 服务全 healthcheck
├── .env.example  .gitignore
├── backend/
│   ├── Dockerfile  entrypoint.sh  alembic.ini  requirements.txt
│   ├── migrations/             # alembic（env.py + versions/0001_initial.py）
│   ├── fixtures/certs/         # 11 个真实 PEM（只含证书，无私钥）+ gen_fixtures.py + manifest.json
│   ├── scripts/seed_demo.py    # 幂等 seed（自然键 upsert）
│   └── src/
│       ├── config/             # settings / database / app / celery_app
│       ├── constants/          # enums / roles / error_codes / limits
│       ├── models/             # 6 实体 + user + audit_log + base
│       ├── schemas/            # pydantic 请求体
│       ├── middlewares/        # auth / rbac / rate_limit / audit_logger / error_handler
│       ├── routes/             # meta / auth / certificates / endpoints / assessments / matrix / migration / exports
│       ├── controllers/        # 请求编排 + 审计
│       ├── services/           # x509_audit(算法1) / strength(算法2) / assessment / certificate / endpoint / migration / export / auth / audit
│       └── utils/              # jwt / password(PBKDF2) / errors / logger / redis / oid_map / timeutil
├── worker/
│   ├── Dockerfile  healthcheck.sh
│   └── src/{config,tasks}      # Celery app + 评估任务 + 心跳任务
└── frontend/
    ├── Dockerfile  nginx.conf  package.json  vite.config.ts  tsconfig.json
    └── src/{api,stores,types,components/common,hooks,pages,router,utils,constants,styles}
```

## 7. 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `COMPOSE_PROJECT_NAME` | `cryptoinv` | 容器名前缀 |
| `FRONTEND_PORT` / `BACKEND_PORT` / `DB_PORT` | `18234` / `19234` / `17734` | 题目分配端口 |
| `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `cryptoinv` / `cryptoinv` / `cryptoinv_pw_2026` | PostgreSQL |
| `JWT_SECRET` | 见 `.env.example`（演示值，生产必须换） | HS256 签名密钥 |
| `ACCESS_TOKEN_MINUTES` | `120` | access token 有效期 |
| `REDIS_URL` | `redis://redis:6379/0` | broker / 限流 / 进度 |
| `SEED_DEMO` | `true` | 启动自动跑一次幂等 seed |
| `RATE_LIMIT_DEFAULT_PER_MINUTE` | `240` | 每用户每分钟常规配额 |
| `RATE_LIMIT_ASSESS_PER_MINUTE` | `6` | 评估/扫描类接口每分钟配额 |

## 8. 演示账号

| 账号 | 口令 | 角色 |
|---|---|---|
| `admin@cryptoinv.demo` | `Demo@2026` | admin |
| `engineer@cryptoinv.demo` | `Demo@2026` | engineer |
| `owner@cryptoinv.demo` | `Demo@2026` | owner（省人社厅） |

## 9. 诚实边界（必读）

1. **全部为合成数据**：不连接真实 CA、不做真实 TLS 握手、不查询真实 CVE/证书库。
   证书是自签/合成 CA 签发的本地 PEM；"扫描"是按 hostname sha256 确定性挑选本地 fixture 的**受控模拟**。
2. **私钥绝不入库**：`fixtures/certs/` 只有 `CERTIFICATE` 块；`gen_fixtures.py` 的作者期私钥只存在于临时目录。
   导入接口发现 `PRIVATE KEY` 直接 422 拒绝（`PEM_PRIVATE_KEY_REJECTED`），不会落库。
3. **SM2 的库限制**：`cryptography`/本镜像 OpenSSL 不支持 SM2 曲线公钥运算，
   SM2 证书只能做到"加载 + OID/字段识别"，无法做公钥解析与签名验证 → 标记 `unsupported_by_crypto_lib` 并进入人工清单。
4. **日期锚定**：fixtures 与生成证书的有效期锚定 **2026-11-10**，因此 `12 过期 / 8 30 天内 / 10 90 天内`
   是在验收日成立的真实计算值；跨日期运行会按实时天数自然漂移（这正是证书管理应有的行为）。

## 10. 枚举出现位置（共享枚举 2 组 + 1）

| 枚举 | 后端 | 前端 | 其它引用 |
|---|---|---|---|
| `MigrationPriority`（P0-P3） | `constants/enums.py` | `constants/enums.ts` | `services/strength.py`、`services/migration_service.py`、`schemas`、`pages/MigrationPage.vue`、`constants/labels.ts` |
| `ChainValidation`（is_valid/expired/name_mismatch/incomplete） | `constants/enums.py` | `constants/enums.ts` | `services/x509_audit.py`、`services/assessment_service.py`、`models/chain_record.py`、`components/common/ChainViewer.vue`、`pages/CertsPage.vue` |
| `RiskTag`（6 个标签） | `constants/enums.py` | `constants/enums.ts` | `services/strength.py`、`pages/CertsPage.vue`、`pages/CertDetailPage.vue`、`components/common/RiskTagChip.vue` |

## 11. 横切关注点

- **认证授权**：JWT（HS256，access 2h + refresh 7d）+ RBAC 能力矩阵（`constants/roles.py`）+
  `owner` 行级数据范围（`user.dept`）；越权写审计并返回 403。
- **审计日志**：`audit_logs` 表，登录 / 导入 / 扫描 / 评估 / 迁移生成与流转 / 导出 / 越权拒绝全部落库，
  `admin` 可查 `/api/audit`。
- **限流与配额**：Redis 滑动窗口（每用户每路径每分钟）+ 每角色每日配额（admin 2000 / engineer 1200 / owner 300），超限 429。
- **口令**：PBKDF2-HMAC-SHA256（210000 轮 + 随机盐，标准库实现，避免额外 C 依赖）。

## 12. 已知差异

见 `test-artifacts/gb-561/TESTING.md` §8。摘要：合成数据/模拟扫描、SM2 库限制、有效期锚定日期、
Celery worker 同步兜底逻辑（worker 不在线时 API 内联执行）。

## License

内部演示项目，仅用于评审与教学；所有机构、域名、证书均为虚构合成数据。

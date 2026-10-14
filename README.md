# QX 低延迟公开订阅筛选器

Python 3.10+，使用 sing-box 1.12.12 实际代理连接测速，生成 Quantumult X 的节点资源文件。仅接受有权使用并允许公开再分发的来源；不扫描 IP/端口、不猜测凭据。

## 订阅地址

```
https://raw.githubusercontent.com/art61771-stack/qx-clean-subscription/main/public/qx.txt
```

Quantumult X → 设置 → 节点 → 引用（资源）→ 添加此 URL；该文件是节点资源，不是完整 QX 配置。详细菜单名称可能随版本改变。

筛选报告：[`public/status.json`](public/status.json)。若 selected=0，订阅只有注释，没有可用节点；不代表已找到节点。不保留过期结果冒充新结果。

## 自动更新和自定义数量

每 6 小时执行一次（GitHub 调度可能延迟）。Actions → Update QX subscription → Run workflow：
- `count`：最多选出多少个，默认 **20**，范围 1–100。
- `max_latency`：每次 HTTPS 测试耗时上限，默认 **200ms**。

定时任务使用默认参数。修改定时默认值需要同时修改工作流 env 中的默认值。

本地运行需要 Python、curl、sing-box（不使用 pip 依赖）：

```bash
python collect.py --count 20 --max-latency 200 --max-risk 10
```

## 筛选规则（不夸大“纯净”）

1. 支持标准 Shadowsocks AEAD、Trojan TCP+TLS、VMess AEAD TCP/WS（可选TLS）URI。复杂插件、VLESS/Reality、Trojan WS/gRPC 等明确跳过，不生成错误 QX 配置。VMess auto 导出为 QX aes-128-gcm。
2. 真实 sing-box 代理转发，访问 `https://www.gstatic.com/generate_204` 三次。每次都是独立 curl，包含连接、代理握手、TLS、HTTP 响应时间；**三次均 ≤200ms** 才入选，按中位数排序。不是 TCP ping。
3. 通过节点获取出口 IP；通过 proxycheck.io 公共 API 查询。仅 `proxy=no` 且风险分 ≤10 入选；缺失、额度耗尽、查询失败全部拒绝。代理节点往往会被标记为 proxy，因此可能无合格结果。此规则只是风险数据库筛选，**不保证住宅 IP、绝对干净或流媒体/AI 解锁**。
4. 相同出口 IP 只保留最快一个。数量是上限，不足不凑数。
5. 测速地点是 GitHub runner，**不代表你手机/国内网络的延迟**，更不能保证未来持续可用。建议 QX 中再次测速。
6. 最多测试 150 个候选、4 并发；不做下载带宽压测。

## 来源及公开凭据风险

按用户要求，另接入 Pawdroid/Free-servers、free-nodes/v2rayfree 和 free18/v2ray 的上游公开免费订阅做节点优选。发布者主动提供订阅不等于我们独立确认了每台服务器的所有权或再分发许可；不接受已知泄露/付费私人账户，收到运营者撤回要求即移除。仅将通过测试的 QX 兼容节点公开，VLESS/Reality 等明确跳过。最多测试去重后的前150个候选，不宣称已测完整列表。

同时保留主动公开的自建分享：
- General Kim / [@general_kim_free_vpn](https://t.me/general_kim_free_vpn)：运营者明确说明自己搭建 SS 服务器，且“欢迎大家自由使用并分享给更多人”。项目最后更新 2025-04-28，需实测确认存活。
- VV科技 / [@vvkj11](https://t.me/vvkj11)：读取 free18/v2ray README 的“自建节点”分组，并另行读取其主动公布的通用免费订阅。
- 五叶 / [@hkaa0](https://t.me/hkaa0)：只读取 #自建 搜索页中明确写着“转发请标注来源”的帖子，排除匿名投稿，订阅保留署名。

这些是发布者自述的自建免费分享，并非对服务器所有权的独立审计。历史分享可能已失效；公开分享不等于低延迟、安全或干净，仍需实测。只看 Telegram 公开网页，不登录/入群，不抓取私人消息或付费凭据。

`sources.json` 中每个来源必须标记 `redistribution_allowed: true`，并记录允许分享的证据。空列表时不会凭空生成节点。

也可以设置仓库 Actions secret `SOURCE_URLS`（每行一个 HTTPS 订阅 URL）：**设置该 secret 即确认有权公开分享这些节点**。secret 本身不会写入日志/订阅，但节点连接凭据会出现在公开订阅和 Git 历史中；不要填付费机场/个人订阅，除非服务提供者明确允许公开再分发。

GitHub token 不进入脚本或订阅。公开节点可能被他人滥用、限流、封禁；删除仓库不保证撤回已经被复制的凭据。不要经不可信免费节点传输明文敏感信息。

## 文件

- `collect.py`：采集、实测、风险筛选、生成 QX 文件。
- `.github/workflows/update.yml`：定时运行、校验内核 SHA256、发布结果。
- `tests/`：解析器和拒绝边界的单元测试。
- `public/qx.txt`：公开节点资源。
- `public/status.json`：不含源订阅地址/节点密码的筛选摘要。

首次使用以及每次更新请先看 `status.json`，不能把工作流成功当作已筛选出合格节点。

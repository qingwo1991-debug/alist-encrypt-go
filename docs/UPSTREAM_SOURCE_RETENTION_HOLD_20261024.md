# 上游来源保留暂停：覆盖迁移、调度和独立 cron

## 本轮真实发现及修复范围

前一阶段已验证 uploader 的持久条件有效，但它不等于上游入口全部暂停。本轮实际发现下载迁移、统一调度、watchdog 的三个 timer 仍 active，对应 service 尚无来源审查条件；另有每周 cron 直接运行 unified shell 的去重模式。不能倒称此前这些入口已经暂停，也不凭此推断过去实际删了哪些文件。

本轮安装的只有安全暂停措施，**没有安装新来源证明组件或恢复上传**：

- 给三个 service 增加持久、默认不满足的来源审查条件，与现有 uploader 使用同一不存在的 reviewed sentinel。
- 停止三个 timer 和 service，以及既有已失败的临时恢复 scheduler；保留 timer 的 enabled 配置，不自动恢复。
- 在 unified shell 的 mkdir、cd、Python 调用之前加入八行提前检查，未审查时直接保持，覆盖直接 pipeline 和每周 cron 的 dupes；只读 status 不在此次调用范围。
- 原始 shell 私有备份保留；现行 backend、mover、uploader 源码未被新阶段替换。

## 实际验收及独立复查

父级 daemon-reload 后请求启动三个 service，均由 false condition 跳过，没有执行 ExecStart。独立只读 systemctl show 再次确认三个 service 全部 inactive/dead、ConditionResult=no、drop-in 正确，三个 timer 全部 inactive；uploader 也保持 inactive/dead、ConditionResult=no。

shell 语法检查通过；父级与独立复查实际执行 pipeline、dupes，均退出 0、返回精确 held 提示且 stderr 为空，代码在任何 Python 调用前返回。审查标记在前后均不存在且不是 symlink。独立复查核验三份 drop-in、shell 和备份摘要前后一致，未发现 P0/P1。

没有运行 status、实际下载／云 RPC、真实媒体处理、回收站 prepare／clear／restore，也没有创建审查标记。此措施不拦截任意 root 直接运行 Python 或外部 aria2 控制面；不把 systemd 条件说成冻结全部生产者。

## 仍须完成

新来源登记、分片证明、配对发布与上传门禁保持阶段状态；初版来源整链的六项真实组件微型测试已由父级独立重跑通过（0.777 秒），但使用的只是 128 字节合成文件和假 native RPC，不是实际上传、完整解码或云端恢复验收。

原生完整快照获取、实际 mover 入口协调与发布后恢复控制器仍须各自审查、整组安装门禁和实际验收。缺失来源不得按名字或历史 hash 自动补造登记。原源、torrent、控制文件、下载任务和旧云对象继续保留；完整云端明文读回与持久绑定收据也不能替代另行审查的清理协议。

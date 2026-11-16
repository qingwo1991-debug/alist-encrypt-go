# 已安装固定 FD 验证器的实际解码兼容性（2026-10-24）

## 通过，仅微小合成媒体

在已安装的协调源集及实际服务 Python 环境中，完成了 Linux `/proc/self/fd` 和 FFmpeg `pass_fds` 的真实兼容性验证，总墙钟 **5.924 秒**。没有读取生产影片、调用云端或恢复上传器。

| 合成夹具 | 大小 | 内容 | 真实固定 FD 完整验证 |
| --- | ---: | --- | --- |
| Matroska | 103,099 字节 | 2 秒 64×64 FFV1 / PCM，440Hz 合成音频 | 通过，9 次真实子进程 |
| MP4 | 51,723 字节 | 2 秒 64×64 MPEG-4 / AAC，440Hz 合成音频 | 通过，9 次真实子进程 |

总载荷 **154,822 字节**，生成时限制单编码 / filter 线程，不超过 1 MiB 及 30 秒总预算。两文件均使用 `full_decode=True`、`timeout=10` 和实际打开的 FD。仪表观察每次调用输入为 `/proc/self/fd/N`、`pass_fds=(N,)`，参数不含原路径；实际子进程执行未被 mock。观察包装器为缺少它的采样调用增加了 `-nostdin`，未修改接受条件，故不声称是完全不变 argv 的逐字复刻。

## 路径替换两层结果

固定 MP4 FD 后，将其合成路径改名并在原位置写入少量无效字节：

- 实际完整验证仍读取原 inode，通过另外 9 次真实子进程。
- 外层 `UploadSourceGuard.confirm_decoded()` 拒绝新的命名路径身份，抛出 SourceChangedError。

合计 **27 个真实验证子进程：12 ffprobe + 15 ffmpeg**；生成夹具的另两次 ffmpeg 不计入验证数。这是解码 FD 兼容性与变源拒绝的证据，不授权发布替换路径。

## 安装与持续门禁未变

实际导入 `/root/script/media_safety.py` 和 `/root/script/upload_source_guard.py`，安装前后摘要仍为 `2dd6f1f6957d7b7a83bda8e67ffcf8f6b9c871a69a3d49e75fe3364b0cec45f4` 与 `034d8e06f325f8fd318f7ba638c413440b751cea6dbb4cb7b816ada9bca5e4a7`；上传器仍为 `2fc4d0d03fc84ec00988c31a0877350ea41a08cdcfcaf48d8f20127f4bebb1c8`。

结束后上传器 inactive / ConditionResult=no，夜间 timer 和 service inactive，批准 sentinel 缺失。仅清理本测试明确命名的微小合成载荷，保留报告及脚本。没有源代码修改、真实影片解码、网络 / 云请求、配置变化或服务启动。

本结果追加于此前 **83 项安装路径离线 / loopback 回归**，不替代它们，也不等于所有媒体格式认证、实际恢复件完整解码或 torrent 来源真实性验收。来源账本与 mover / uploader / 删源流程的持久证明集成仍待完成，上传持续暂停。

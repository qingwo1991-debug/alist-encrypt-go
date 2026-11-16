# Android 本地目录挂载与加密自动同步落地方案

## Summary
目标是在当前集成版 Android App 中一次性实现以下四项能力，并保持边界受控：

1. **A. 支持挂载手机本地目录**
   - 重点支持 `/Download`、`/DCIM`
   - 兼容 Android 9-16
2. **B. 支持存储权限申请与状态引导**
3. **C. 提供本地目录挂载 UI**
4. **D. 提供目录级定时加密同步上传**
   - 文件类型过滤
   - 支持排除目录
   - WiFi-only
   - 保留目录结构
   - 立即执行与周期执行
   - 上传统一走本地 `5344` 加密代理

边界：
- 只做“本地目录访问 + Local 挂载 + 最小可用同步系统”
- 不增加当前没有证据必须要的权限：`ACCESS_LOCAL_NETWORK`、`SCHEDULE_EXACT_ALARM`、`FOREGROUND_SERVICE_SPECIAL_USE`
- 不做 SAF 树 URI 持久化方案；以绝对路径 + `MANAGE_EXTERNAL_STORAGE` 为主
- 不做双向同步、复杂冲突合并、MD5 全量校验、秒级精确调度

## Key Changes

### 1. Android 存储权限与系统声明
修改 [mobile/android/app/src/main/AndroidManifest.xml](/root/AI/alist-encrypt-go/mobile/android/app/src/main/AndroidManifest.xml)

新增权限：
- Android 9-10：
  - `android.permission.READ_EXTERNAL_STORAGE`
  - `android.permission.WRITE_EXTERNAL_STORAGE`（`maxSdkVersion=29`）
- Android 11+ 主权限：
  - `android.permission.MANAGE_EXTERNAL_STORAGE`
- Android 13+ 补充媒体权限：
  - `android.permission.READ_MEDIA_IMAGES`
  - `android.permission.READ_MEDIA_VIDEO`
  - `android.permission.READ_MEDIA_AUDIO`

新增应用属性：
- `<application android:requestLegacyExternalStorage="true" ...>`

不加：
- `ACCESS_LOCAL_NETWORK`
- `SCHEDULE_EXACT_ALARM`
- `FOREGROUND_SERVICE_SPECIAL_USE`

保持现有前台服务类型不变，不为同步功能新增 specialUse FGS。

### 2. Flutter 端统一存储权限工具
新增：
- `mobile/lib/utils/storage_permission_helper.dart`

提供最小接口：
- `Future<bool> isGranted()`
- `Future<bool> requestWithRationale(BuildContext context)`
- `Future<void> openManageAllFilesSettings()`

策略固定：
- Android 9-10：请求 `Permission.storage`
- Android 11-16：请求 `Permission.manageExternalStorage`
- `READ_MEDIA_*` 仅作为附加声明，不单独驱动目录挂载流程

说明文案只解释：
- 访问本地目录
- 本地目录挂载
- 加密后同步上传
- 未配置前不会自动上传任何文件

### 3. 原生桥接与配置持久化
当前已有：
- `MainActivity.kt`
- `AppConfigBridge.kt`
- `EncryptProxyBridge.kt`
- `generated_api.dart`
- `NativeBridge`

在此基础上扩展，不重构现有架构。

#### 3.1 AppConfig 扩展
修改 [mobile/android/app/src/main/kotlin/com/openlist/mobile/config/AppConfig.kt](/root/AI/alist-encrypt-go/mobile/android/app/src/main/kotlin/com/openlist/mobile/config/AppConfig.kt)

新增持久化字段：
- `localMountsJson`
- `syncTasksJson`

只存 JSON 字符串，不先引入 Room 作为配置存储。

#### 3.2 Pigeon / Bridge 扩展
扩展当前 Pigeon 定义与生成接口，增加两组能力：

- `StorageAccess`
  - `isStorageAccessGranted`
  - `requestStorageAccess`
  - `openStorageAccessSettings`

- `SyncTaskApi`
  - `getLocalMountsJson`
  - `setLocalMountsJson`
  - `getSyncTasksJson`
  - `setSyncTasksJson`
  - `scheduleSyncTask`
  - `cancelSyncTask`
  - `runSyncTaskNow`
  - `getSyncTaskStatus`
  - `getSyncTaskHistory`

对应新增原生 bridge：
- `mobile/android/app/src/main/kotlin/com/openlist/mobile/bridge/StorageBridge.kt`
- `mobile/android/app/src/main/kotlin/com/openlist/mobile/bridge/SyncBridge.kt`

并在 [MainActivity.kt](/root/AI/alist-encrypt-go/mobile/android/app/src/main/kotlin/com/openlist/mobile/MainActivity.kt) 注册。

### 4. 本地目录挂载 UI
新增：
- `mobile/lib/models/local_mount.dart`
- `mobile/lib/pages/local_mount/local_mount_page.dart`
- `mobile/lib/pages/local_mount/local_mount_controller.dart`

功能：
- 选择本地目录
- 快捷创建：
  - Download
  - DCIM
  - Pictures
  - Movies
- 列出当前已配置的本地挂载
- 创建 / 删除挂载
- 配置显示名称
- 配置只读

实现方式：
- Flutter 端先拿绝对路径
- 调用本地 OpenList 管理 API 创建 Local 存储
- 复用已有管理员登录态 / 本地服务状态
- 不额外引入第二套认证模型

OpenList API 以真实接口为准，落地时对接：
- `GET /api/admin/storage/list`
- `POST /api/admin/storage/create`
- `POST /api/admin/storage/delete`

要求：
- 先在当前 `mobile/openlist-lib`/本地 OpenList 集成版本里确认字段
- 实现者不得自行发明 Local 驱动 schema

### 5. 同步任务模型与 Flutter 管理层
新增：
- `mobile/lib/models/sync_task.dart`
- `mobile/lib/utils/sync_task_manager.dart`
- `mobile/lib/pages/sync/sync_task_list_page.dart`
- `mobile/lib/pages/sync/sync_task_edit_page.dart`
- `mobile/lib/pages/sync/sync_history_page.dart`

任务字段固定：
- `id`
- `name`
- `sourcePath`
- `targetPath`
- `fileExtensions`
- `excludeFolders`
- `intervalHours`
- `wifiOnly`
- `enabled`
- `deleteAfterSync`
- `preserveFolderStructure`
- `lastSyncTime`
- `lastSyncFileCount`
- `lastError`

本轮支持的文件类型预设：
- 照片：`.jpg .jpeg .png .heic .heif .webp .dng`
- 视频：`.mp4 .mov .avi .mkv .3gp .webm`
- 音频：`.mp3 .flac .wav .aac .ogg`
- 文档：`.pdf .doc .docx .xls .xlsx .ppt .pptx`
- 全部文件

### 6. Android 原生同步执行层
当前 `build.gradle` 已包含：
- `androidx.work:work-runtime-ktx:2.9.0`

新增原生文件：
- `mobile/android/app/src/main/kotlin/com/openlist/mobile/sync/SyncTask.kt`
- `mobile/android/app/src/main/kotlin/com/openlist/mobile/sync/SyncRecordStore.kt`
- `mobile/android/app/src/main/kotlin/com/openlist/mobile/sync/SyncWorker.kt`
- `mobile/android/app/src/main/kotlin/com/openlist/mobile/sync/SyncScheduler.kt`

#### 6.1 配置存储
任务配置：
- 放在 `AppConfig.syncTasksJson`

同步记录：
- 不启用 Room
- 使用单独 JSON 文件或轻量 SQLite/Room 封装均可，但本轮推荐 **JSON 文件持久化**
- 文件位置放在 `AppConfig.dataDir/sync_records.json`

记录字段：
- `taskId`
- `filePath`
- `fileSize`
- `lastModified`
- `syncedAt`
- `remotePath`

#### 6.2 增量判断
固定规则：
- `filePath + fileSize + lastModified`
- 不做 MD5/内容哈希
- 文件 metadata 未变化则视为已同步

#### 6.3 上传链路
统一通过本地加密代理：
- `PUT http://127.0.0.1:5344/api/fs/put`

请求要求：
- `File-Path` 使用目标 Alist 路径
- `Content-Length` 为源文件大小
- body 为本地文件原文
- 加密代理负责内容加密与文件名加密

绝不允许：
- 直接发到 `5244`
- 单独再造一套加密上传协议

#### 6.4 WorkManager 调度
使用：
- `PeriodicWorkRequest`
- `OneTimeWorkRequest`

约束：
- `wifiOnly=true` -> `NetworkType.UNMETERED`
- 否则 `NetworkType.CONNECTED`
- `setRequiresBatteryNotLow(true)`

不使用：
- AlarmManager
- 精确闹钟
- specialUse 前台服务

#### 6.5 Worker 执行步骤
`SyncWorker` 固定流程：
1. 读取任务配置
2. 校验存储权限
3. 校验本地 OpenList / 加密代理服务存活
4. 扫描源目录（递归）
5. 过滤扩展名
6. 排除目录
7. 对比本地同步记录
8. 逐个上传
9. 成功则写入同步记录
10. 汇总成功/失败数
11. 写入历史
12. 如启用 `deleteAfterSync`，仅删除成功上传文件

#### 6.6 失败语义
- 单文件失败不终止整个任务
- 记录失败项与最后错误
- Worker 返回 success/failure 只按整体是否执行完主流程决定
- 不做高复杂重试矩阵；依赖 WorkManager 自身重调度

### 7. 冲突、删除与目录结构策略
本轮固定：
- **冲突策略：覆盖同路径文件**
- **preserveFolderStructure=true** 时：
  - 目标路径 = `targetPath + relativePath`
- **preserveFolderStructure=false** 时：
  - 目标路径 = `targetPath + basename`
- **deleteAfterSync** 默认关闭
- 开启时必须在 UI 上做高风险提示
- 仅对已确认上传成功文件删除源文件

### 8. Flutter 页面集成位置
不扩张底部导航结构。

集成方式：
- 在现有加密页面或设置页增加两个入口：
  - 本地挂载
  - 同步任务

优先位置建议：
- `EncryptConfigPage` 下增加子入口
- 或 `SettingsScreen` 下增加入口

不把底部导航从现状改成 5 tab。

### 9. 更新灰屏与目录能力的关系
不把“检查更新灰屏”修复继续混入这一功能包。
该问题已单独收敛过，本轮只围绕本地目录与同步能力做实现。

## Test Plan

### Android 9-16 权限测试
- Android 9/10：
  - 进入本地挂载页时申请 `storage`
- Android 11/12：
  - 进入挂载流程时申请 `manageExternalStorage`
- Android 13/14/15/16：
  - 目录挂载仍走 `manageExternalStorage`
  - 媒体权限不主导目录挂载逻辑

### 本地挂载测试
- 选择 `Download`
- 选择 `DCIM`
- 通过快捷入口创建 Local 挂载
- 通过目录选择器创建 Local 挂载
- 挂载后 OpenList 内可浏览
- 删除挂载后列表消失

### 同步任务测试
- 创建照片同步任务：`DCIM -> /encrypt/photos`
- 创建下载目录同步任务：`Download -> /encrypt/downloads`
- 扩展名过滤生效
- 排除目录生效
- preserveFolderStructure 生效
- WiFi-only 生效
- 立即执行成功
- 周期任务能被调度
- 已同步文件不重复上传
- 修改过的文件会重新上传

### 上传与加密验证
- 上传请求实际发往 `127.0.0.1:5344`
- 云端文件内容为密文
- 云端文件名遵循当前加密规则
- 不绕过本地加密代理

### 状态与历史测试
- 同步历史能展示成功/失败次数
- 任务可暂停/恢复/删除
- 删除任务后对应周期 work 被取消

## Assumptions
- 当前项目为非 Google Play 分发，可使用 `MANAGE_EXTERNAL_STORAGE`
- 当前需求明确要求 A/B/C/D 全做，因此同步系统纳入本轮范围
- 本轮不做 SAF URI 持久化，不做双向同步，不做 MD5 增量判断，不做复杂冲突策略
- Local 挂载和同步认证统一复用本地 OpenList 现有管理能力，不引入第二套同步账号设计
- WorkManager 是唯一周期任务实现方式

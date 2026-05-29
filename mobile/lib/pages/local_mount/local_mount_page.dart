import 'dart:async';

import 'package:flutter/material.dart';
import 'package:get/get.dart';

import 'local_mount_controller.dart';
import '../../models/local_mount.dart';
import '../../utils/sync_task_manager.dart';
import '../../utils/storage_permission_helper.dart';

class LocalMountPage extends StatefulWidget {
  const LocalMountPage({super.key});

  @override
  State<LocalMountPage> createState() => _LocalMountPageState();
}

class _LocalMountPageState extends State<LocalMountPage> {
  late final LocalMountController controller;

  @override
  void initState() {
    super.initState();
    controller = Get.put(LocalMountController());
    controller.addListener(_onChanged);
    _initApiClient();
  }

  @override
  void dispose() {
    controller.removeListener(_onChanged);
    super.dispose();
  }

  void _onChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  /// 初始化 API 客户端（token 统一由 AdminAuthManager 获取）
  Future<void> _initApiClient() async {
    await controller.initApiClient();
    await controller.refreshBackendStatus();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('本地目录挂载'),
        actions: [
          if (!controller.isBackendReady)
            const Padding(
              padding: EdgeInsets.only(right: 12),
              child: Center(
                child: Icon(Icons.warning_amber, color: Colors.orange, size: 20),
              ),
            ),
        ],
      ),
      body: !controller.isLoaded
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                if (!controller.isBackendReady) _buildApiWarning(),
                const SizedBox(height: 8),
                _buildQuickMountSection(context, controller),
                const SizedBox(height: 16),
                if (controller.mounts.isEmpty)
                  Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.folder_off, size: 64, color: Theme.of(context).hintColor),
                        const SizedBox(height: 16),
                        Text(
                          '暂无本地挂载',
                          style: TextStyle(color: Theme.of(context).hintColor, fontSize: 16),
                        ),
                      ],
                    ),
                  )
                else
                  ...controller.mounts.map((mount) => _buildMountCard(context, mount, controller)),
              ],
            ),
    );
  }

  Widget _buildApiWarning() {
    final status = controller.backendStatus;
    return Card(
      color: Colors.orange.shade50,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.info_outline, color: Colors.orange),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    status.message,
                    style: const TextStyle(fontSize: 13),
                  ),
                ),
              ],
            ),
            if (status == LocalMountBackendStatus.authMissing ||
                status == LocalMountBackendStatus.authInvalid) ...[
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton.tonalIcon(
                    onPressed: () => _showAdminPasswordDialog(context),
                    icon: const Icon(Icons.lock_open),
                    label: const Text('输入现有密码'),
                  ),
                  TextButton.icon(
                    onPressed: () => controller.refreshBackendStatus(),
                    icon: const Icon(Icons.refresh),
                    label: const Text('重新检查'),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _showAdminPasswordDialog(BuildContext context) async {
    final textController = TextEditingController();
    var obscureText = true;
    var isSubmitting = false;
    String? errorText;
    await showDialog<void>(
      context: context,
      builder: (dialogContext) {
        return StatefulBuilder(
          builder: (_, setState) {
            return AlertDialog(
              title: const Text('输入 OpenList 管理员密码'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: textController,
                    enabled: !isSubmitting,
                    obscureText: obscureText,
                    decoration: InputDecoration(
                      labelText: '管理员密码',
                      helperText: '这里只校验并缓存当前已有密码，不会强制重置。',
                      errorText: errorText,
                      suffixIcon: IconButton(
                        onPressed: isSubmitting
                            ? null
                            : () {
                                setState(() {
                                  obscureText = !obscureText;
                                });
                              },
                        icon: Icon(
                          obscureText ? Icons.visibility : Icons.visibility_off,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: isSubmitting ? null : () => Navigator.of(dialogContext).pop(),
                  child: const Text('取消'),
                ),
                FilledButton(
                  onPressed: isSubmitting
                      ? null
                      : () async {
                          final password = textController.text.trim();
                          if (password.length < 4) {
                            setState(() {
                              errorText = '管理员密码至少需要 4 位';
                            });
                            return;
                          }
                          setState(() {
                            isSubmitting = true;
                            errorText = null;
                          });
                          final error = await controller
                              .verifyAndStoreAdminPassword(password)
                              .timeout(
                                const Duration(seconds: 15),
                                onTimeout: () => '管理员密码校验超时，请稍后重试。',
                              );
                          if (!dialogContext.mounted) return;
                          if (error == null) {
                            Navigator.of(dialogContext).pop();
                            ScaffoldMessenger.of(this.context).showSnackBar(
                              const SnackBar(
                                content: Text('管理员密码校验成功，已可用于本地挂载和同步。'),
                                backgroundColor: Colors.green,
                              ),
                            );
                            return;
                          }
                          setState(() {
                            isSubmitting = false;
                            errorText = error;
                          });
                        },
                  child: isSubmitting
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('校验并保存'),
                ),
              ],
            );
          },
        );
      },
    );
    textController.dispose();
  }

  Widget _buildQuickMountSection(BuildContext context, LocalMountController controller) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text('快捷创建', style: Theme.of(context).textTheme.titleMedium),
                TextButton.icon(
                  icon: const Icon(Icons.folder_open),
                  label: const Text('选择目录'),
                  onPressed: () => _handlePermissionAndAction(
                    context,
                    () => _doAddMountFromPicker(context),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _QuickMountChip(
                  label: 'Download',
                  icon: Icons.download,
                  onTap: () => _handlePermissionAndAction(
                    context,
                    () => _doAddQuickMount(context, 'Download', '/storage/emulated/0/Download'),
                  ),
                ),
                _QuickMountChip(
                  label: 'DCIM',
                  icon: Icons.camera_alt,
                  onTap: () => _handlePermissionAndAction(
                    context,
                    () => _doAddQuickMount(context, 'DCIM', '/storage/emulated/0/DCIM'),
                  ),
                ),
                _QuickMountChip(
                  label: 'Pictures',
                  icon: Icons.photo_library,
                  onTap: () => _handlePermissionAndAction(
                    context,
                    () => _doAddQuickMount(context, 'Pictures', '/storage/emulated/0/Pictures'),
                  ),
                ),
                _QuickMountChip(
                  label: 'Movies',
                  icon: Icons.movie,
                  onTap: () => _handlePermissionAndAction(
                    context,
                    () => _doAddQuickMount(context, 'Movies', '/storage/emulated/0/Movies'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _doAddQuickMount(BuildContext context, String name, String path) async {
    final error = await controller.addQuickMount(name, path);
    if (error != null && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(error), backgroundColor: Colors.orange),
      );
    } else if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('$name 挂载成功'),
          backgroundColor: Colors.green,
        ),
      );
    }
  }

  Future<void> _doAddMountFromPicker(BuildContext context) async {
    final error = await controller.addMountFromPicker();
    if (error != null && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(error), backgroundColor: Colors.orange),
      );
    } else if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('挂载成功'),
          backgroundColor: Colors.green,
        ),
      );
    }
  }

  Future<void> _handlePermissionAndAction(
    BuildContext context,
    Future<void> Function() action,
  ) async {
    final granted = await StoragePermissionHelper.requestWithRationale(context);
    if (granted) {
      await action();
    }
  }

  Widget _buildMountCard(
    BuildContext context,
    LocalMount mount,
    LocalMountController controller,
  ) {
    return Card(
      child: ListTile(
        leading: Icon(
          mount.readOnly ? Icons.folder : Icons.folder_open,
          color: mount.isSynced ? Colors.green : Theme.of(context).primaryColor,
        ),
        title: Row(
          children: [
            Expanded(child: Text(mount.name)),
            if (!mount.isSynced)
              const SizedBox(width: 8),
            if (!mount.isSynced)
              Icon(Icons.cloud_off, size: 16, color: Colors.grey.shade500),
            if (mount.isSynced)
              Icon(Icons.cloud_done, size: 16, color: Colors.green),
          ],
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              mount.path,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.bodySmall,
            ),
            if (mount.isSynced)
              Text(
                '已同步到 OpenList (ID: ${mount.storageId})',
                style: TextStyle(fontSize: 11, color: Colors.green.shade700),
              ),
          ],
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (mount.readOnly)
              const Tooltip(
                message: '只读',
                child: Icon(Icons.lock, size: 18, color: Colors.grey),
              ),
            IconButton(
              icon: const Icon(Icons.delete_outline, color: Colors.red),
              onPressed: () => _confirmDelete(context, mount, controller),
            ),
          ],
        ),
        onTap: () => _showEditDialog(context, mount, controller),
      ),
    );
  }

  void _confirmDelete(
    BuildContext context,
    LocalMount mount,
    LocalMountController controller,
  ) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('删除挂载'),
        content: Text('确定要删除挂载 "${mount.name}" 吗？${mount.isSynced ? "此操作也会从 OpenList 中删除对应存储。" : ""}'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () async {
              final ok = await controller.deleteMount(mount.id);
              if (ctx.mounted) Navigator.pop(ctx);
              if (!ok && context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('从 OpenList 删除存储失败，本地配置未移除'),
                    backgroundColor: Colors.orange,
                  ),
                );
              }
            },
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('删除'),
          ),
        ],
      ),
    );
  }

  void _showEditDialog(
    BuildContext context,
    LocalMount mount,
    LocalMountController controller,
  ) {
    final nameController = TextEditingController(text: mount.name);

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, _) => AlertDialog(
          title: const Text('编辑挂载'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameController,
                decoration: const InputDecoration(labelText: '显示名称'),
              ),
              const SizedBox(height: 12),
              const Text(
                '只读策略本轮未映射到 OpenList 实际权限，避免误导，暂不提供编辑。',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
              if (mount.isSynced)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(
                    'OpenList 存储 ID: ${mount.storageId}\n路径: ${mount.virtualPath ?? "-"}',
                    style: const TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('取消'),
            ),
            FilledButton(
              onPressed: () async {
                final error = await controller.updateMount(
                  mount.copyWith(
                    name: nameController.text,
                  ),
                );
                if (ctx.mounted) {
                  Navigator.pop(ctx);
                }
                if (error != null && context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(error),
                      backgroundColor: Colors.orange,
                    ),
                  );
                }
              },
              child: const Text('保存'),
            ),
          ],
        ),
      ),
    );
  }
}

class _QuickMountChip extends StatelessWidget {
  final String label;
  final IconData icon;
  final VoidCallback onTap;

  const _QuickMountChip({
    required this.label,
    required this.icon,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return ActionChip(
      avatar: Icon(icon, size: 18),
      label: Text(label),
      onPressed: onTap,
    );
  }
}

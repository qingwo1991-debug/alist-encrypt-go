import 'dart:ffi';

import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_svg/svg.dart';
import 'package:get/get.dart';

import '../../generated/l10n.dart';
import '../../generated_api.dart';
import '../../utils/intent_utils.dart';

class AppAboutDialog extends StatefulWidget {
  const AppAboutDialog({super.key});

  @override
  State<AppAboutDialog> createState() {
    return _AppAboutDialogState();
  }
}

class _AppAboutDialogState extends State<AppAboutDialog> {
  String _openlistVersion = "";
  String _version = "";
  int _versionCode = 0;

  Future<Void?> updateVer() async {
    _openlistVersion = await Android().getOpenListVersion();
    _version = await NativeBridge.common.getVersionName();
    _versionCode = await NativeBridge.common.getVersionCode();
    return null;
  }

  @override
  void initState() {
    updateVer().then((value) => setState(() {}));

    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    // 当前项目链接 - 直接链接到项目主页，不指定特定release版本
    const projectUrl = "https://github.com/qingwo1991-debug/alist-encrypt-go";

    // 上游项目链接（鸣谢）
    final openlistUrl =
        "https://github.com/OpenListTeam/OpenList/releases/tag/$_openlistVersion";
    const openlistMobileUrl = "https://github.com/OpenListTeam/OpenList-Mobile";

    return Dialog(
      child: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              SvgPicture.asset(
                "assets/openlist.svg",
                width: 72,
                height: 72,
              ),
              const SizedBox(height: 16),
              Text(
                "OpenList Encrypt",
                style: theme.textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                '$_version ($_versionCode)',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                "OpenList Android client with bundled encryption proxy",
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),

              // 项目信息
              Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  S.of(context).about,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              const SizedBox(height: 8),
              Card(
                margin: EdgeInsets.zero,
                child: ListTile(
                  leading: Icon(
                    Icons.lock_outline,
                    color: theme.colorScheme.primary,
                  ),
                  title: const Text("OpenList Encrypt"),
                  subtitle: Text(_version.isNotEmpty ? "v$_version" : ""),
                  trailing: const Icon(Icons.open_in_new, size: 20),
                  onTap: () {
                    IntentUtils.getUrlIntent(projectUrl).launchChooser("OpenList Encrypt");
                  },
                  onLongPress: () {
                    Clipboard.setData(ClipboardData(text: projectUrl));
                    Get.showSnackbar(GetSnackBar(
                      message: S.of(context).copiedToClipboard,
                      duration: const Duration(seconds: 1),
                    ));
                  },
                ),
              ),
              const SizedBox(height: 24),

              // 鸣谢部分
              Align(
                alignment: Alignment.centerLeft,
                child: Row(
                  children: [
                    Icon(
                      Icons.favorite,
                      size: 16,
                      color: Colors.red.shade400,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      "鸣谢",
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 4),
              Text(
                "本项目基于以下开源项目开发，感谢开发者的无私贡献！",
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 8),
              Card(
                margin: EdgeInsets.zero,
                child: ListTile(
                  leading: Icon(
                    Icons.folder_open,
                    color: theme.colorScheme.secondary,
                  ),
                  title: Text(S.of(context).openlist),
                  subtitle: Text(_openlistVersion.isNotEmpty
                      ? _openlistVersion
                      : "文件列表程序"),
                  trailing: const Icon(Icons.open_in_new, size: 20),
                  onTap: () {
                    IntentUtils.getUrlIntent(openlistUrl).launchChooser(S.of(context).openlist);
                  },
                  onLongPress: () {
                    Clipboard.setData(ClipboardData(text: openlistUrl));
                    Get.showSnackbar(GetSnackBar(
                      message: S.of(context).copiedToClipboard,
                      duration: const Duration(seconds: 1),
                    ));
                  },
                ),
              ),
              const SizedBox(height: 8),
              Card(
                margin: EdgeInsets.zero,
                child: ListTile(
                  leading: Icon(
                    Icons.phone_android,
                    color: theme.colorScheme.tertiary,
                  ),
                  title: Text(S.of(context).openlistMobile),
                  subtitle: const Text("移动客户端框架"),
                  trailing: const Icon(Icons.open_in_new, size: 20),
                  onTap: () {
                    IntentUtils.getUrlIntent(openlistMobileUrl).launchChooser(S.of(context).openlistMobile);
                  },
                  onLongPress: () {
                    Clipboard.setData(const ClipboardData(text: openlistMobileUrl));
                    Get.showSnackbar(GetSnackBar(
                      message: S.of(context).copiedToClipboard,
                      duration: const Duration(seconds: 1),
                    ));
                  },
                ),
              ),
              const SizedBox(height: 8),
              Card(
                margin: EdgeInsets.zero,
                child: ListTile(
                  leading: Icon(
                    Icons.description_outlined,
                    color: theme.colorScheme.outline,
                  ),
                  title: Text(S.of(context).openSourceLicenses),
                  subtitle: Text(S.of(context).viewThirdPartyLicenses),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () {
                    showLicensePage(
                      context: context,
                      applicationName: "OpenList Encrypt",
                      applicationVersion: '$_version ($_versionCode)',
                      applicationIcon: Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: SvgPicture.asset(
                          "assets/openlist.svg",
                          width: 48,
                          height: 48,
                        ),
                      ),
                    );
                  },
                ),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                child: FilledButton.tonal(
                  onPressed: () => Navigator.pop(context),
                  child: Text(S.of(context).ok),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

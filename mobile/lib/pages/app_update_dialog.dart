import 'package:flutter/material.dart';

import '../generated/l10n.dart';
import '../utils/update_checker.dart';
import '../utils/intent_utils.dart';
import 'app_update_progress_dialog.dart';

class AppUpdateDialog extends StatelessWidget {
  final String content;
  final String apkUrl;
  final String htmlUrl;
  final String version;

  const AppUpdateDialog(
      {super.key,
      required this.content,
      required this.apkUrl,
      required this.version,
      required this.htmlUrl});

  static bool _checking = false;

  static checkUpdateAndShowDialog(
      BuildContext context, ValueChanged<bool>? checkFinished) async {
    if (_checking) {
      return;
    }
    _checking = true;
    var loadingShown = false;
    final checker = UpdateChecker(owner: "qingwo1991-debug", repo: "alist-encrypt-go");
    try {
      if (context.mounted) {
        loadingShown = true;
        showDialog(
          context: context,
          barrierDismissible: false,
          builder: (dialogContext) => const AlertDialog(
            content: Row(
              children: [
                SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
                SizedBox(width: 12),
                Expanded(
                  child: Text('正在检查更新...'),
                ),
              ],
            ),
          ),
        );
      }

      await checker.downloadData();
      final hasNewVersion = await checker.hasNewVersion();

      checkFinished?.call(hasNewVersion);

      if (loadingShown && context.mounted) {
        Navigator.of(context, rootNavigator: true).pop();
        loadingShown = false;
      }

      if (hasNewVersion) {
        if (!context.mounted) return;
        showDialog(
          context: context,
          barrierDismissible: false,
          barrierColor: Colors.black.withOpacity(0.5),
          builder: (context) {
            return AppUpdateDialog(
              content: checker.getUpdateContent(),
              apkUrl: checker.getApkDownloadUrl(),
              htmlUrl: checker.getHtmlUrl(),
              version: checker.getDisplayVersion(),
            );
          },
        );
      }
    } catch (e) {
      checkFinished?.call(false);
      if (loadingShown && context.mounted) {
        Navigator.of(context, rootNavigator: true).pop();
        loadingShown = false;
      }
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('${S.of(context).updateFailed}: $e')),
      );
    } finally {
      _checking = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return AlertDialog(
      title: Row(
        children: [
          Icon(
            Icons.system_update,
            color: theme.colorScheme.primary,
            size: 28,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(S.of(context).newVersionFound),
          ),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: theme.colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(20),
              ),
              child: Text(
                version,
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: theme.colorScheme.onPrimaryContainer,
                ),
              ),
            ),
            const SizedBox(height: 16),
            
            Card(
              margin: EdgeInsets.zero,
              child: Padding(
                padding: const EdgeInsets.all(12),
              child: Text(
                  content.isEmpty ? '未提供更新说明，请直接前往发布页面查看。' : content,
                  style: theme.textTheme.bodyMedium,
                ),
              ),
            ),
            const SizedBox(height: 16),
            
            Text(
              S.of(context).selectDownloadMethod,
              style: theme.textTheme.titleSmall?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            
            Card(
              margin: EdgeInsets.zero,
              child: ListTile(
                leading: Icon(
                  Icons.download,
                  color: theme.colorScheme.primary,
                ),
                title: Text(S.of(context).directDownloadApk),
                subtitle: Text(S.of(context).directDownloadMethodDesc),
                trailing: const Icon(Icons.chevron_right),
                onTap: () async {
                  Navigator.pop(context);
                  showDialog(
                    context: context,
                    barrierDismissible: false,
                    barrierColor: Colors.black.withOpacity(0.5),
                    builder: (context) => AppUpdateProgressDialog(
                      apkUrl: apkUrl,
                      version: version,
                    ),
                  );
                },
              ),
            ),
            const SizedBox(height: 8),
            
            Card(
              margin: EdgeInsets.zero,
              child: ListTile(
                leading: Icon(
                  Icons.open_in_browser,
                  color: theme.colorScheme.secondary,
                ),
                title: Text(S.of(context).downloadApk),
                subtitle: Text(S.of(context).browserDownloadMethodDesc),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  Navigator.pop(context);
                  IntentUtils.getUrlIntent(apkUrl)
                      .launchChooser(S.of(context).downloadApk);
                },
              ),
            ),
            const SizedBox(height: 8),

            Card(
              margin: EdgeInsets.zero,
              child: ListTile(
                leading: Icon(
                  Icons.article_outlined,
                  color: theme.colorScheme.tertiary,
                ),
                title: Text(S.of(context).releasePage),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  Navigator.pop(context);
                  IntentUtils.getUrlIntent(htmlUrl)
                      .launchChooser(S.of(context).releasePage);
                },
              ),
            ),
          ],
        ),
      ),
      actions: <Widget>[
        TextButton(
          child: Text(S.of(context).cancel),
          onPressed: () {
            Navigator.pop(context);
          },
        ),
      ],
    );
  }
}

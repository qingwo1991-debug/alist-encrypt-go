import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';

import '../contant/native_bridge.dart';

/// 统一存储权限工具
///
/// Android 策略：
/// - 9-10：通过 permission_handler 请求 Permission.storage（真实系统弹窗）
/// - 11+：通过原生 StorageBridge 跳转系统设置页授予 MANAGE_EXTERNAL_STORAGE
class StoragePermissionHelper {
  StoragePermissionHelper._();

  /// 检查存储权限是否已授予
  static Future<bool> isGranted() async {
    if (!Platform.isAndroid) return true;
    try {
      return await NativeBridge.storageAccess.isStorageAccessGranted();
    } catch (_) {
      // 桥接不可用时 fallback 到 permission_handler
      return await Permission.storage.isGranted ||
          await Permission.manageExternalStorage.isGranted;
    }
  }
  
  /// 打开存储访问权限系统设置页面
  static Future<void> openManageAllFilesSettings() async {
    if (!Platform.isAndroid) return;
    try {
      await NativeBridge.storageAccess.openStorageAccessSettings();
    } catch (e) {
      debugPrint('Failed to open storage settings: $e');
    }
  }

  /// 检查 SDK 版本
  static Future<bool> _isAndroid11Plus() async {
    try {
      final sdk = await NativeBridge.common.getDeviceSdkInt();
      return sdk >= 30;
    } catch (_) {
      return true; // 安全默认
    }
  }

  /// 请求存储权限
  ///
  /// Android 9-10：通过 permission_handler 发起系统权限弹窗
  /// Android 11+：弹 rationale → 跳系统设置 → 返回后复查
  static Future<bool> requestWithRationale(BuildContext context) async {
    if (!Platform.isAndroid) return true;
    if (await isGranted()) return true;

    final is11Plus = await _isAndroid11Plus();

    if (is11Plus) {
      return _requestAndroid11Plus(context);
    } else {
      return _requestAndroid9And10(context);
    }
  }

  /// Android 11+：跳系统设置页
  static Future<bool> _requestAndroid11Plus(BuildContext context) async {
    if (!context.mounted) return false;
    final userAgreed = await _showRationaleDialog(context);
    if (!userAgreed) return false;

    await NativeBridge.storageAccess.openStorageAccessSettings();

    // 等待返回并多次复查
    await Future.delayed(const Duration(milliseconds: 500));
    for (int i = 0; i < 6; i++) {
      await Future.delayed(const Duration(milliseconds: 500));
      if (await isGranted()) return true;
    }
    return await isGranted();
  }

  /// Android 9-10：通过 permission_handler 真正发起权限请求
  static Future<bool> _requestAndroid9And10(BuildContext context) async {
    final status = await Permission.storage.request();
    if (status.isGranted) return true;

    // 永久拒绝时引导到设置
    if (status.isPermanentlyDenied && context.mounted) {
      await _showRationaleDialog(context);
      await openAppSettings();
      // 复查
      await Future.delayed(const Duration(milliseconds: 500));
      for (int i = 0; i < 6; i++) {
        await Future.delayed(const Duration(milliseconds: 500));
        if (await isGranted()) return true;
      }
    }
    return await isGranted();
  }

  static Future<bool> _showRationaleDialog(BuildContext context) {
    final completer = Completer<bool>();
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const Text('需要存储权限'),
        content: const Text(
          '读取手机照片、视频并执行加密备份需要存储权限。\n\n'
          '未配置前不会自动上传任何文件。\n\n'
          '点击"前往设置"后，请在系统设置中授予存储权限。',
        ),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              completer.complete(false);
            },
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx);
              completer.complete(true);
            },
            child: const Text('前往设置'),
          ),
        ],
      ),
    );
    return completer.future;
  }
}

import 'dart:convert';
import 'dart:developer';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:share_plus/share_plus.dart';

import '../contant/native_bridge.dart';

class ConfigExport {
  static const String _magicHeader = 'OPENLIST_CONFIG_BACKUP';
  static const int _configVersion = 1;

  /// 导出加密配置到文件，不包含 adminPassword
  static Future<String?> exportConfig() async {
    try {
      final dataDir = await NativeBridge.appConfig.getDataDir();
      final configFile = File('$dataDir/encrypt_config.json');

      if (!await configFile.exists()) {
        throw Exception('配置文件不存在');
      }

      final raw = await configFile.readAsString();
      final config = json.decode(raw) as Map<String, dynamic>;

      // 移除敏感字段
      config.remove('adminPassword');

      final export = {
        '_magic': _magicHeader,
        '_version': _configVersion,
        '_exportedAt': DateTime.now().toIso8601String(),
        'config': config,
      };

      final exportJson = json.encode(export);

      // 保存到下载目录
      final downloadDir = await _getExportDirectory();
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final exportFile = File('${downloadDir.path}/openlist_config_$timestamp.json');
      await exportFile.writeAsString(exportJson);

      log('配置已导出到: ${exportFile.path}');
      return exportFile.path;
    } catch (e) {
      log('配置导出失败: $e');
      rethrow;
    }
  }

  /// 分享导出的配置文件
  static Future<void> shareConfig(String filePath) async {
    await SharePlus.instance.share(ShareParams(files: [XFile(filePath)]));
  }

  /// 从文件导入配置
  static Future<void> importConfig() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['json'],
    );

    if (result == null || result.files.isEmpty) return;

    final filePath = result.files.single.path;
    if (filePath == null) return;

    await _doImport(filePath);
  }

  static Future<void> _doImport(String filePath) async {
    final file = File(filePath);
    if (!await file.exists()) {
      throw Exception('文件不存在');
    }

    final raw = await file.readAsString();
    final data = json.decode(raw) as Map<String, dynamic>;

    // 校验魔数
    if (data['_magic'] != _magicHeader) {
      throw Exception('不是有效的 OpenList 配置备份文件');
    }

    final version = data['_version'] as int? ?? 0;
    if (version > _configVersion) {
      throw Exception('配置文件版本($version)高于当前支持版本($_configVersion)');
    }

    final config = data['config'] as Map<String, dynamic>?;
    if (config == null || config.isEmpty) {
      throw Exception('配置文件内容为空');
    }

    // 读取当前配置，保留 adminPassword
    final dataDir = await NativeBridge.appConfig.getDataDir();
    final configFile = File('$dataDir/encrypt_config.json');

    String? existingPassword;
    if (await configFile.exists()) {
      try {
        final existingRaw = await configFile.readAsString();
        final existingConfig = json.decode(existingRaw) as Map<String, dynamic>;
        existingPassword = existingConfig['adminPassword'] as String?;
      } catch (_) {}
    }

    // 写入导入的配置，恢复 adminPassword
    if (existingPassword != null) {
      config['adminPassword'] = existingPassword;
    }

    final importJson = json.encode(config);
    await configFile.writeAsString(importJson);

    log('配置已导入，adminPassword 已${existingPassword != null ? "保留" : "跳过"}');
  }

  static Future<Directory> _getExportDirectory() async {
    final dir = Directory(
      '${Directory.systemTemp.path}/openlist_export',
    );
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    return dir;
  }
}

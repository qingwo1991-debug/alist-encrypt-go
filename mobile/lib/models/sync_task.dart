import 'dart:convert';

/// 同步任务模型
class SyncTask {
  final String id;
  String name;
  String sourcePath;
  String targetPath;
  List<String> fileExtensions;
  List<String> excludeFolders;
  int intervalHours;
  bool wifiOnly;
  bool enabled;
  bool deleteAfterSync;
  bool preserveFolderStructure;
  int uploadSpeedLimitKbps;
  int? lastSyncTime;
  int? lastSyncFileCount;
  String? lastError;

  SyncTask({
    required this.id,
    required this.name,
    required this.sourcePath,
    required this.targetPath,
    List<String>? fileExtensions,
    List<String>? excludeFolders,
    this.intervalHours = 1,
    this.wifiOnly = true,
    this.enabled = true,
    this.deleteAfterSync = false,
    this.preserveFolderStructure = true,
    this.uploadSpeedLimitKbps = 0,
    this.lastSyncTime,
    this.lastSyncFileCount,
    this.lastError,
  })  : fileExtensions = fileExtensions ?? [],
        excludeFolders = excludeFolders ?? [];

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'sourcePath': sourcePath,
        'targetPath': targetPath,
        'fileExtensions': fileExtensions,
        'excludeFolders': excludeFolders,
        'intervalHours': intervalHours,
        'wifiOnly': wifiOnly,
        'enabled': enabled,
        'deleteAfterSync': deleteAfterSync,
        'preserveFolderStructure': preserveFolderStructure,
        'uploadSpeedLimitKbps': uploadSpeedLimitKbps,
        'lastSyncTime': lastSyncTime,
        'lastSyncFileCount': lastSyncFileCount,
        'lastError': lastError,
      };

  factory SyncTask.fromJson(Map<String, dynamic> json) {
    return SyncTask(
      id: json['id'] as String,
      name: json['name'] as String,
      sourcePath: json['sourcePath'] as String,
      targetPath: json['targetPath'] as String,
      fileExtensions: (json['fileExtensions'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          [],
      excludeFolders: (json['excludeFolders'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          [],
      intervalHours: json['intervalHours'] as int? ?? 1,
      wifiOnly: json['wifiOnly'] as bool? ?? true,
      enabled: json['enabled'] as bool? ?? true,
      deleteAfterSync: json['deleteAfterSync'] as bool? ?? false,
      preserveFolderStructure:
          json['preserveFolderStructure'] as bool? ?? true,
      uploadSpeedLimitKbps: json['uploadSpeedLimitKbps'] as int? ?? 0,
      lastSyncTime: json['lastSyncTime'] as int?,
      lastSyncFileCount: json['lastSyncFileCount'] as int?,
      lastError: json['lastError'] as String?,
    );
  }

  /// 从 JSON 数组字符串解析任务列表
  static List<SyncTask> listFromJsonString(String jsonString) {
    if (jsonString.isEmpty || jsonString == '[]') return [];
    final list = json.decode(jsonString) as List<dynamic>;
    return list
        .map((e) => SyncTask.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// 将任务列表序列化为 JSON 数组字符串
  static String listToJsonString(List<SyncTask> tasks) {
    return json.encode(tasks.map((t) => t.toJson()).toList());
  }

  /// 文件类型预设
  static const Map<String, List<String>> presetExtensions = {
    '照片': ['.jpg', '.jpeg', '.png', '.heic', '.heif', '.webp', '.dng'],
    '视频': ['.mp4', '.mov', '.avi', '.mkv', '.3gp', '.webm'],
    '音频': ['.mp3', '.flac', '.wav', '.aac', '.ogg'],
    '文档': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
  };

  static const String allFilesLabel = '全部文件';

  /// 应用预设扩展名
  void applyPreset(String presetName) {
    if (presetName == allFilesLabel) {
      fileExtensions = [];
      return;
    }
    final preset = presetExtensions[presetName];
    if (preset != null) {
      fileExtensions = List.from(preset);
    }
  }

  /// 合并预设扩展名
  void mergePreset(String presetName) {
    if (presetName == allFilesLabel) {
      fileExtensions = [];
      return;
    }
    final preset = presetExtensions[presetName];
    if (preset != null) {
      final merged = <String>{...fileExtensions, ...preset};
      fileExtensions = merged.toList();
    }
  }
}

import 'dart:convert';

/// 本地目录挂载模型
class LocalMount {
  final String id;
  final String name;
  final String path;
  final bool readOnly;
  final int createdAt;
  /// OpenList 存储 ID（调用创建 API 后获得，null 表示尚未同步到 OpenList）
  final int? storageId;
  /// 挂载在 OpenList 中的虚拟路径，如 /本地存储/Download
  final String? virtualPath;

  LocalMount({
    required this.id,
    required this.name,
    required this.path,
    this.readOnly = false,
    int? createdAt,
    this.storageId,
    this.virtualPath,
  }) : createdAt = createdAt ?? DateTime.now().millisecondsSinceEpoch;

  /// 是否已在 OpenList 中成功创建存储
  bool get isSynced => storageId != null;

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'path': path,
        'readOnly': readOnly,
        'createdAt': createdAt,
        'storageId': storageId,
        'virtualPath': virtualPath,
      };

  factory LocalMount.fromJson(Map<String, dynamic> json) => LocalMount(
        id: json['id'] as String,
        name: json['name'] as String,
        path: json['path'] as String,
        readOnly: json['readOnly'] as bool? ?? false,
        createdAt: json['createdAt'] as int?,
        storageId: json['storageId'] as int?,
        virtualPath: json['virtualPath'] as String?,
      );

  LocalMount copyWith({
    String? id,
    String? name,
    String? path,
    bool? readOnly,
    int? createdAt,
    int? storageId,
    String? virtualPath,
  }) =>
      LocalMount(
        id: id ?? this.id,
        name: name ?? this.name,
        path: path ?? this.path,
        readOnly: readOnly ?? this.readOnly,
        createdAt: createdAt ?? this.createdAt,
        storageId: storageId ?? this.storageId,
        virtualPath: virtualPath ?? this.virtualPath,
      );

  /// 从 JSON 数组字符串解析挂载列表
  static List<LocalMount> listFromJsonString(String jsonString) {
    if (jsonString.isEmpty || jsonString == '[]') return [];
    final list = json.decode(jsonString) as List<dynamic>;
    return list
        .map((e) => LocalMount.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// 将挂载列表序列化为 JSON 数组字符串
  static String listToJsonString(List<LocalMount> mounts) {
    return json.encode(mounts.map((m) => m.toJson()).toList());
  }
}

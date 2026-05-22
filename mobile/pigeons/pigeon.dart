import 'package:pigeon/pigeon.dart';

@HostApi()
abstract class AppConfig {
  bool isWakeLockEnabled();

  void setWakeLockEnabled(bool enabled);

  bool isStartAtBootEnabled();

  void setStartAtBootEnabled(bool enabled);

  bool isAutoCheckUpdateEnabled();

  void setAutoCheckUpdateEnabled(bool enabled);

  bool isAutoOpenWebPageEnabled();

  void setAutoOpenWebPageEnabled(bool enabled);

  String getDataDir();

  void setDataDir(String dir);

  bool isSilentJumpAppEnabled();

  void setSilentJumpAppEnabled(bool enabled);
}

@HostApi()
abstract class NativeCommon {
  bool startActivityFromUri(String intentUri);

  int getDeviceSdkInt();

  String getDeviceCPUABI();

  String getVersionName();

  int getVersionCode();

  void toast(String msg);

  void longToast(String msg);
}

@HostApi()
abstract class Android {
  void addShortcut();

  void startService();

  void setAdminPwd(String pwd);

  int getOpenListHttpPort();

  bool isRunning();

  String getOpenListVersion();
}

@FlutterApi()
abstract class Event {
  void onServiceStatusChanged(bool isRunning);

  void onServerLog(
    int level,
    String time,
    String log,
  );
}

/// 加密代理管理接口
@HostApi()
abstract class EncryptProxy {
  /// 初始化加密代理
  void initEncryptProxy(String configPath);
  
  /// 启动加密代理
  void startEncryptProxy();
  
  /// 停止加密代理
  void stopEncryptProxy();
  
  /// 重启加密代理
  void restartEncryptProxy();
  
  /// 检查加密代理是否运行中
  bool isEncryptProxyRunning();
  
  /// 获取代理端口
  int getEncryptProxyPort();
  
  /// 设置 Alist 主机
  void setEncryptAlistHost(String host, int port, bool https);
  
  /// 设置代理端口
  void setEncryptProxyPort(int port);
  
  /// 设置 H2C 开关（HTTP/2 Cleartext）
  void setEncryptEnableH2C(bool enable);
  
  /// 获取 H2C 开关状态
  bool getEncryptEnableH2C();

  /// 设置 DB_EXPORT 同步配置
  void setEncryptDbExportSyncConfig(
    bool enable,
    String baseUrl,
    int intervalSeconds,
    bool authEnabled,
    String username,
    String password,
  );

  /// 设置网络策略
  void setEncryptNetworkPolicy(
    int upstreamTimeoutSeconds,
    int probeTimeoutSeconds,
    int probeBudgetSeconds,
    int upstreamBackoffSeconds,
    bool enableLocalBypass,
  );
  
  /// 添加加密路径
  void addEncryptPath(String path, String password, String encType, bool encName, String encSuffix);
  
  /// 更新加密路径
  void updateEncryptPath(int index, String path, String password, String encType, bool encName, String encSuffix, bool enable);
  
  /// 删除加密路径
  void removeEncryptPath(int index);
  
  /// 获取加密路径列表（JSON格式）
  String getEncryptPathsJson();
  
  /// 获取完整配置（JSON格式）
  String getEncryptConfigJson();
  
  /// 设置管理密码
  void setEncryptAdminPassword(String password);
  
  /// 验证管理密码
  bool verifyEncryptAdminPassword(String password);
}

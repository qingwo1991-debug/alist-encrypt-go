import 'package:openlist_mobile/pages/openlist/log_level_view.dart';
import 'package:flutter/material.dart';

class Log {
  final int level;
  final String time;
  final String content;

  Log(this.level, this.time, this.content);
}

class LogListView extends StatefulWidget {
  const LogListView({Key? key, required this.logs, this.controller}) : super(key: key);

  final List<Log> logs;
  final ScrollController? controller;

  @override
  State<LogListView> createState() => _LogListViewState();
}

class _LogListViewState extends State<LogListView> {
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      itemCount: widget.logs.length,
      controller: widget.controller,
      // 性能优化：添加 cacheExtent 提前缓存不可见区域的 Widget
      cacheExtent: 500,
      // 性能优化：设置固定高度，减少布局计算开销
      itemExtent: 72,
      itemBuilder: (context, index) {
        final log = widget.logs[index];
        return ListTile(
          dense: true,
          // 性能优化：使用普通 Text 替代 SelectableText，减少组件开销
          title: Text(
            log.content,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          subtitle: Text(log.time),
          leading: LogLevelView(level: log.level),
        );
      },
    );
  }
}

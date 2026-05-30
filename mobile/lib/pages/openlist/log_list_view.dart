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
  final TextEditingController _filterController = TextEditingController();
  String _filter = '';

  @override
  void dispose() {
    _filterController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final keyword = _filter.trim().toLowerCase();
    final logs = keyword.isEmpty
        ? widget.logs
        : widget.logs.where((log) {
            final haystack = '${log.time} ${log.content}'.toLowerCase();
            return haystack.contains(keyword);
          }).toList();

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 8),
          child: TextField(
            controller: _filterController,
            decoration: InputDecoration(
              prefixIcon: const Icon(Icons.search),
              hintText: '按 traceId / taskId / mountId / 关键字过滤',
              suffixIcon: _filter.isEmpty
                  ? null
                  : IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () {
                        _filterController.clear();
                        setState(() => _filter = '');
                      },
                    ),
            ),
            onChanged: (value) => setState(() => _filter = value),
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: logs.length,
            controller: widget.controller,
            cacheExtent: 500,
            itemExtent: 72,
            itemBuilder: (context, index) {
              final log = logs[index];
              return ListTile(
                dense: true,
                title: Text(
                  log.content,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                subtitle: Text(log.time),
                leading: LogLevelView(level: log.level),
              );
            },
          ),
        ),
      ],
    );
  }
}

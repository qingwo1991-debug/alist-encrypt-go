import 'package:flutter/material.dart';

final GlobalKey<NavigatorState> rootNavigatorKey = GlobalKey<NavigatorState>();
final GlobalKey<ScaffoldMessengerState> rootScaffoldMessengerKey =
    GlobalKey<ScaffoldMessengerState>();

ScaffoldFeatureController<SnackBar, SnackBarClosedReason>? showGlobalSnackBar(
  SnackBar snackBar, {
  bool replaceCurrent = false,
}) {
  final messenger = rootScaffoldMessengerKey.currentState;
  if (messenger == null) {
    return null;
  }
  if (replaceCurrent) {
    messenger.hideCurrentSnackBar();
  }
  return messenger.showSnackBar(snackBar);
}


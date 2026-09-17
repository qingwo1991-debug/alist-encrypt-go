import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/dir_sync_remote_session.dart';

class _StubAdapter implements HttpClientAdapter {
  _StubAdapter(this.handler);
  final ResponseBody Function(RequestOptions options) handler;
  final List<RequestOptions> requests = [];

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    requests.add(options);
    return handler(options);
  }

  @override
  void close({bool force = false}) {}
}

Map<String, dynamic> _ok(dynamic data) => {'code': 0, 'data': data};

void main() {
  group('DirSyncRemoteSession origin parsing', () {
    test('normalizes to scheme/host/port only', () {
      final session = DirSyncRemoteSession('http://example.com:8080/sub?q=1#f');
      expect(session.origin.toString(), 'http://example.com:8080');
      session.dispose();
    });

    test('rejects credentials, non-http schemes and bare hosts', () {
      for (final bad in [
        'http://user:pass@example.com',
        'ftp://example.com',
        'example.com',
        'http://',
        'http://example.com:0',
      ]) {
        expect(
          () => DirSyncRemoteSession(bad),
          throwsFormatException,
          reason: bad,
        );
      }
    });
  });

  group('DirSyncRemoteSession auth', () {
    test('login stores jwtToken and sends it as Bearer on overview', () async {
      final adapter = _StubAdapter((options) {
        if (options.uri.path == '/enc-api/login') {
          return ResponseBody.fromString(
            jsonEncode(_ok({'jwtToken': 'jwt-1'})),
            200,
            headers: {
              Headers.contentTypeHeader: [Headers.jsonContentType],
            },
          );
        }
        return ResponseBody.fromString(
          jsonEncode(_ok({'scan_configured': true})),
          200,
          headers: {
            Headers.contentTypeHeader: [Headers.jsonContentType],
          },
        );
      });
      final session = DirSyncRemoteSession(
        'http://example.com:8080',
        dio: Dio()..httpClientAdapter = adapter,
      );
      await session.login('admin', 'secret');
      expect(session.isAuthenticated, isTrue);

      final overview = await session.overview();
      expect(overview['scan_configured'], isTrue);
      expect(adapter.requests.last.uri.toString(),
          'http://example.com:8080/api/encrypt/dir-sync/overview');
      expect(adapter.requests.last.headers['Authorization'], 'Bearer jwt-1');
      session.dispose();
    });

    test('failed login keeps unauthenticated and reports error', () async {
      final adapter = _StubAdapter(
        (options) => ResponseBody.fromString(
          jsonEncode({'code': 500, 'msg': 'passwword error'}),
          200,
          headers: {
            Headers.contentTypeHeader: [Headers.jsonContentType],
          },
        ),
      );
      final session = DirSyncRemoteSession(
        'http://example.com:8080',
        dio: Dio()..httpClientAdapter = adapter,
      );
      await expectLater(session.login('admin', 'bad'), throwsException);
      expect(session.isAuthenticated, isFalse);
      session.dispose();
    });

    test('401 clears token so later calls require re-login', () async {
      var status = 200;
      final adapter = _StubAdapter((options) {
        if (options.uri.path == '/enc-api/login') {
          return ResponseBody.fromString(
            jsonEncode(_ok({'jwtToken': 'jwt-1'})),
            200,
            headers: {
              Headers.contentTypeHeader: [Headers.jsonContentType],
            },
          );
        }
        return ResponseBody.fromString(
          jsonEncode(status == 401
              ? {'code': 401, 'msg': 'user unlogin'}
              : _ok(const <String, dynamic>{})),
          status,
          headers: {
            Headers.contentTypeHeader: [Headers.jsonContentType],
          },
        );
      });
      final session = DirSyncRemoteSession(
        'http://example.com:8080',
        dio: Dio()..httpClientAdapter = adapter,
      );
      await session.login('admin', 'secret');
      status = 401;
      await expectLater(session.overview(), throwsException);
      expect(session.isAuthenticated, isFalse);
      session.dispose();
    });

    test('redirect responses are rejected, not followed', () async {
      final adapter = _StubAdapter((options) {
        if (options.uri.path == '/enc-api/login') {
          return ResponseBody.fromString(
            jsonEncode(_ok({'jwtToken': 'jwt-1'})),
            200,
            headers: {
              Headers.contentTypeHeader: [Headers.jsonContentType],
            },
          );
        }
        return ResponseBody.fromString('', 302, headers: {
          'location': ['http://example.com:8080/login']
        });
      });
      final session = DirSyncRemoteSession(
        'http://example.com:8080',
        dio: Dio()..httpClientAdapter = adapter,
      );
      await session.login('admin', 'secret');
      await expectLater(session.overview(), throwsException);
      expect(session.isAuthenticated, isTrue);
      session.dispose();
    });

    test('logout clears token and cancels in-flight requests', () async {
      final adapter = _StubAdapter((options) async {
        await Future<void>.delayed(const Duration(milliseconds: 50));
        return ResponseBody.fromString(
          jsonEncode(_ok(const <String, dynamic>{})),
          200,
          headers: {
            Headers.contentTypeHeader: [Headers.jsonContentType],
          },
        );
      });
      final session = DirSyncRemoteSession(
        'http://example.com:8080',
        dio: Dio()..httpClientAdapter = adapter,
      );
      await session.login('admin', 'secret');
      final pending = session.overview();
      session.logout();
      await expectLater(pending, throwsException);
      expect(session.isAuthenticated, isFalse);
      session.dispose();
    });
  });
}

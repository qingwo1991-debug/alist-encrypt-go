import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/openlist_api_client.dart';

void main() {
  group('OpenListApiClient', () {
    test('listStorages uses paged admin endpoint', () async {
      late RequestOptions captured;
      final dio = Dio()
        ..interceptors.add(
          InterceptorsWrapper(
            onRequest: (options, handler) {
              captured = options;
              handler.resolve(
                Response(
                  requestOptions: options,
                  data: {
                    'code': 200,
                    'data': {
                      'content': [
                        {'id': 1, 'mount_path': '/local/download'}
                      ]
                    }
                  },
                ),
              );
            },
          ),
        );

      final client = OpenListApiClient(
        baseUrl: 'http://127.0.0.1:5244',
        dio: dio,
        tokenProvider: () async => 'token',
      );

      final storages = await client.listStorages();

      expect(captured.method, 'GET');
      expect(
        captured.uri.toString(),
        'http://127.0.0.1:5244/api/admin/storage/list?page=1&per_page=1000',
      );
      expect(storages.single['mount_path'], '/local/download');
    });

    test('createLocalStorage sends mount path and root_folder_path separately', () async {
      late RequestOptions captured;
      final dio = Dio()
        ..interceptors.add(
          InterceptorsWrapper(
            onRequest: (options, handler) {
              captured = options;
              handler.resolve(
                Response(
                  requestOptions: options,
                  data: {
                    'code': 200,
                    'data': {'id': 42}
                  },
                ),
              );
            },
          ),
        );

      final client = OpenListApiClient(
        baseUrl: 'http://127.0.0.1:5244',
        dio: dio,
        tokenProvider: () async => 'token',
      );

      await client.createLocalStorage(
        localPath: '/storage/emulated/0/DCIM',
        name: 'DCIM',
        mountPath: '/local/dcim',
      );

      final body = captured.data as Map<String, dynamic>;
      final addition = body['addition'] as String;

      expect(captured.method, 'POST');
      expect(
        captured.uri.toString(),
        'http://127.0.0.1:5244/api/admin/storage/create',
      );
      expect(body['mount_path'], '/local/dcim');
      expect(body['driver'], 'Local');
      expect(addition, contains('"root_folder_path":"/storage/emulated/0/DCIM"'));
      expect(addition, isNot(contains('"/local/dcim"')));
    });

    test('deleteStorage sends id in query string', () async {
      late RequestOptions captured;
      final dio = Dio()
        ..interceptors.add(
          InterceptorsWrapper(
            onRequest: (options, handler) {
              captured = options;
              handler.resolve(
                Response(
                  requestOptions: options,
                  data: {'code': 200},
                ),
              );
            },
          ),
        );

      final client = OpenListApiClient(
        baseUrl: 'http://127.0.0.1:5244',
        dio: dio,
        tokenProvider: () async => 'token',
      );

      final ok = await client.deleteStorage(123);

      expect(ok, isTrue);
      expect(captured.method, 'POST');
      expect(
        captured.uri.toString(),
        'http://127.0.0.1:5244/api/admin/storage/delete?id=123',
      );
      expect(captured.data, isNull);
    });

    test('getStorage uses query string id', () async {
      late RequestOptions captured;
      final dio = Dio()
        ..interceptors.add(
          InterceptorsWrapper(
            onRequest: (options, handler) {
              captured = options;
              handler.resolve(
                Response(
                  requestOptions: options,
                  data: {
                    'code': 200,
                    'data': {'id': 5, 'remark': 'DCIM'}
                  },
                ),
              );
            },
          ),
        );

      final client = OpenListApiClient(
        baseUrl: 'http://127.0.0.1:5244',
        dio: dio,
        tokenProvider: () async => 'token',
      );

      final storage = await client.getStorage(5);

      expect(captured.method, 'GET');
      expect(
        captured.uri.toString(),
        'http://127.0.0.1:5244/api/admin/storage/get?id=5',
      );
      expect(storage?['remark'], 'DCIM');
    });

    test('updateStorage posts full storage payload', () async {
      late RequestOptions captured;
      final dio = Dio()
        ..interceptors.add(
          InterceptorsWrapper(
            onRequest: (options, handler) {
              captured = options;
              handler.resolve(
                Response(
                  requestOptions: options,
                  data: {'code': 200},
                ),
              );
            },
          ),
        );

      final client = OpenListApiClient(
        baseUrl: 'http://127.0.0.1:5244',
        dio: dio,
        tokenProvider: () async => 'token',
      );

      final ok = await client.updateStorage({
        'id': 5,
        'mount_path': '/local/dcim',
        'driver': 'Local',
        'remark': 'New Name',
        'addition': '{"root_folder_path":"/storage/emulated/0/DCIM"}',
      });

      expect(ok, isTrue);
      expect(captured.method, 'POST');
      expect(
        captured.uri.toString(),
        'http://127.0.0.1:5244/api/admin/storage/update',
      );
      expect((captured.data as Map<String, dynamic>)['remark'], 'New Name');
    });
  });
}

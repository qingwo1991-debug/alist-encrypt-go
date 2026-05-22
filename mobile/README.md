# OpenList Encrypt

Android client for OpenList with bundled encryption proxy support.

## Build

```bash
cd mobile/openlist-lib/scripts
./init_openlist.sh
./init_gomobile.sh
./gobind.sh

cd ../../..
cd mobile
flutter pub get
flutter build apk --release --split-per-abi
```

Before the first release build, generate the local reusable signing keystore:

```bash
cd mobile/android/app
keytool -genkeypair -v \
  -keystore openlist-local.keystore \
  -storepass openlistlocal \
  -keypass openlistlocal \
  -alias openlistlocal \
  -keyalg RSA \
  -keysize 2048 \
  -validity 36500 \
  -dname "CN=OpenList Encrypt, OU=Mobile, O=OpenList Encrypt, L=Shanghai, ST=Shanghai, C=CN"
```

If `android/app/openlist-local.keystore` exists, release builds will use it by
default so new APKs can overwrite previous installs. If you provide your own
signing values in `local.properties`, those take precedence.

## Syncing App Layer From OpenList-Mobile

To update the Flutter/Android app layer from the local upstream checkout while
keeping this repo's local overrides for permissions, download behavior, and web
screen fixes:

```bash
cd mobile/scripts
./sync_openlist_mobile.sh /root/AI/OpenList-Mobile
```

The script syncs the app layer from `OpenList-Mobile` and then restores the
local override files tracked in this repository.

## Notes

- Android only.
- APK update assets are matched by ABI.
- `mobile/openlist-lib` remains the current Go binding path.

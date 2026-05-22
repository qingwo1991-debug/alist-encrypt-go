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

## Notes

- Android only.
- APK update assets are matched by ABI.
- `mobile/openlist-lib` remains the current Go binding path.

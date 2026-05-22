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

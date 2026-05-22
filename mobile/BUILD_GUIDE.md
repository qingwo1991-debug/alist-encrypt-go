# Build Guide

## Requirements

- Flutter 3.24+
- Go 1.23+
- Android SDK 35
- Android NDK 25.2.9519653
- `gomobile`

## Android Library

```bash
cd mobile/openlist-lib/scripts
./init_openlist.sh
./init_gomobile.sh
./gobind.sh
```

This populates `mobile/android/app/libs/` with the AAR used by the app.

## APK

```bash
cd mobile
flutter pub get
flutter build apk --release --split-per-abi
```

## Release Assets

- `OpenList-Encrypt-<version>_arm64-v8a.apk`
- `OpenList-Encrypt-<version>_armeabi-v7a.apk`
- `OpenList-Encrypt-<version>_x86_64.apk`


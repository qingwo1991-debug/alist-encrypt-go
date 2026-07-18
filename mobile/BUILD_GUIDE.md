# Build Guide

## Requirements

- Flutter 3.24+
- Go 1.23+
- Android SDK 35
- Android NDK 25.2.9519653
- `gomobile`

## Android Library

```bash
cd mobile/enc-webui
npm ci
npm run build

cd ../openlist-lib
bash scripts/install_enc_web.sh

cd scripts
./init_gomobile.sh
./gobind.sh release all
```

This installs the reviewed mobile Web UI and populates
`mobile/android/app/libs/` with the AAR used by the app. The `init_openlist.sh`
and `init_web.sh` scripts are only for an explicit upstream refresh and are not
part of a reproducible release build.

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

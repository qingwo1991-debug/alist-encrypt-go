# Repository Guidelines

## Project Structure & Module Organization
The root app is an Android-only Flutter client. Main UI code lives in `lib/`, with feature pages under `lib/pages/`, shared helpers in `lib/utils/`, and generated localization/API files in `lib/generated*`. Flutter tests live in `test/`.

`openlist-lib/` contains the bundled Go backend and encryption proxy. The mobile-facing package is under `openlist-lib/openlistlib/`; broader server code lives in `openlist-lib/cmd/`, `openlist-lib/internal/`, and `openlist-lib/pkg/`.

Native platform code is in `android/`. Treat Pigeon outputs and Flutter intl outputs as generated unless the change specifically targets generation.

## Build, Test, and Development Commands
- `flutter pub get`: install Dart and Flutter dependencies.
- `flutter analyze`: run the Dart static analyzer with `flutter_lints`.
- `flutter test`: run Flutter widget and unit tests from `test/`.
- `bash test/run_webdav_tests.sh`: run the focused Go WebDAV regression test.
- `cd openlist-lib && go test ./...`: run Go tests for the backend; skip or narrow packages if CGO or external services block local runs.
- `cd openlist-lib/scripts && ./init_gomobile.sh && ./gobind.sh`: initialize gomobile and rebuild the Android Go binding.
- `cd enc-webui && pnpm install && pnpm dev`: start the web UI in Vite dev mode.
- `cd enc-webui && pnpm build && pnpm lint && pnpm coverage`: build, lint, and run Vitest coverage for the web UI.

## Coding Style & Naming Conventions
Follow existing style per stack. Dart uses `flutter_lints`; keep files `snake_case.dart` and classes `PascalCase`. Vue/TypeScript uses 2-space indentation, single quotes, no semicolons, and 150-char lines per `enc-webui/.prettierrc`. Go code should stay `gofmt`-formatted with idiomatic package names and table-driven tests where practical.

## Testing Guidelines
Add Flutter tests in `test/` with names ending in `_test.dart`. Add Go tests beside the package under test with `_test.go`. For web UI work, prefer Vitest coverage where available. Cover encryption routing, WebDAV behavior, and platform bridge changes with an automated test or a documented manual check.

## Commit & Pull Request Guidelines
Recent history uses Conventional Commit prefixes such as `feat(encrypt): ...`, `feat(routing): ...`, and `chore(ui): ...`. Keep commits scoped and imperative. PRs should explain the user-visible change, list verification commands run, and include screenshots for UI changes.

## Security & Configuration Tips
Do not commit real server URLs, credentials, or encryption passwords. Review generated bindings and config changes carefully, especially anything affecting ports `5244` and `5344`, WebDAV behavior, or mobile storage paths.

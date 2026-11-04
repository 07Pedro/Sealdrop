# Sealdrop for Android

The phone's side of Sealdrop (Android 17 or newer, Kotlin). See [../docs/PROTOCOL.md](../docs/PROTOCOL.md).

**State: the format core is done** (`core/`, an Android library): sealing and opening files, manifests, receipts and
the pairing checks. **The app's screens are drafted** (`app/`), with made-up data only: nothing behind them works yet.
Uploads, receipts, the handover between apps and the camera come next.

`core` uses only what Android 17 has built in: `android.crypto.hpke` for HPKE, and Conscrypt for X25519, Ed25519,
ECDSA P-256, ChaCha20-Poly1305 and HMAC. No other library.

| File | What |
|---|---|
| `Json.kt`, `Encoding.kt` | §3: strict JSON (I-JSON), base64url, hex, base32 |
| `Hkdf.kt` | HKDF-SHA256 on HMAC |
| `Sizes.kt` | §4: padded lengths, possible sizes, the largest delivery |
| `Keys.kt`, `HpkeSuite.kt` | §2, §3: X25519 for HPKE, P-256 (`r ‖ s`, low-S; the signer takes a Keystore key), Ed25519, key IDs |
| `Sealed.kt` | §4: writing a sealed file (streamed piece by piece), and reading it step by step |
| `Manifests.kt` | §5, §7: content, the bundle and pairing manifests, names, the delivery digest |
| `Reading.kt` | §4, §5, §7: uploads, deliveries, pairing requests and receipts, in the order of checks |
| `Receipts.kt`, `Pairing.kt` | §6, §7: the receipts as the phone reads them; the offer, the MAC, the fingerprint |

The collector's side of reading (uploads, deliveries, pairing requests) is here too, so that both sides are tested
against the same files.

## The app (`app/`)

| File | What |
|---|---|
| `ui/Model.kt` | what the screens show, and the warnings of §9.3 in plain words |
| `ui/Pairing.kt` | welcome, scanning the QR code, naming the phone, comparing the code (§7), approving an app (§8) |
| `ui/Status.kt` | the main screen (what was sent and picked up, warnings, holds, refused deliveries) and the settings |
| `ui/Parts.kt`, `ui/theme/` | shared pieces and the colours |

The icons are [Material Symbols](https://github.com/google/material-design-icons) (Apache 2.0), fetched as vector
drawables with `tools/icons.py`. The app icon, an envelope with a wax seal, was drawn for this project.

To see every screen, `PreviewShotsTest` draws them with made-up data and saves them as images:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -e class app.sealdrop.ui.PreviewShotsTest app.sealdrop.test/androidx.test.runner.AndroidJUnitRunner
adb pull /sdcard/Android/data/app.sealdrop/files/previews
adb uninstall app.sealdrop.test
adb uninstall app.sealdrop
```

## Tests of the format core

They run on a device or emulator with Android 17 (API 37), against the shared test files in
[../testvectors](../testvectors), which are packed into the test app.

```sh
./gradlew :core:assembleDebugAndroidTest
adb install -r core/build/outputs/apk/androidTest/debug/core-debug-androidTest.apk
adb shell am instrument -w app.sealdrop.core.test/androidx.test.runner.AndroidJUnitRunner
adb uninstall app.sealdrop.core.test
```

- `CasesTest` opens every sealed file in `testvectors/` as `cases.json` says; `BasicsTest` and `ManifestsTest` run the
  vectors (JSON, base64url, HKDF, RFC 9180's HPKE vector, signatures, sizes, names, manifests, pairing, offers).
- `SealTest`: Sealdrop seals and opens its own files, also with a signing key in the Android Keystore.
- `CrossFilesTest` writes sealed files for the collector to open. Before the `adb uninstall` above:

  ```sh
  adb pull /sdcard/Android/data/app.sealdrop.core.test/files/cross
  python ../testvectors/check_android_files.py cross
  ```

# Sealdrop for Android

The phone's side of Sealdrop (Android 17 or newer, Kotlin). See [../docs/PROTOCOL.md](../docs/PROTOCOL.md).

**State: working.** The format core (`core/`, an Android library: sealing and opening files, manifests, receipts and
the pairing checks), and the app behind its screens (`app/`): pairing with the QR code, the hand-over from approved
apps, sealing, uploading (resumed after a cut), receipts, warnings and holds. Tested against a stand-in collector on
the device, and end to end with the real collector and a test bucket ([../tools/e2e](../tools/e2e)). Release builds
are signed with your own key ([below](#release-builds)). Installed on a phone with Android 17; not yet paired with a
real collector.

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
| `Engine.kt` | the app's state: the database, the keys, the folders, the storage clients; one sync at a time |
| `data/Db.kt`, `data/Vault.kt` | SQLite (deliveries, files, uploads, approvals, holds, receipts); the storage keys, sealed with a Keystore key |
| `net/Gate.kt`, `net/S3.kt` | §8: the only way out (HTTPS to the paired storage's host, nothing else); the S3 requests, Signature Version 4 |
| `send/Approvals.kt` | §9.1: the apps you approved, by signing certificate, checked on every call; requests from new apps |
| `send/Handover.kt` | §9.1: the AIDL service other apps bind to: begin, add, commit, status, hold, send now |
| `send/Outbox.kt` | §9.2: packing deliveries into bundles, sealing, uploading (in 8 MiB parts above 8 MiB, resumed) |
| `send/Inbox.kt` | §6: reading receipts: stored, duplicates, conflicts, refusals and their strikes, lost deliveries, two collectors |
| `send/Sync.kt`, `send/Jobs.kt` | §8, §9.2, §9.3: one sync run; the jobs that start them, the pauses after a failure, the receipt rhythm |
| `send/Holds.kt`, `send/Warnings.kt` | §9.1: holds; the warning bits apps and the main screen read |
| `send/Stores.kt`, `send/Owner.kt` | `up/` and `ack/`, and what the storage's answers mean; the owner's buttons (send again, Wi-Fi only) |
| `pair/Pairer.kt`, `pair/Qr.kt` | §7: the pairing request, waiting for the paired receipt, pairing again, unpairing; reading the QR code |
| `ui/App.kt`, `ui/Snapshot.kt`, `ui/Camera.kt` | the screens' navigation, what they show from the real state, the camera preview |
| `ui/Model.kt`, `ui/Texts.kt` | what the screens show, the warnings of §9.3 in plain words, times and sizes |
| `ui/Pairing.kt` | welcome, scanning the QR code, naming the phone, comparing the code (§7), approving an app (§8) |
| `ui/Status.kt` | the main screen (what was sent and picked up, warnings, holds, refused deliveries) and the settings |
| `ui/Parts.kt`, `ui/theme/` | shared pieces and the colours |

The interface other apps use is in `api/` (package `app.sealdrop.api`): the AIDL files and the constants of §9.1.
`demo/` is a made-up sending app (`org.example.sender`, no permissions) that shows how an app hands files over.

**Talks only to the storage.** The app has the INTERNET permission for one host: the paired storage. Three tests
make sure: `OnlyStorageTest` (on the computer) reads the sources and the manifest (only `net/Gate.kt` opens
connections, no network libraries, cleartext off, exactly these permissions); `GateTest` (on the device) tries other
hosts and plain HTTP; and the end-to-end check watches the app's connections while it runs.

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

## Tests of the app

On the computer (Signature Version 4 against AWS's examples, and the "only the storage" checks):

```sh
./gradlew :app:testDebugUnitTest
```

On a device or emulator (Android 17), against a stand-in collector in memory: pairing, hand-overs and every refusal
of §9.1, packing and sealing, uploads cut and resumed, receipts with duplicates, conflicts, refusals and strikes,
lost deliveries, two collectors, holds, warnings, pairing again and unpairing:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -e class app.sealdrop.send.FlowTest,app.sealdrop.send.GateTest app.sealdrop.test/androidx.test.runner.AndroidJUnitRunner
adb uninstall app.sealdrop.test
```

## End to end

[`../tools/e2e/run.py`](../tools/e2e/run.py) runs everything together on an **emulator**: Sealdrop, the made-up
sending app, the real collector on the computer and a test bucket from `setup_b2 --test`. It pairs with the real
`pair` command, sends deliveries, and plays the failure cases (tampered files, a cut connection on both sides,
duplicates, conflicts, junk in the inbox). It clears both apps' data first, so never point it at a phone.

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest :demo:assembleDebug :demo:assembleDebugAndroidTest
python3 ../tools/e2e/run.py --adb "$(command -v adb)"
```

## Release builds

Android installs an update only over an app signed with the same key, so a phone's Sealdrop is signed with a key of
your own, kept outside this repository. Debug builds use Android's debug key (for emulators and the tests), so they
never install over a release.

1. Make the key, in a folder outside the repository (`keytool` comes with Android Studio's JDK). It asks for a
   password twice:

   ```sh
   keytool -genkeypair -keystore sealdrop-release.jks -alias sealdrop -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=Sealdrop"
   ```

2. Next to it, a `keystore.properties` (`storeFile` is relative to this file; letters and digits in the password
   keep the file simple):

   ```properties
   storeFile=sealdrop-release.jks
   storePassword=...
   keyAlias=sealdrop
   keyPassword=...
   ```

3. In `android/local.properties` (never in git), the path to that file: `sealdrop.signing=/path/to/keystore.properties`.
   If the line names a missing file, the build stops; without the line, the release is left unsigned.
4. `./gradlew :app:assembleRelease` writes `app/build/outputs/apk/release/app-release.apk`. Its certificate:
   `apksigner verify --print-certs app-release.apk`.

Back up both files. If the key is lost, Sealdrop can only be uninstalled and installed again, which deletes its keys
and queue: the phone then pairs again, and apps hand over again what wasn't picked up.

The release isn't shrunk (no R8), so it runs the same code the tests ran.

## Choices the protocol leaves open

- **Storage on the phone:** SQLite for the state; the storage keys and the pairing state in one file, encrypted with
  an AES key in the Android Keystore. The signing key itself never leaves the Keystore.
- **Approvals:** an app that was refused, or whose approval was withdrawn, isn't asked about again for 30 days. An
  app with another signing certificate asks again.
- **Hand-overs** live in memory. If Android ends Sealdrop's process in the middle of one, it's gone (its files are
  removed when Sealdrop starts again), and the app starts over with `begin`. Each committed delivery gets its own
  folder with a random name.
- **Pauses after a failure** (§8) happen between job runs: a failed run plans the next one after the pause. A new
  reason to send (a hand-over, "send now", the network coming back) starts the pauses from the beginning.
- **Holds:** when the last hold is released, a sync starts at once; a hold that just runs out lets the next planned
  run start as usual.
- **Receipts:** an entry whose digest differs from the phone's own counts as "the collector reports a problem". A
  whole upload refused for `unknown-sender` changes nothing on the phone (it happens after pairing again, with an old
  upload). An upload whose signature fails is matched to nothing, as §6 says, so its deliveries stay "in the inbox"
  until they're sent again after 60 days.
- **Pairing:** the QR reader also reads light-on-dark codes, as terminals show them. The pairing request waits in the
  app's private files until it's uploaded; the code to compare is shown at once. The phone's name is the device
  model unless the owner changes it.
- **Unpairing** removes the keys, every unfinished delivery and the uploads, but keeps the approved apps and the
  deliveries that ended (so `status` still answers for them).
- **Notifications:** only one, when an app asks to be approved. Sealdrop asks for the permission right after pairing.


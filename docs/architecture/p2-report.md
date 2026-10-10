# Raport P2 — EveryOut

Implementacja pozostaje na working tree `fix/app-detection-errors`. Zastane zmiany
P0/P1 zachowano; P2 nie tworzy providera ani capability do usuwania. Tryb uczenia
jest dostępny w ustawieniach aplikacji pod „Learn an application”.

## Pliki P2

| Obszar        | Pliki dodane lub zmienione w P2                                                                                                                           |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Model         | `crates/core-model/src/lib.rs`, `src/observation.rs`, `tests/observation.rs`                                                                              |
| Skaner        | `crates/detection/src/storage.rs`                                                                                                                         |
| Windows       | `crates/platform-windows/src/lib.rs`, `filesystem.rs`, `native.rs`, `win32_identity.rs`, `observation.rs`, `observation/teach.rs`, `tests/observation.rs` |
| Desktop / IPC | `src-tauri/build.rs`, `capabilities/default.json`, `src/acl_tests.rs`, `src/bindings.rs`, `src/commands.rs`, `src/lib.rs`, `src/teach.rs`                 |
| UI            | `src/App.tsx`, `src/TeachMode.tsx`, `src/TeachMode.test.tsx`, `src/api/index.ts`, `src/api/types.ts`, `src/demo.ts`, `src/styles.css`                     |
| Dokumentacja  | `docs/architecture/teach-observation.md`, `p2-report.md`, `examples/learned-observation.json`                                                             |

Pozostałe zmodyfikowane pliki widoczne w `git status` należą do zastanego P1.
W `win32_identity.rs` P2 dodaje jedynie dostęp do metadanych związanego EXE.
Nie wykonano commita ani zmiany gałęzi.

## Architektura i granica bezpieczeństwa

`TeachSession` wiąże dokładną tożsamość P1, fizyczny EXE, metadane wersji/podpisu,
opcjonalny kanał, fingerprint frameworku, procesy, rooty, fazy, daty i completeness.
Osobny worker desktopowy obsługuje uczenie bez dostępu do silnika usuwania.
Zapisuje sesję i learned observation z provenance Teach/Observation. Wynik ma status
Candidate lub Observed, a nie Validated. Historyczne dane pozostają zachowane.

Discovery obserwuje krótko AppData Local/Roaming i dostępny LocalLow oraz korzysta
z kandydatów istniejącego skanera i P1. Po 20 sekundach szerokie watchery znikają.
Focused pass obejmuje maksymalnie osiem rootów; pełny cykl ma fazy A–G i limit
20 minut. Między cyklami watchery są wyłączone. Do awansu wymagane są przynajmniej
dwa kompletne, zgodne cykle.

Backend używa `ReadDirectoryChangesExW`, dynamicznego wykrywania dostępności i
fallbacku do `ReadDirectoryChangesW`. Pracuje asynchronicznie, z OVERLAPPED i subtree.
Overflow, zero-byte result lub błędne powiadomienia wymuszają metadata rescan.
`RecoveredByRescan` oznacza odzyskany stan końcowy, a nie odzyskaną historię.
Taki cykl nie dostarcza negatywnego dowodu i nie zalicza się do dwóch pełnych cykli.

LevelDB, SQLite WAL/SHM, IndexedDB, Session Storage i cache są normalizowane do
rodzin. Wewnętrzne rotujące pliki nie tworzą osobnych zakresów. Algorytm porównuje
zachowanie we wszystkich sześciu przedziałach cyklu; nie opiera klasyfikacji auth na
nazwach plików. Zachowuje sprzeczne wyniki jako Inconclusive. Szczegóły i limity
opisano w [architekturze Teach](teach-observation.md).

Moduł P2 nie odczytuje payloadów storage, sekretów, tokenów, cookie values ani
rekordów baz danych. Nie haszuje danych użytkownika. Odczyt PE/podpisu EXE pochodzi
z P1; odczyt lokalnej historii dotyczy wyłącznie własnych rekordów EveryOut.
Nie dodano Credential Manager, memory reads, injection, sterownika, ETW, USN,
destrukcyjnego registry learn ani generic wipe.

## Wyniki acceptance

| Przypadek                                           | Oczekiwany i sprawdzany wynik                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------- |
| Losowo nazwany EXE `TotallyUnknownApp-<random>.exe` | P1 Exact; EXE rzeczywiście uruchamiany w izolowanym fixture               |
| Root `SomeVendor/RandomProfile82`                   | Wykryty przez zmiany, bez dopasowania nazwy EXE lub katalogu              |
| Dwa pełne cykle login/restart/logout                | Rodzina `randomprofile82/local storage`: StronglyObserved → Auth Observed |
| Cache/logi we wszystkich fazach                     | BackgroundNoise / Noise                                                   |
| OpaqueStore bez nazwy cache                         | BackgroundNoise na podstawie zachowania                                   |
| Sprzeczne cykle                                     | Inconclusive; brak awansu mimo dwóch pozytywnych cykli                    |
| Rzeczywisty overflow bufora 64 KiB                  | Rescan, RecoveredByRescan, zachowane provenance utraty historii           |
| Zmiana EXE/wersji/kanału/frameworku/rootu           | Stale albo NeedsReobservation; historia pozostaje                         |
| Dwie unrelated aplikacje, jeden fizyczny root       | SharedConflict dla obu właścicieli w projekcji historii                   |
| User confirmation i Restart Manager                 | Nie tworzą Validated ani samodzielnego dowodu auth                        |
| Learned scope                                       | Authority Unreviewed; preservation Unknown; Action Blocked                |

Przykład pełnego learned observation znajduje się w
[learned-observation.json](examples/learned-observation.json). Jest to rekord
syntetyczny, pokazujący format i provenance; nie stanowi dowodu dla realnej aplikacji.

## Kontrole

| Kontrola                                                | Wynik                           |
| ------------------------------------------------------- | ------------------------------- |
| `cargo test --workspace`                                | 252 passed, 0 failed, 1 ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS                            |
| `cargo fmt --all -- --check`                            | PASS                            |
| `cargo run -p everyout --example bindings -- --check`   | PASS                            |
| `cargo run -p xtask -- catalog-validate`                | PASS — 45 manifestów            |
| `cargo run -p xtask -- catalog-table --check`           | PASS                            |
| `pnpm typecheck`                                        | PASS                            |
| `pnpm lint`                                             | PASS — bez ostrzeżeń            |
| `pnpm test`                                             | 68 passed / 12 plików, 0 failed |
| `pnpm format:check`                                     | PASS                            |
| `pnpm build`                                            | PASS                            |
| `git diff --check`                                      | PASS                            |

Jeden ignored to istniejący subprocess fixture procesu, uruchamiany jawnie przez
testy nadrzędne. Nowe testy P2 obejmują model, natywne eventy i cancellation,
rzeczywisty overflow, pełne dwa cykle uruchamianej nieznanej aplikacji, zapis i shared
history, invalidation frameworku oraz zachowanie UI. Test zakresu 64-bitowych file IDs
potwierdza zachowanie wszystkich bitów przez IPC; reprezentacja używa decimal strings.
Istniejące testy Spotify i generyczne fixtures Win32 P1 również przeszły.

Testy realnych produktów w VM i destrukcyjna walidacja nie zostały przeprowadzone.
Acceptance dotyczy izolowanych, syntetycznych aplikacji i prawdziwych API Windows.

## Dokładna granica następnego etapu

1. Controlled Scope Validation: sprawdzenie, czy usunięcie konkretnej rodziny
   rzeczywiście prowadzi do signed-out state, a nie tylko koreluje z wylogowaniem.
2. Ocena utraty i zachowania danych, canaries oraz próby na realnych aplikacjach w VM.
3. Dopiero po tych dowodach: Validated Surgical Logout, operation authority i provider.
4. Dalsze adaptery metadanych: registry-heavy aplikacje, custom roots, niezależne
   wykrywanie kanału i szersze wybieranie MSIX executable.
5. Opcjonalne backendy ETW/USN, dokładniejsze przypisywanie późnych eventów do faz
   i rozszerzenie polityk dla rodzin intensywnie kompaktowanych przy restartach.
6. Rozbudowa obsługi historii ponad limity P2 i ewentualne dodatkowe UX shortlisty.

P2 nie przeprowadza destrukcyjnej walidacji ani automatycznego usuwania learned scope.

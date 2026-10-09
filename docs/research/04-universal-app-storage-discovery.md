# EveryOut — uniwersalne wykrywanie magazynów danych aplikacji

Data analizy: 2026-10-07. Zakres: dostarczone logi, implementacja wykrywania i źródła pierwotne.
Nie wykonano czyszczenia ani inwentaryzacji prywatnych danych komputera deweloperskiego.

## Wniosek

Najlepszą podstawą jest połączenie wykrywania struktur danych z identyfikacją instalacji
i opcjonalną obserwacją operacji plikowych procesu. Sama lista popularnych aplikacji ma ograniczoną
skalowalność. Samo wyszukanie folderów o nazwie `Cache` nie ustala właściciela, przeznaczenia
zawartości ani skuteczności wylogowania. Trzeba zachowywać takie wyniki jako materiał do dalszej
identyfikacji, zamiast całkowicie je odrzucać.

Nie ma w przeanalizowanych API wspólnego zapytania systemowego zwracającego wszystkie katalogi
cache dowolnej aplikacji Win32. To wniosek z porównania opisanych niżej mechanizmów, nie gwarancja
pełności przeglądu wszystkich istniejących narzędzi. Aplikacje mogą korzystać z własnych lokalizacji,
kilku magazynów oraz współdzielonych usług uwierzytelniania.

## Co dokładnie wynika z logów

1. Dla Spotify `build-plan` i `dry-run` kończą się bez błędu komendy, lecz akcja otrzymuje
   `preview-blocked`, `outcome: blocked` i `verification: not-performed`. Sukces komendy oznacza
   zwrócenie podglądu; nie oznacza wykonania czyszczenia.
2. Manifest Spotify ma `support: candidate`, wersję produktu `unvalidated`, niezweryfikowane
   `prefs`, brak przeanalizowanej tożsamości procesu i blokady dotyczące zakresu sesji oraz
   zachowania innych danych. Blokada pochodzi z modelu obsługi, a nie z błędu odczytu pliku.
3. `authentication: unknown` i brak weryfikacji nie pozwalają stwierdzić ani zalogowania,
   ani skutecznego wylogowania. Zaobserwowano jedynie metadane istniejącego pliku.
4. `process_count: 0` nie dowodzi, że Spotify nie działa: manifest ma pustą listę nazw procesów
   i deklaruje brak zweryfikowanej tożsamości obrazu procesu.
5. Liczne `adapter-unavailable: unsupported` wskazują oddzielny problem: katalog zawiera wpisy,
   dla których executor nie ma obsługi. Rozbudowa skanera nie implementuje tych adapterów.
6. Błąd `Chrome_WidgetWin_0` nie jest przedstawiony jako przyczyna blokady podglądu.
   `STATUS_CONTROL_C_EXIT` oznacza przerwanie procesu; te komunikaty nie potwierdzają awarii usuwania.

Instrukcja wylogowania w interfejsie producenta jest obecnie fallbackiem. Nie zastępuje
automatycznego działania, którego użytkownik oczekuje od EveryOut.

## Dlaczego poprzedni skaner pomijał aplikacje

Skaner miał jedno wyliczenie bezpośrednich podkatalogów Local/Roaming AppData i osiem stałych
układów. Nie obejmował dowolnego zagnieżdżenia `Producent/Aplikacja/...`, dodatkowych profili
ani partycji. Rozpoznawał głównie zestaw magazynów Chromium, wymagając trzech artefaktów.

Nawet rozpoznana struktura nie wystarczała: funkcja `score` odrzuca wynik z mniej niż dwiema
niezależnymi rodzinami dowodów. Dla zwykłego katalogu AppData skaner dostarczał tylko storage.
Inwentaryzacja desktopowa zbiera nazwy kluczy i skrótów, lecz nie wartości DisplayName,
InstallLocation, Publisher ani cel skrótu. To wyjaśnia brak drugiego dowodu. Nazwa folderu
nie powinna być sztucznie liczona jako niezależne potwierdzenie instalacji.

## Porównanie podejść znalezionych w źródłach

| Mechanizm                   | Co daje                                                         | Granica użyteczności                                                                  |
| --------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Struktury Electron/Chromium | Wspólne nazwy cookies, local/session storage, IndexedDB i cache | Rozpoznaje rodzinę magazynu; nie konkretną aplikację ani token logowania              |
| Kontenery MSIX              | Systemowo zarejestrowaną tożsamość kontenera                    | Dane LocalState i LocalCache mogą mieć różne znaczenie dla aplikacji                  |
| WebView2 UDF                | Wspólny układ danych wielu aplikacji                            | Lokalizacja może być niestandardowa i folder może być współdzielony                   |
| Standardowe lokalizacje Qt  | Typowe ścieżki producent/aplikacja/cache                        | Konwencja frameworka, nie wymóg wobec każdej aplikacji                                |
| ETW / Process Monitor       | Dowód użycia konkretnej ścieżki przez proces                    | Aktywne okno obserwacji, uprawnienia, utrata zdarzeń, nie dowód bezpiecznego usuwania |
| CleanerML / Winapp2         | Weryfikowane przez społeczność reguły aplikacji                 | Katalog reguł, nie uniwersalny detektor sesji                                         |
| Watcher / USN               | Informację, co się zmieniło                                     | Nie wystarcza do identyfikacji procesu ani semantyki danych                           |

### Electron, Chromium, WebView2 i Qt

Electron opisuje `userData`, domyślnie pod AppData z nazwą aplikacji, oraz `sessionData`, które
obejmuje dane sesji Chromium. Program może nadpisać te ścieżki. API session rozdziela operacje
czyszczenia cache i magazynów danych. Wniosek projektowy: reguła rodziny technologicznej może
znaleźć podobne magazyny w wielu niszowych aplikacjach, ale nie wyznacza automatycznie pełnej sesji.
Źródła: [Electron app](https://www.electronjs.org/docs/latest/api/app),
[Electron session](https://www.electronjs.org/docs/latest/api/session).

WebView2 przechowuje cookies i zasoby cache w UDF. Microsoft opisuje domyślną lokalizację
obok pliku wykonywalnego dla aplikacji Win32 oraz możliwość wybrania innej lokalizacji.
UDF może być współdzielony. Dlatego pełne pokrycie wymaga danych o procesie/instalacji,
a nie tylko AppData. Źródło:
[Manage user data folders](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder).

Chromium dokumentuje formaty cache, w tym index i pliki danych. Rozpoznanie nazw takiej struktury
może wzmacniać dowód rodzaju magazynu. Nie ustanawia prawa do usunięcia nadrzędnego katalogu.
Źródło: [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/).

Qt udostępnia CacheLocation, AppDataLocation i AppLocalDataLocation. To uzasadnia szukanie
zagnieżdżonych katalogów producenta i aplikacji. Nie zakładamy, że każde oprogramowanie przestrzega
tej konwencji. Źródło: [QStandardPaths](https://doc.qt.io/qt-6/qstandardpaths.html).

Microsoft rozdziela lokalne dane aplikacji i LocalCacheFolder, którego dane nie uczestniczą
w backup/restore. Nie wynika z tego, że dowolny plik w kontenerze jest zbędny lub pozbawiony
informacji logowania. Źródło:
[Store and retrieve app data](https://learn.microsoft.com/en-in/windows/apps/design/app-settings/store-and-retrieve-app-data).

### Jak znaleźć niestandardową lokalizację

Process Monitor rejestruje aktywność plikową, rejestru i procesów. Jest dobrym narzędziem
laboratoryjnym do sprawdzania nowych aplikacji. W EveryOut odpowiednikiem może być ograniczona
sesja ETW z korelacją zdarzeń plikowych oraz tożsamości procesów. To propozycja architektury,
nie funkcja wdrożona w tej zmianie. Źródła:
[Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon),
[FileIo](https://learn.microsoft.com/en-us/windows/win32/etw/fileio).

Obserwator powinien:

1. Powiązać PID z czasem utworzenia procesu, użytkownikiem i zweryfikowanym obrazem wykonywalnym.
   Sama nazwa `app.exe` ani PID nie wystarczają; PID może zostać ponownie użyty.
2. Obserwować wybrany proces i powiązane procesy potomne w krótkim oknie używania aplikacji.
   Nie uruchamiać automatycznie nieznanych programów ani przechwytywać treści baz/tokenów.
3. Zachowywać mapowanie `proces → operacja → fizyczny katalog` i liczniki, agregując je lokalnie.
   Dane surowe mogą zawierać prywatne ścieżki; nie powinny trafiać do zwykłych logów.
4. Rozróżniać odczyt, zapis i utworzenie oraz dostęp wielu aplikacji do tego samego magazynu.
   Dowód zapisu wzmacnia przypisanie, lecz nie potwierdza wyłącznego właściciela.
5. Raportować utratę zdarzeń, brak dostępu, proces zakończony przed obserwacją i brak aktywności.
   Brak zdarzeń nie oznacza braku danych.
6. Zwracać wynik do warstwy discovery; dopiero osobna reguła określa zakres czyszczenia.

Microsoft wymaga odpowiednich uprawnień do sterowania sesjami ETW i zaleca mały zakres, filtry,
ograniczoną pamięć oraz zatrzymanie sesji po zakończeniu scenariusza. Nie należy obiecywać,
że każdy wariant takiego skanowania zadziała bez podwyższonych uprawnień. Źródło:
[StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew).

ReadDirectoryChangesW daje powiadomienia o zmianach katalogu, a rekord USN V2 informacje
o zmienionym obiekcie. Ich opisane struktury nie zawierają identyfikacji procesu sprawcy.
Wniosek: są przydatne do przyrostowego reskanu, ale nie zastępują korelacji procesu z plikiem.
Źródła: [ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw),
[USN_RECORD_V2](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2).

### Czy ktoś już rozwiązał ten problem

BleachBit używa deklaratywnego CleanerML, a Winapp2 jest bazą reguł czyszczenia aplikacji.
Potwierdza to praktyczną wartość wspólnego katalogu reguł. Nie stanowi dowodu, że znaleziono
uniwersalny sposób rozpoznania wszystkich danych uwierzytelniania.
Reguły można wykorzystać jako wskazówki do badań po sprawdzeniu licencji, wersji i zakresu;
nie należy automatycznie wykonywać ich wildcardów jako planów EveryOut.
Źródła: [CleanerML](https://docs.bleachbit.org/cml/cleanerml/),
[Winapp2](https://github.com/MoscaDotTo/Winapp2).

Spotify rozdziela cache od pobranych materiałów w dokumentacji pamięci. To dodatkowy powód,
aby nie utożsamiać usuwania cache, resetu preferencji, usunięcia pobrań i wylogowania.
Źródło: [Spotify storage information](https://support.spotify.com/mt/article/storage-information/).

## Wdrożony pierwszy etap

- Nowe `ScanReport.storage` zachowuje wyniki magazynów niezależnie od progów ownership scoring.
  Istniejące confidence gates dla tożsamości aplikacji nie zostały osłabione.
- Skan metadanych Local/Roaming AppData przeszukuje katalogi wszerz, do sześciu poziomów,
  maksymalnie 2000 katalogów (1000 na zakres Local/Roaming) i 2000 oczekujących wpisów;
  zwraca najwyżej 500 grup kandydatów.
  Przekroczenie limitu, brak dostępu i anulowanie są jawnie raportowane jako niepełne pokrycie.
- Obsługiwane są grupy artefaktów Chromium i Mozilli oraz wskazówki nazw cache.
  `Network/Cookies` jest sprawdzane jako plik; sam katalog Network nie wystarcza.
- Zagnieżdżone układy, dodatkowe profile i partycje mieszczące się w budżecie są odnajdywane
  bez manifestu dla konkretnej aplikacji. Grupa odpowiada kontenerowi najwyższego poziomu,
  niekoniecznie jednej aplikacji: producent może umieszczać tam kilka produktów.
- Skan nie wchodzi w payloady cache, IndexedDB, local/session storage, pobrania, zasoby
  instalacyjne i zależności. Odrzuca przekierowania/reparse points poprzez istniejące
  capabilities systemu plików, zachowujące uchwyty wszystkich przodków.
- Pakiety są badane wyłącznie przez systemowo zarejestrowane kontenery, bez zgadywania właścicieli
  wszystkich katalogów Packages. Sam wynik discovery może obejmować pozostałości po instalacji.
- UI otrzymuje wyniki jako niewybrane, nieklasyfikowane wskazówki z nazwą katalogu/kontenera.
  Etykieta nie jest potwierdzoną nazwą aplikacji. Podobne etykiety oraz kilka zakresów
  Local/Roaming mogą dawać odrębne wyniki; nie są scalane na podstawie samej nazwy.
- Log developerski `storage-discovery` zawiera liczby aplikacji-kontenerów, lokalizacji,
  rodzaje dowodów i kody pokrycia. Nie zapisuje etykiet folderów, profili ani ścieżek.
- Wyniki discovery nie otrzymują uprawnień do usuwania/zamykania. Próba przesłania ich ID jako
  celu czyszczenia jest odrzucana przez warstwę komend.

Ten etap nie odblokowuje automatycznie Spotify, nie dodaje ETW i nie obejmuje całego dysku,
LocalLow ani dowolnych instalacji portable. Wykrycie cache o nietypowej nazwie bez
rozpoznawalnych sąsiadów pozostaje poza pokryciem. Nie ustalono procentowej skuteczności
na rzeczywistym zbiorze aplikacji.

## Kolejne etapy systemu

1. **Tożsamość instalacji:** ograniczona lista dozwolonych metadanych Uninstall/App Paths,
   celów skrótów i obrazu procesu. DisplayName lub podobieństwo folderu są wskazówkami;
   silne przypisanie wymaga zgodności kilku źródeł i rzeczywistej instalacji.
2. **Własność fizycznego magazynu:** lokalne mapowanie korzeni do instalacji, wykrywanie
   współdzielonych i nakładających się katalogów oraz wersji aplikacji. Zachować rozdział
   między pewnością typu magazynu, właściciela i bezpiecznej operacji.
3. **Obserwacja ETW na żądanie:** ustalenie nietypowych lokalizacji i powiązanie używających
   ich procesów. Najpierw prototyp i testy uprawnień, przeciążenia oraz utraty zdarzeń.
4. **Reguły operacji:** rozdzielić zweryfikowane czyszczenie cache, reset lokalnej sesji
   i pełny reset aplikacji. Nie proponować resetu całego katalogu jako domyślnego sposobu
   wylogowania z nieznanej aplikacji; może on obejmować dokumenty, klucze lub historię.
5. **Weryfikacja efektu:** potwierdzić usunięcie wskazanych artefaktów osobno od ponownego
   pojawienia się ekranu logowania. Nie obiecywać cofnięcia zdalnej sesji przez offline wipe.
6. **Pomiar pokrycia:** korpus Windows 10/11 z Electron/CEF/WebView2, Qt/native, MSIX,
   aplikacjami portable i relokowanymi. Oddzielnie mierzyć znalezienie korzenia, poprawne
   przypisanie właściciela i skuteczność operacji. Pozostałości oraz nieznane etykiety
   uwzględniać, zamiast usuwać je z mianownika.

## Weryfikacja implementacji

Testy syntetyczne sprawdzają wykrycie nieznanej aplikacji w zagnieżdżeniach/partycjach,
obsługę plików o zablokowanym odczycie zawartości, pomijanie payloadów i junctionów,
anulowanie oraz jawny limit głębokości. Test komend sprawdza dostarczenie wyników do UI
i odmowę użycia discovery jako celu usuwania. Nie zastępuje to kalibracji na realnych instalacjach.

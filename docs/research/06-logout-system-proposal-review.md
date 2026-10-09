# EveryOut — przegląd propozycji systemu wylogowania

Data: 2026-10-08. Analiza dotyczy przekazanej propozycji, aktualnego kodu oraz dokumentacji
producentów. Opisuje stan wdrożenia i dalsze prace; nie stanowi deklaracji obsługi wszystkich aplikacji.

## Diagnoza i poprawki

Trafna jest diagnoza, że poprawne wykrycie pliku i pomyślny dry run nie oznaczają możliwości
wylogowania. Katalogowe blokady są przenoszone do planu, a samo rozszerzenie skanera ich nie usuwa.
Nie należy wyłączać wszystkich blokad jednocześnie: znaczenie plików różni się między produktami.

Wdrożone zostały:

- Ograniczony skan metadanych Local/Roaming AppData, niezależny od listy providerów. Odnajduje
  zagnieżdżone magazyny, profile i partycje; zachowuje wskazówki także bez ustalonego właściciela.
  Limity i niepełne pokrycie są jawne. [Szczegóły](04-universal-app-storage-discovery.md).
- Powrót z podglądu bez zużywania niezmienionego inventory. Po rzeczywistych zmianach procesów
  lub danych wymagany jest nowy skan, ponieważ poprzednie obserwacje tracą aktualność.
- Filtrowanie procesów przed otwieraniem ich uchwytów. Odmowa dostępu do niepowiązanego procesu
  nie blokuje Spotify. Zamknięcie nadal wymaga zgodności konta, sesji i konkretnego obrazu procesu.
- Wąski adapter Spotify: usuwa cztery sprawdzone pola logowania z `prefs`, zachowując pozostałe
  bajty. Sprawdzony plik wykonywalny jest przypięty hashem. Zmieniona wersja lub format blokują
  operację. Test przez silnik zakończył się `complete-local-scope`; przy wcześniejszym restarcie
  zaobserwowano ekran logowania. [Zakres i ograniczenia](05-spotify-local-logout.md).
- Aktualizacja zaufanego katalogu wbudowanego, aby zmiana manifestu nie unieruchamiała istniejącej
  instalacji. Ochrona przed cofnięciem wersji i ponownym użyciem rewizji pozostaje aktywna.

Spotify pozostaje kandydatem o konkretnym sprawdzonym zakresie. Inne aplikacje nie zostały
automatycznie awansowane do obsługiwanych. Liczbę manifestów i ich blokady należy ustalać
z bieżącego katalogu, zamiast utrwalać liczbę z wcześniejszego przeglądu.

## Wspólny mechanizm dla mniej popularnych aplikacji

Docelowy przepływ: **odkrycie magazynu → przypisanie właściciela → określenie skutków operacji
→ test wersji → wykonanie → weryfikacja**. Każdy etap dostarcza inny rodzaj dowodu.

Electron udostępnia partycje trwałe i sesje w pamięci. Ścieżki `userData` i `sessionData`
mogą zostać zmienione przez aplikację. Dane sesji obejmują także cookies i cache, więc rozpoznanie
rodziny frameworka nie określa jeszcze bezpiecznego zakresu wylogowania.
Źródła: [Electron session](https://www.electronjs.org/docs/latest/api/session),
[Electron app](https://www.electronjs.org/docs/latest/api/app).

WebView2 na Win32 domyślnie używa `<exe>.WebView2` obok programu, ale aplikacja może ustawić
własną lokalizację. UDF może być współdzielony. `EBWebView` jest wskazówką struktury wewnętrznej,
nie uniwersalną regułą ustalającą właściciela. W przyszłym resolverze trzeba zachować dowód
powiązania instalacji, UDF i wybranej aplikacji oraz zgłaszać nierozstrzygnięte współdzielenie.
Źródło: [Microsoft — user data folders](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder).

Warto dodać wąskie metadane instalacji i runtime, potem korelację operacji plikowych procesu
w kontrolowanym laboratorium. `InstallLocation`, nazwa folderu lub `app.asar` stanowią poszlaki;
nie mogą samodzielnie autoryzować zamknięcia procesu ani usunięcia całego katalogu.

Średnia confidence może pozwalać wybrać wynik do dalszego przeglądu. Nie powinna pozwalać
wykonać zgadywanego resetu. Zgoda użytkownika na utratę danych nie rozstrzyga, czy katalog
rzeczywiście należy do aplikacji i czy operacja w ogóle usuwa logowanie.

## Credential Manager

Propozycja słusznie uwzględnia, że `CredEnumerateW` zwraca rekordy poświadczeń, a nie wyłącznie
nazwy. Microsoft opisuje filtrowanie prefiksem i bufor wymagający `CredFree`. Nazwa/prefiks
nie są dowodem wyłącznej własności aplikacji.
Źródło: [CredEnumerateW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew).

Ten mechanizm nie został wdrożony. Wymaga osobnej decyzji dotyczącej dostępu do poświadczeń,
analizy cyklu życia bufora, dokładnych sprawdzonych celów i ochrony współdzielonej tożsamości.
Lista kilku zakazanych prefiksów Microsoft nie wystarcza do zabezpieczenia wszystkich usług
systemowych. Bezpieczna podstawa to wąska pozytywna lista konkretnych testowanych operacji.
Nieznanych wpisów nie należy nazywać „DPAPI app”: sama enumeracja nie ustala takiej aplikacji.

## Kolejność dalszego wdrażania

1. Zbierać wersjonowane dowody własności i skutków dla popularnych produktów według
   [listy testów VM](../testing/vm-checklist.md), a następnie dodawać ograniczone adaptery.
2. Rozbudować deklaratywne resolvery Electron/CEF/WebView2 bez dowolnych wildcardów wykonawczych.
   Pozwala to współdzielić implementację między produktami, zachowując kontrolę zakresu.
3. Dodać metadane instalacji/runtime oraz laboratoryjną obserwację niestandardowych ścieżek.
   Wyniki trafiają najpierw do discovery, potem do przeglądu reguły.
4. Rozpatrzyć osobno Credential Manager wraz z precyzyjną polityką i świadomą zgodą.

Plan podziału na gałęzie, commity i publikację należy stosować po ustaleniu konkretnego zakresu
wydania. Przegląd propozycji nie publikuje zmian w repozytorium zdalnym.

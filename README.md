# my-lua-project

[Скачать DLL + injector для legacy CS:GO x86 (ZIP, 14 МБ)](https://github.com/valentinaxbianca1337-cloud/my-lua-project/raw/refs/heads/main/downloads/skeet-windows-x86-overlay-v1.zip)

Архив содержит `skeet.dll`, `injector.exe`, исходники обвязки, инструкцию на русском, символы отладки и отчёты проверок. Применён фикс Steam Overlay из предоставленного скриншота: обновлены сигнатуры и два смещения вызовов; при ошибке поиска инициализация останавливается.

Сборка предназначена для **legacy `csgo.exe`, Windows x86**. Запуск в Windows и игре не проверен. DLL использует оригинальное бинарное ядро; полный Rage в C++ не восстановлен, экспериментальный предиктор не подключён.

Контрольные суммы и ограничения сборки: [SKEET_WINDOWS_RELEASE.json](downloads/SKEET_WINDOWS_RELEASE.json). Внутри ZIP также находится `SHA256SUMS.txt` для всех файлов.

## Диагностика промахов

[Скачать диагностический Lua и инструкцию (ZIP)](https://github.com/valentinaxbianca1337-cloud/my-lua-project/raw/refs/heads/main/downloads/skeet-prediction-diagnostics-v1.zip).

Скрипт записывает сетевые состояния целей, флаги штатного предсказания и события `aim_fire/aim_hit/aim_miss`; игру и DLL он не меняет. Для разбора включить **Record prediction diagnostics**, воспроизвести 2–3 промаха, нажать **Export prediction trace** и передать `skeet_prediction_trace.json`. [Подробная инструкция](prediction_diagnostics/README_RU.md).

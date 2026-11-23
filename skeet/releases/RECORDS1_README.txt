Improved Records 1 + NL Movement — 24.11.2026

Вкладка Improved с кисточкой под Rage теперь содержит работающие настройки:

Backtrack
- Backtrack: включить дополнительное ограничение возраста записей.
- Max age 16–200 ms: только сужает окно, которое уже разрешило ядро.

Lag records
- Consistent pose: одна подготовленная запись для поиска и применения.
- Max gap 1–16 ticks: предел интерполяции между соседними записями.
- Limit records / Record limit 1–32: дополнительное ограничение истории.

Extrapolation
- Отдельный checkbox, доступен вместе с Consistent pose и collision данными.
- Max ticks 1–2; default 1. Общий перевод позиции ограничен 16 units.
- Last: тип последнего применения или отклонения; Module unavailable означает,
  что sites не подошли и модуль оставил native обработку.

Все новые функциональные checkbox по умолчанию выключены. Для первого
сравнения включить только Consistent pose. Extrapolation прогнозирует лишь
короткое перемещение существующей позы и не восстанавливает будущую анимацию
противника; держать её выключенной до отдельного теста. Увеличение точности
на сервере этой сборкой ещё не подтверждено. Подробный разбор и ограничения:
RECORDS_AUDIT_RU.txt; машинные отчёты: reports/.

Запуск
1. Полностью распаковать комплект. Для нового инжекта использовать skeet.dll
   и injector.exe из одного комплекта; Launch_Improved.cmd сохраняет лог.
2. После загрузки открыть Insert -> кисточка под Rage -> Improved.
3. Для движения из предыдущей совмещённой версии загрузить отдельно
   nl_movement_combined.lua: MISC -> Movement -> Neverlose movement.
   Без этого Lua bridge movement exports обработчик команд не включают.

Movement сохранён из предыдущего combined выпуска, новых изменений steering
здесь нет. Normal/WASD steering и Directional candidate selection проверены
по NL instructions. Collision predictor адаптирован под Source и не является
полным переносом protected Neverlose movement 1:1. Autopeek, автостоп и прочий
movement не переносились. При недоступности trace или исчерпании бюджета
1536 queries Directional использует WASD. Штатный Air strafe восстанавливается
при выключении/выгрузке Lua. Не включать два Lua стрейфера одновременно.

UI основан на рабочем Fix3. Native IDs/TabsArr и texture atlas других иконок
сохранены; размещение кисточки учитывает resize и DPI. В Improved нет Movement
и Profiles. Старая пустая вкладка и предыдущий combined архив доступны отдельно
для отката. Не загружать несколько версий DLL одновременно.

Сборка source_project
python -m pip install -r requirements-build.txt -r requirements-test.txt
python verify_source.py
python build_windows.py

Закрытые fixtures на Linux с g++:
python build_tests.py
python tests/validate_records.py
python tests/validate_record_bridges.py
python tests/validate_record_world.py
python tests/validate_improved_native.py
python tests/validate_improved_frame.py
python tests/validate_movement_v2_windows.py
python tests/test_combined_adapter.py

Тесты не запускают DLL entry, настоящий injector или игру. Исходный embedded
skeet.bin проверяется по SHA256. В Windows сборка — x86, ziglang 0.13.0.

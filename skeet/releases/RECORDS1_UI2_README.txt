Improved Records 1 UI2 + NL Movement

Исправление интерфейса по скриншоту пользователя.
- Ползунки получают штатную ширину после установки размеров панели.
- Используются оригинальные Child/Slider callbacks для DPI, resize и layout.
- Размеры содержимого обновляются после создания, resize и смены DPI.
- Удалены все восемь служебных label: Last: ..., подсказки о collision,
  Consistent pose и Module unavailable. В меню только 4 checkbox и 4 slider.
- Панели, кисточка под Rage и все настройки обработки записей сохранены.

Геймплейные record_layout/session/hooks/runtime/world/options и движение
побайтово сохранены из Records 1. Опции Extrapolation по-прежнему требуют
Consistent pose и доступных collision данных; недоступный checkbox остаётся
серым. Удаление подписей не отключает эти проверки.

Запуск
1. Распаковать весь архив и использовать matching skeet.dll / injector.exe.
2. Launch_Improved.cmd запускает injector и сохраняет прежнюю диагностику
   improved-status.txt. DLL не заменяется внутри уже запущенного процесса:
   для обновления нужен новый запуск игры.
3. Insert -> кисточка под Rage -> Improved.
4. Для прежнего movement отдельно загрузить nl_movement_combined.lua:
   MISC -> Movement -> Neverlose movement. Два Lua стрейфера не включать.

Исходники: source_project. Сборка: python build_windows.py (ziglang 0.13.0).
Закрытые UI fixtures: python build_tests.py, затем
python tests/validate_improved_native.py
python tests/validate_improved_frame.py

Проверяются исходные native callbacks DPI/resize/layout, ширина полосок,
непересечение строк, отсутствие лишнего scrollbar, переключения иконок,
DPI, resize, чужая Lua-вкладка. Constructors/renderer — контролируемые границы;
это не запуск настоящей GPU-отрисовки. Новая UI2 DLL в игре здесь не запускалась.
Предыдущую Records 1 пользователь сообщил как хорошо трекающую; количественного
игрового сравнения нет. UI2 не меняет алгоритмы записи/прогноза/стрельбы.

Предыдущий records разбор сохранён в RECORDS_AUDIT_RU.txt. reports/baseline_records1
содержит исторические отчёты предыдущего выпуска; актуальные UI2 отчёты отдельно
в reports/. Полный protected Neverlose movement 1:1 не заявляется.

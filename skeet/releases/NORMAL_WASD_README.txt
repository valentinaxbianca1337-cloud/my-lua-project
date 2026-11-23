Skeet 8802 + Normal/WASD strafe: Windows x86

ВАЖНО: это НЕ полный movement Neverlose 1:1.
Подготовлена и проверена Normal/WASD вычислительная ветка. Directional/circle
и зависимый симулятор движения/столкновений Neverlose пока не перенесены.
Autopeek и автостоп перед выстрелом не изменялись по выбранной области работы.
Исчезновение прежних остановок на серверах и игровая совместимость не подтверждены.

В комплекте:
  skeet.dll       — собранный Windows x86 wrapper с movement exports;
  injector.exe    — собранный matching x86 loader;
  lua/nl_movement.lua — необходимый адаптер публичного API GameSense;
  source_project/ — соответствующие исходники;
  reports/        — результаты проверок;
  SHA256SUMS.txt  — контрольные суммы файлов пакета.

Как подключить:
1. skeet.dll и injector.exe должны находиться рядом. Цель — legacy csgo.exe
   Windows x86, эта сборка не предназначена для CS2.
2. Запустить injector.exe после запуска подходящего клиента. В этой работе
   injector не исполнялся, полный игровой запуск не проверялся.
3. Через штатную загрузку Lua GameSense загрузить lua/nl_movement.lua.
4. В MISC -> Movement включить Neverlose WASD strafe. Начальное сглаживание 50%.
   Checkbox изначально выключен. Без Lua-адаптера C++-расчёт сам не активируется.

Адаптер вызывает новые C ABI exports только из уже загруженного skeet.dll.
Одновременно отключается штатный Air strafe; при выключении исходное значение
восстанавливается. Угол прицеливания, attack, jump/duck, tickbase и packet flags
не переписываются. С другими Lua, меняющими движение, общий арбитр отсутствует.

Проверено:
  - Windows x86 PE у DLL и injector;
  - matching loader-status export и 4 movement exports;
  - исходный skeet.bin в ресурсах DLL;
  - 4494 изолированных сравнения расчёта с исходными NL SSE/WASD блоками;
  - 193 portable C++ API/guard cases;
  - 15 групп Lua host-policy/FFI checks;
  - 300 вызовов movement-кода из фактически собранной DLL в Unicorn:
    float32 угол совпал с portable C++, cdecl cleanup и запросы ABI проверены.

В эмуляторе DLL entrypoint, injector и Windows loader не запускались.
atan2 и части математических зависимостей имеют явно заданные границы тестов.
Проверка export-функций не доказывает исправность загрузки всей DLL в игру,
серверное поведение, FPS, отсутствие коррекций или улучшение стрельбы.

База — ранее подготовленные исходники без игровых scan/precision/motion,
body preference и DT accuracy патчей. Меню/инвентарь и совместимость загрузчика
сохранены. Подробные ограничения и воспроизведение — source_project/README_RU.txt.

ZIP SHA256: dc51f387db4aee99eedc26c428b165a7ae1ba27ce02d030d608a54352d882d8f

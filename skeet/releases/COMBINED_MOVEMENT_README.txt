Improved Fix3 + NL Movement 1 — unified build

В одном комплекте: рабочий интерфейс Improved Fix 3, native расчёт движения,
matching injector и Lua bridge nl_movement_combined.lua.
Режимы: Normal, WASD, Directional.

Directional использует проверенный выбор поворотов из NL и адаптированный
Source hull predictor. Это НЕ полный перенос всего movement Neverlose 1:1.
Сходство всего симулятора и поведение на сервере ещё не подтверждены.

Установка:
1. Полностью закрыть csgo.exe; распаковать архив в новую папку.
2. Запустить Launch_Combined.cmd. Загрузчик должен показывать:
   Improved Fix3 + NL Movement 1
3. После запуска ядра открыть меню через Insert. Improved должен появиться
   под Rage; его проверенный UI-код сохранён. Лог: improved-status.txt.
4. Загрузить nl_movement_combined.lua через меню GameSense Lua.
5. MISC -> Movement -> Neverlose movement; выбрать NL strafe mode.
   Старый адаптер/другой стрейфер предварительно выключить.

Без Lua bridge экспортированные расчёты сами обработчик команд не создают.
Сам расчёт выполняется в DLL, Lua передаёт публичные данные и записывает
forwardmove/sidemove/move_yaw. Aim angles/attack/duck/packet fields не меняет.
Штатный Air strafe временно отключается и восстанавливается при выключении
или выгрузке bridge. Нативные gameplay bytes, ConVars и entity memory не патчатся.

Directional: hull traces через EngineTraceClient004, отдельный clone-based
predictor без записи в сущность игрока. Ограничение 1536 trace queries на
команду; недоступные interfaces, повреждённые результаты trace или исчерпание
бюджета переключают расчёт на WASD с однократным сообщением в Lua log.
Surface friction фиксирован 1; отсутствующие hull/max-wishspeed параметры
имеют стандартные Source defaults. Это ограничения host-адаптации.
Autopeek/автостоп перед выстрелом/остальные movement-функции не переносились.

Проверки: 924 сравнения NL Directional выбора поворотов, 21 группа Lua
lifecycle/replay/ownership проверок, 22 portable случая геометрии/guards,
x86 Ray_t/filter/TraceRay ABI с контролируемыми interface factories,
18 вызовов новых exports фактически собранной DLL и 300 legacy вызовов.
Реальные DLL entry/injector/game engine и серверный матч не запускались.
Отчёты и полные исходники лежат рядом. Старую Fix 3 можно сохранить отдельно.

В Improved Backtrack / Lag records / Extrapolation по-прежнему являются
панелями без новых игровых настроек. Movement находится в MISC, не в Improved.
Цель: Windows x86, legacy CS:GO (не CS2).

Improved Records 3 + NL Movement

Удалён наш модуль Hitscan/Units: панель, настройки, headers, вызов установки и
перехват генерации точек. Штатный сканер Skeet сохранён. UI возвращён к трём
панелям Backtrack / Lag records / Extrapolation; иконка под Rage, DPI и resize
сохранены из проверенной UI2.

Исправление record collision initialization
m_flSimulationTime искали только как DPT_Float. В Source оно может быть
DPT_Int, а RecvProxy_SimulationTime записывает float-секунды в entity.
Теперь поиск принимает DPT_Int и DPT_Float, сохраняя проверку конечного float,
соответствия последней записи, размеров hull и полного прохождения swept trace.
Это исправляет отказ инициализации при integer RecvProp и может объяснять
недоступную Extrapolation при Consistent pose. Другие причины отказа интерфейсов
или данных остаются возможны; разблокирование в вашей игре ещё не подтверждено.

Старая compiled x86 world fixture с integer RecvProp воспроизвела ready=false.
Новая fixture принимает Int и Float, отклоняет Vector/String; девять проверок
ошибок hull/trace/time проходят. Native pose/getter/apply, меню, ABI и pure movement
exports также проверены. Полное окно backtrack и серверные ограничения не расширены.
Не заявляется рост попаданий: это исправление готовности данных для ограниченного
прогноза, не новый resolver и не прогноз всей анимации.

Все новые опции по умолчанию выключены. Для Extrapolation нужны Consistent pose
и готовые collision данные. Даже после исправления начинать с 1 tick; в движении
с изменением стойки прогноз может быть отклонён. Стрельба остаётся за штатным Rage.

Установка: полностью перезапустить игру, использовать skeet.dll и injector.exe
из одного архива. Native NL movement сохранён, его включение через отдельный
nl_movement_combined.lua. AI Peek поставляется отдельной ai_peek.lua, не включается
этой DLL и работает через публичный API. При AI Peek не использовать второй
наземный autopeek одновременно. Старые Lua native lag-records патчи оставить
выключенными для сравнения, чтобы не смешивать две реализации.

В архиве исходники, build_windows.py/build_tests.py и отчёты reports/.
Действительная игра, DLL entry и injector на этом стенде не запускались;
практические FPS/hit rate и сетевое поведение нужно проверить в игре.

Источник сведений о RecvProxy:
https://github.com/ValveSoftware/source-sdk-2013/blob/master/src/game/client/c_baseentity.cpp

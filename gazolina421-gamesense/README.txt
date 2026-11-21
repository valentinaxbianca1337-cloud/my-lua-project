GAZOLINA 421 — GameSense CS:GO, редакция 1.5

Файл: Gazolina421_gamesense.lua
Среда: GameSense CS:GO, LuaJIT 5.1. Не CS2.
Исходник: загруженный Gazolina421.lua для Neverlose v3.

ЗАПУСК

1. Выгрузи старую Gazolina, замени файл и загрузи новую Lua.
2. AA -> Anti-aimbot angles -> чекбокс Gazolina.
3. Один чекбокс включает всю Lua. Отдельной кнопки/бинда активации нет.

При первом запуске скрипт выключен. При выключении и выгрузке он возвращает
захваченные настройки GameSense и cvar. Профили и настройки сохраняются.
Штатные Anti-aimbot angles скрыты, пока Gazolina включена. На странице other
временно скрыты и штатные Fake lag / Other; при уходе с неё их видимость
восстанавливается. Значения Fake lag это скрытие не меняет.

ЧТО ИЗМЕНИЛОСЬ В 1.5

No Fall Damage удалён целиком: элемент меню, обработчик, вызов и зависимости.
В Other добавлен Unsafe Recharge, описанный ниже.
Удалены profile options и действия action/apply редактора профиля.
Команда редактора автоматически совпадает с командой локального игрока:
T -> профили T, CT -> профили CT. Вверху показана короткая метка T или CT.
При смене команды старые значения сохраняются до загрузки нового профиля.
Вне команды/сервера остаётся последняя выбранная команда, по умолчанию T.
State заменён одной полоской на 9 позиций с названиями состояний.

В стандартном правом блоке AA -> Other при открытом builder показана одна
кнопка: send to ct для T либо send to t для CT. Она копирует ВСЕ 9 состояний
текущей команды на противоположную, включая Pitch, yaw, body и defensive.
Последующее изменение исходной команды не изменяет скопированные значения.
Кнопка использует стандартные размеры GameSense. Публичный ui API не задаёт
произвольную ширину отдельных контролов; правки координат/размеров в память
в этом файле не используются.

BODY YAW И ЗАДЕРЖКИ

Диапазоны left/right и from/to теперь -58..58 градусов, default left=-58,
right=58. Старое усиление значения Body yaw в 3 раза удалено. Это запрашиваемое
значение штатного Body yaw; оно не обещает ровно такой измеренный desync при
любом движении/оружии/состоянии. Fake yaw limit, если доступен, получает модуль
того же значения, максимум 58.

off выключает Body yaw.
static удерживает выбранную сторону; inverter меняет её. По умолчанию jitter
выключен. При включении jitter появляется отдельная задержка 1..32 отправленных
тиков. Значения ближе к 1 переключают чаще, ближе к 32 — реже.
ticks переключает стороны через указанное число 1..32 отправленных тиков.
random выбирает длительность удержания от 1 до указанного максимума 1..32.
В ticks/random Body yaw не выключается периодически целиком, как в старом коде.
Режимы limit mode: default использует left/right, switch использует from/to,
random выбирает значение между from/to и удерживает его до очередного переключения.

Yaw и Body yaw имеют независимые часы. Body yaw не меняет последовательность
Left/Right Yaw и его задержку. Команды с chokedcommands>0 не продвигают эти часы.
Случайная задержка yaw выбирается на начало интервала, а не заново каждый тик.

У старых GS-пресетов положительные left/from преобразуются в отрицательную
сторону с ограничением 58, right/to — в положительную. Новые профили помечены
body_format=2: подписанные значения при повторном импорте не переинтерпретируются.

UNSAFE RECHARGE

Чекбокс находится на странице other в стандартном блоке AA -> Other.
Требуются gamesense/antiaim_funcs с get_double_tap и штатные ссылки Ragebot Enabled /
Double tap. При отсутствии зависимости включение отклоняется с пояснением в консоли.

После rage-выстрела по противнику (aim_fire) или локального weapon_fire с текущим
противником скрипт открывает ограниченное окно recharge при активном DT. Через
2 тика после последнего выстрела, если helper ещё сообщает, что DT не готов,
временно выключается Ragebot Enabled и cmd.force_defensive выставляется false.
Это даёт штатному DT возможность заряжаться и при доступном для выстрела враге.
Сам DT, его клавиша, лимит shift и сетевые структуры не переписываются.

Когда helper сообщает готовность, исходное состояние Ragebot возвращается.
Оно также возвращается при выключении чекбокса/DT/Lua, смерти, смене оружия,
смене карты, отключении, ошибке обработчика или по таймауту 0.75 секунды.
Fake duck исключает этот режим. Первый и второй выстрелы не отменяются входным
in_attack: обработчик ждёт 2 тика и не выключает DT.

Это пауза автоматической стрельбы ради штатной перезарядки, а не отдельный
публичный API мгновенного заряда. Скорость и результат зависят от сборки GS,
оружия и сервера. Во время паузы Ragebot не выбирает новые выстрелы.

МЕНЮ И ПОЛНОТА БИЛДЕРА

Первый список: anti-aim / other / configs.
Второй список anti-aim: builder / hotkeys / options. Отдельного tickbase нет.
В builder: метка команды, State, Pitch, Solo/Double, yaw jitter, body yaw,
body settings и defensive. Нет Add Yaw, Force Break LC и старого глобального
списка состояний Break LC. Shared ESP также удалён целиком.

Solo показывает один yaw offset, Double — left/right и apply delay.
Задержки yaw: Default / Random / Ways; все 10 timing сохранены отдельно.
Yaw jitter: off / center / offset / random / spin / 3-way / 5-way, рандомизация
значений и до 10 своих шагов. body settings раскрывает параметры Body yaw.
Defensive включает настройки бывшего Tickbase для выбранной команды/состояния:
Action Triggers, Hide Shots, Choke, Random и до 10 своих интервалов Choke.

Сохраняются 18 независимых профилей: T/CT × Standing, Running, Slowing,
Crouching, Sneaking, Air, Air Crouching, Manuals, Safe Head.
В каждом профиле 65 исходных полей с запрошенными изменениями GS-диапазонов,
а также Pitch, defensive_enabled и body_delay: 68 настроек. body_format —
метаданные миграции, а не дополнительный переключатель интерфейса.
У старых GS-пресетов без новых полей: Pitch=Down, defensive=false, body_delay=2.

hotkeys: Freestanding, Prefer Manual, Manual Yaw, направления и сброс.
Бинд Freestanding появляется после включения галочки в той же строке СПРАВА:
так расположен штатный inline-hotkey GameSense. Начальный режим — On hotkey;
назначь клавишу или выбери Always on. При выключении функции бинд скрывается.
Manual Left/Right/Forward включают направление по первому нажатию, повторное
нажатие его сбрасывает; Reset Manuals сбрасывает любое направление.
options: Anti-Bruteforce, Safe Head, Warmup AA.

other — одна страница, без дополнительных списков разделов:
Anti-aimbot angles: Viewmodel, Aspect ratio, Scope Overlay.
Fake lag: Hit marker, Manual Arrows, Keep Model Transparency, Extended Ping Spike.
Other: Move Lean, Jitter Legs, Fast Ladder, Unsafe Recharge, Grenade Release,
       Increase speed, Purchases, Damage Dealt.
Вложенные параметры появляются после галочки. Бинд Ping также встроен в строку.
Viewmodel, Aspect, Move Lean и Hit marker имеют рабочие чекбоксы. При импорте
старых GS-пресетов новые флаги выводятся из прежних настроек; новые пресеты
сохраняют явные флаги.

ПРЕСЕТЫ И СОХРАНЕНИЕ

configs: Search, список, Name, action и кнопка run. New/Save создают или обновляют
пресет, Load загружает, Delete удаляет, Sort меняет порядок. Export копирует
выбранный сохранённый пресет. Import применяет содержимое буфера; для сохранения
импорта введи Name и выполни Save. Запрошенное удаление action относится к Builder;
операции сохранения configs оставлены доступными.

JSON-пресеты: GAZOLINA_GS1: + JSON, формат v1 сохраняется.
Профили хранятся в обычных GS-конфигах через ui.new_string и в database.
Именованные пресеты локальны для database. Собственный JSON переносит настройки,
но не master и не назначение/режимы горячих клавиш; последние хранит GS-конфиг.
Импорт валидирует данные до применения и не исполняет Lua-код из буфера.
Старые Neverlose-пресеты PUI/MessagePack/LZSS/Z85 с этим форматом несовместимы.

БИБЛИОТЕКИ

gamesense/clipboard — буфер; при отсутствии есть адаптер VGUI_System010 для Windows/x86.
gamesense/trace + vector — Grenade Release.
gamesense/entity — Move Lean.
gamesense/csgo_weapons — параметры оружия, без библиотеки используются запасные значения.
gamesense/antiaim_funcs — определение готовности DT для Unsafe Recharge.

Необязательные библиотеки загружаются через pcall(require). При отсутствии нужной
зависимости соответствующий чекбокс выключается с сообщением в консоли.
Основной builder работает без них. Скрипт ничего не скачивает сам.

ОТЛИЧИЯ API NEVERLOSE / GAMESENSE

Интерфейс использует стандартный ui GS, без PUI/вложенных gear-окон Neverlose.
Body yaw, desync, pitch и внутренние exploit-политики двух клиентов различаются.
3-Way/5-Way/Spin рассчитываются скриптом; остальные jitter используют штатный GS.
Defensive использует cmd.force_defensive и доступный DT fake lag limit. Политики
Hide Shots: Favor Fire Rate восстанавливает лимит, Favor Fake Lag задаёт 2,
Break LC задаёт 1. Custom Choke сохраняет выбранный интервал. Внутренняя зарядка
Neverlose и идентичный серверный таймер этим не воспроизводятся.
Warmup Fake Up/Down сопоставлены Up/Down GS.
Grenade Release сохраняет расчёты броска/отскоков и проверки целей; движение
игрока экстраполируется с трассировками вместо simulate_movement Neverlose.
Keep Model Transparency временно меняет alpha m_clrRender и возвращает после кадра;
нет идентичного localplayer_transparency callback и weapon-chams Neverlose.
Scope Overlay использует renderer.gradient. Отдельный Console-шрифт API не даёт.
Extended Ping Spike управляет штатным Ping spike, не обходит ограничения сервера.
aim_hit/aim_miss заменяют aim_ack. Safe Head использует существующий девятый профиль.

ПРОВЕРКА

Синтаксис и запуск проверены настоящим LuaJIT 2.1 / Lua 5.1 через lupa.
Пройдены 88 сценариев на модели GameSense API: 35 основных, 6 вариантов окружения,
13 расширенных builder-сценариев, 16 сценариев общего меню и 18 сценариев 1.5.
Последние включают авто-команду без потери данных, отправку всех 9 состояний,
диапазоны -58..58, стабильный Static, интервалы 1/32, choked-команды, независимость
таймеров yaw/body, миграцию, recharge и восстановление Ragebot при завершении,
таймауте, выключении, смерти, смене оружия и ошибке helper.
Дополнительно выполнены 3402 сочетания builder-режимов по всем 18 профилям.
1170 определений исходных полей сверены с явными исключениями диапазонов/default,
изменённых по запросу. Подробности: BUILDER_COVERAGE.txt.

GameSense и CS:GO в рабочей среде отсутствуют. Внешний вид и поведение в настоящем
клиенте не проверены; имитация API не заменяет игровой тест. Для ошибки загрузки
нужен точный текст консоли со строкой и версия/сборка клиента.

API ДЛЯ СВЕРКИ

https://gamesensical.gitbook.io/docs/developers/globals/ui
https://gamesensical.gitbook.io/docs/developers/development/events
https://gamesensical.gitbook.io/docs/developers/globals/entity
https://gamesensical.gitbook.io/docs/developers/globals/client
https://gamesensical.gitbook.io/docs/developers/globals/cvar
https://gamesensical.gitbook.io/docs/developers/globals/renderer
https://github.com/ValveSoftware/source-sdk-2013/blob/master/src/public/vgui/ISystem.h
https://neverlose.gitbook.io/neverlose

Основной источник конкретной логики Neverlose — загруженный исходник CS:GO;
старые адреса документации v3 могут перенаправлять на CS2.

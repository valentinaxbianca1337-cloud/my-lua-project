GAZOLINA 421 — GameSense CS:GO, редакция 1.6

Файл: Gazolina421_gamesense.lua
Среда: GameSense CS:GO / LuaJIT 5.1, не CS2.
Исходник: загруженная Gazolina421.lua для Neverlose v3.

ЗАПУСК И OVERRIDE

1. Выгрузи предыдущую Lua, замени файл и загрузи новую.
2. AA -> Anti-aimbot angles -> Gazolina включает всю Lua.
3. anti-aim -> builder -> Override включает именно builder анти-аимов.
4. Под Override находится выпадающий список State. Выбери состояние и настрой его.

Override ОДИН на весь builder. Он не привязан к выбранному State и не меняется
при переключении списка. При выключении Override скрипт сразу возвращает
захваченные значения штатных AA и показывает их меню. Функции Other продолжают
работать, пока включён основной чекбокс Gazolina. Новый скрипт по умолчанию
загружается с выключенными Gazolina и Override.

У каждой команды используются ОДНИ И ТЕ ЖЕ девять профилей:
Standing / Running / Slowing / Crouching / Sneaking / Air / Air Crouching /
Manuals / Safe Head. T/CT, метка команды и send to ct/t удалены.
Нет профиля Shared и отдельных Override по состояниям.

State в меню выбирает редактируемый профиль. В игре состояние определяется
автоматически по движению, приседанию, slow motion, manual и Safe Head.
Просмотр Air в меню не заставляет стоящего игрока использовать Air.
Смена команды не переключает редактор и не меняет набор настроек.

DEFENSIVE И РАЗМЕТКА

Defensive удалён из билдера полностью: переключатель, Choke, Random Choke,
поля всех 10 Choke-шагов, Action Triggers / Hide Shots и обработчик принудительного
defensive. Скрипт больше не меняет Double tap fake lag limit ради этих настроек.
Unsafe Recharge остался отдельной функцией Other; в его окне выставляется
cmd.force_defensive=false, без активации удалённого режима.

Override и State — стандартные ui.new_checkbox/ui.new_combobox. В публичном API
нет inline-размещения combobox справа от чекбокса или настройки его координат.
Поэтому State размещён компактным списком БЕЗ дополнительной подписи сразу
под Override. Расположение в одной строке и gear-кнопка с примера не воспроизведены.
Приватные адреса MENU_BASE, изменения памяти меню и сигнатурные сканы не используются.

МЕНЮ

Вся Lua находится во вкладке AA.
Первый список: anti-aim / other / configs.
Второй список anti-aim: builder / hotkeys / options.
При выключенном Override редактор скрыт, список State остаётся доступен.
При включённом Override показываются Pitch, Solo/Double, yaw jitter, Body yaw.
По умолчанию нет длинного столбца кнопок и нет profile options/action/apply в Builder.

Solo — один yaw offset; Double — left/right и apply delay.
Default / Random / Ways сохраняют до 10 отдельных timing.
Yaw jitter: off / center / offset / random / spin / 3-way / 5-way, рандомизация
и до 10 своих значений. Значения сохраняются при закрытии вложенных настроек.
Всего 50 полей на профиль: оставшиеся yaw/body-поля исходника плюс Pitch и body_delay.
Удалённые по запросу defensive-поля не считаются отсутствующей функциональностью.

BODY YAW

left/right и from/to имеют диапазон -58..58; defaults -58/+58.
Старое усиление Body yaw в 3 раза удалено. Это запрашиваемый штатный Body yaw,
а не гарантия измеренного desync при любых движении/оружии/состоянии.
Fake yaw limit при наличии получает модуль значения с максимумом 58.

off — выключить Body yaw.
static — удерживать сторону, inverter меняет её. По умолчанию jitter выключен.
При включении jitter появляется его задержка 1..32 отправленных тиков.
ticks — переключать стороны через заданное число 1..32 отправленных тиков.
random — выбирать время удержания от 1 до выбранного максимума 1..32.
Тики ближе к 1 дают частые переключения, ближе к 32 — более длинное удержание.
Body yaw не выключается периодически целиком в ticks/random.
limit mode default использует left/right; switch использует from/to;
random выбирает значение между from/to и удерживает его до очередного переключения.

Таймеры yaw и body независимы. Body yaw не меняет последовательность yaw.
Choked-команды не продвигают их часы. Случайная задержка yaw выбирается на
интервал, а не заново каждый тик. При смене игрового состояния таймеры сбрасываются.
В старых unsigned-профилях left/from становятся отрицательными, right/to —
положительными, максимум 58. body_format=2 отмечает уже подписанные значения.

HOTKEYS / OPTIONS / OTHER

hotkeys: Freestanding и его настройки, Manual Yaw, направления и Reset Manuals.
Бинд FS появляется после галочки в той же строке СПРАВА — штатный inline-hotkey.
Начальный режим On hotkey: назначь клавишу или выбери Always on.
Manual Left/Right/Forward включают направление по первому нажатию, повторное
нажатие сбрасывает. Reset Manuals сбрасывает любое направление.
При выключенном Override эти AA-функции не подменяют штатные углы.
options: Anti-Bruteforce, Safe Head, Warmup AA. Они применяются только при Override.

other — одна страница, чекбоксы распределены по трём штатным блокам AA:
Anti-aimbot angles: Viewmodel, Aspect ratio, Scope Overlay.
Fake lag: Hit marker, Manual Arrows, Keep Model Transparency, Extended Ping Spike.
Other: Move Lean, Jitter Legs, Fast Ladder, Unsafe Recharge, Grenade Release,
       Increase speed, Purchases, Damage Dealt.
Параметры раскрываются после галочки. На странице other штатные Fake lag/Other
временно скрыты и восстанавливаются при уходе, выключении или выгрузке.
Само скрытие не меняет их значения. No Fall Damage и Shared ESP удалены.

UNSAFE RECHARGE

Нужен gamesense/antiaim_funcs с get_double_tap и штатные Ragebot Enabled / DT.
Без зависимости включение отклоняется с пояснением в консоли.
После rage-выстрела по противнику или локального weapon_fire с текущим противником
открывается окно recharge при активном DT. Через 2 тика после последнего выстрела,
если helper ещё сообщает неготовность DT, временно выключается Ragebot Enabled
и выставляется cmd.force_defensive=false. Так native DT может заряжаться и при
доступном для выстрела враге. DT и его бинд не выключаются; in_attack не блокируется.
Когда helper сообщает готовность, исходный Ragebot возвращается. Возврат также
происходит при выключении функции/DT/Lua, смерти, смене оружия, карты, отключении,
ошибке helper или таймауте 0.75 секунды. Fake duck исключает этот режим.
Это пауза автоматической стрельбы ради штатной зарядки, не мгновенный recharge API.
Его скорость и результат зависят от клиента, оружия и сервера.

ПРЕСЕТЫ И ПЕРЕНОС СТАРЫХ НАСТРОЕК

Новый формат: GAZOLINA_GS2: + JSON, version=2, profiles[State].
Импорт принимает также старый GAZOLINA_GS1 с T/CT. При переносе выбираются
девять CT-профилей, если локальный игрок сейчас CT; иначе — девять T-профилей.
После переноса они применяются обеим командам. Override включается для сохранения
прежнего поведения старого builder. Удалённые defensive-поля больше не применяются.

Полный последний успешно перенесённый v1-пресет, включая ОБЕ команды и старые
поля, сохраняется в database ключом gazolina421_gamesense_v1_legacy_v1_backup.
Старые именованные пресеты остаются в базе в своём исходном формате, пока их
явно не пересохранить. Некорректные данные не меняют живые профили и backup.

configs сохраняет Search, список, Name и действия New/Save/Load/Delete/Export/
Import/Sort через одну кнопку run. Export выдаёт версию выбранного сохранённого
пресета. Import применяет данные из буфера; для отдельного сохранения нажми Save.
Собственный JSON сохраняет Override, профили и настройки. Основной Gazolina и
назначения/режимы горячих клавиш сохраняются средствами GS-конфига.
Профили хранятся также через ui.new_string и database. Старое имя storage-поля
сохранено для загрузки прежних GS-конфигов, содержимое записывается в формате v2.
Импорт не исполняет Lua-код. Neverlose PUI/MessagePack/LZSS/Z85-пресеты несовместимы.

БИБЛИОТЕКИ И РАЗЛИЧИЯ API

gamesense/clipboard — буфер; запасной VGUI_System010-адаптер Windows/x86.
gamesense/trace + vector — Grenade Release.
gamesense/entity — Move Lean.
gamesense/csgo_weapons — параметры оружия, иначе запасные значения.
gamesense/antiaim_funcs — готовность DT для Unsafe Recharge.
Необязательные библиотеки загружаются через pcall(require). При отсутствии нужной
зависимости соответствующая функция явно выключается с пояснением в консоли.
Основной builder использует встроенный API. Lua ничего не скачивает сама.

Внутренние desync/анимации/exploit-алгоритмы GS и Neverlose отличаются.
3-Way/5-Way/Spin рассчитываются скриптом; другие jitter используют штатный GS.
Warmup Fake Up/Down сопоставлены Up/Down. Grenade Release использует расчёты
броска/отскоков и трассировки с экстраполяцией вместо simulate_movement Neverlose.
Keep Model Transparency временно меняет m_clrRender и восстанавливает его после
кадра; штатные chams могут перекрыть эффект. Scope использует renderer.gradient.
Отдельного Console-шрифта API не даёт. Ping не обходит ограничения сервера.
aim_hit/aim_miss заменяют aim_ack. Safe Head использует девятый профиль.

ПРОВЕРКИ

LuaJIT 2.1 / Lua 5.1: 34 базовых сценария, 6 вариантов окружения, 14 сценариев
Body yaw/Unsafe Recharge и 16 сценариев глобального Override/общих профилей.
Итого 70 сценариев на модели GS API. Проверены независимость State, применение
одних профилей T/CT, возврат штатных AA без выключения Other, перенос v1->v2,
backup, отклонение невалидных данных и сохранение всех полей девяти профилей.
Дополнительно выполнены 3402 сочетания yaw/body-режимов по обоим игровым team ID.
Схема оставшихся исходных полей сверена с Lua Neverlose; удаление defensive
учтено явно. Подробности: BUILDER_COVERAGE.txt.

Сам GameSense и CS:GO здесь отсутствуют. Внешний вид и игровой результат не
проверены настоящим клиентом; модель API не заменяет такую проверку. Для ошибки
нужен точный текст консоли со строкой и версия/сборка клиента.

ДОКУМЕНТАЦИЯ

https://gamesensical.gitbook.io/docs/developers/globals/ui
https://gamesensical.gitbook.io/docs/developers/development/events
https://gamesensical.gitbook.io/docs/developers/globals/entity
https://gamesensical.gitbook.io/docs/developers/globals/client
https://gamesensical.gitbook.io/docs/developers/globals/cvar
https://gamesensical.gitbook.io/docs/developers/globals/renderer
https://github.com/ValveSoftware/source-sdk-2013/blob/master/src/public/vgui/ISystem.h
https://neverlose.gitbook.io/neverlose
Конкретная логика старого Neverlose CS:GO сверяется с загруженным исходником.

GAZOLINA 421 — GameSense CS:GO
============================

Файл: Gazolina421_gamesense.lua
Редакция: 1.3. Формат JSON-пресетов остаётся v1, ранее созданные GS-пресеты сохраняются.
Исходник: загруженный пользователем Gazolina421.lua, 4413 строк.
Цель: GameSense для CS:GO, LuaJIT 5.1. Это не версия для CS2.

ЗАПУСК

1. Помести Gazolina421_gamesense.lua в папку Lua-скриптов своего GameSense.
2. Обнови список скриптов в клиенте и загрузи файл.
3. Перезагрузи Lua после замены файла и открой AA -> Anti-aimbot angles.
4. Включи единственный чекбокс Gazolina. Он один управляет работой всей Lua.
5. При выключенном чекбоксе остальные элементы Lua скрыты. Штатные элементы
   Anti-aimbot angles скрываются при включении Gazolina и возвращаются при
   выключении либо выгрузке. Группы Fake lag и Other это скрытие не затрагивает.

Отдельная кнопка переключения и общая горячая клавиша активации удалены.
Горячие клавиши отдельных функций (Manuals, Freestanding, Ping) сохранены.

Скрипт загружается выключенным при первом запуске. При выключении, выгрузке,
смене карты и отключении от сервера он возвращает захваченные значения
параметров GameSense и cvar. Собственные настройки и профили сохраняются.
Как и другие Lua с управлением AA, скрипт следует использовать без одновременно
работающего второго конструктора, меняющего те же параметры.

МЕНЮ

Весь интерфейс Lua размещён в AA -> Anti-aimbot angles.
Навигация соответствует второму предоставленному скриншоту: два обычных
выпадающих списка сверху, без столбца кнопок AA/Other/Configs/Builder/… .
Первый список: anti-aim / other / configs.
Второй список anti-aim: builder / tickbase / hotkeys / options.

Начальный экран builder:
  profile options
  state
  pitch
  yaw offset
  ~ add yaw
  yaw jitter
  body yaw
  force break lc
  defensive settings

По умолчанию кнопок на основном экране билдера нет. Оформление использует
штатные элементы ui GameSense. Запись размеров в память, MENU_BASE, inline-
адаптер версии 1.2 и его запасной вариант с длинным столбцом удалены.

profile options открывает Team, список действий и одну кнопку apply.
Действия: Copy / Paste / Other team / Reset / Shuffle timing / Shuffle offsets /
Shuffle choke. Они выполняются только нажатием apply. Выбранные Team и State
определяют редактируемый профиль. По умолчанию редактируется T / Standing.
Игра использует профиль текущей команды и текущего состояния автоматически.

Сохраняются 18 профилей: T/CT × Standing, Running, Slowing, Crouching, Sneaking,
Air, Air Crouching, Manuals, Safe Head. Все 65 исходных параметров сохранены;
дополнительно у каждого профиля появился Pitch: off / down / up / minimal /
random. Старые пресеты v1 без этого поля получают Pitch = Down.

~ add yaw переключает исходный режим yaw между Off и Dual. При включении
раскрываются Left/Right Yaw и настройки задержки Default / Random / Ways.
Yaw jitter сохраняет исходные модификаторы и их рандомизацию.
Body yaw объединяет исходные Body Yaw и Mode: off / static / ticks / random.
body settings раскрывает Jitter, Inverter, тики и пределы. Закрытие этих настроек
не выключает Body Yaw и не стирает значения.

force break lc меняет наличие выбранного State в исходном списке Break LC;
как в оригинале, список состояний Break LC общий для команд. defensive settings
раскрывает настройки Action Triggers, Hide Shots, Choke и рандомизации в этом же
билдере. Это раскрытие настроек, а не добавленный неподтверждённый режим hidden AA.
Все параметры Tickbase также доступны через второй верхний список -> tickbase.

hotkeys: Freestanding, Prefer Manual, Manual Yaw и клавиши направлений.
options: Anti-Bruteforce, Safe Head, Warmup AA; подраздел выбирается списком.
other: Animations, Movement, Visuals, Log Events, Shared ESP.
Visuals разделён на View / Scope / Hits / Arrows / Extra обычным списком.
configs: Search, список, Name, список действий New/Save/Load/Delete/Export/Import/
Sort и одна кнопка run. Старые операции пресетов сохранены без отдельной кнопки
для каждой операции.

Manual Left/Right/Forward: используй On hotkey; первое нажатие задаёт направление,
повторное нажатие той же клавиши сбрасывает его. Reset Manuals сбрасывает выбор.
Manual Yaw можно выбрать и вручную. Ручное направление перекрывает yaw offset
профиля Manuals, как в исходной логике.

БИБЛИОТЕКИ

Основной AA и обычные визуальные функции используют встроенный API GameSense.
Neverlose/PUI/HTTP/HMAC/inspect/smoothy не нужны. Скрипт ничего не скачивает.

Дополнительные библиотеки загружаются через pcall(require):
  gamesense/clipboard    — Copy/Paste и Import/Export; при отсутствии используется
                          встроенный адаптер VGUI_System010 на Windows/x86.
  gamesense/trace + vector — No Fall Damage и Grenade Release.
  gamesense/entity       — Move Lean.
  gamesense/csgo_weapons — точные параметры скорости оружия/броска гранаты.

Используй соответствующие библиотеки GameSense из доверенного источника
клиента/его Workshop. Если библиотека отсутствует, скрипт всё равно загружается.
No Fall Damage / Grenade Release без trace, Move Lean без entity и Extended Ping
Spike без штатного reference явно выключаются с пояснением в консоли. Они не
остаются включёнными без действующего обработчика. После установки зависимости
перезагрузи Lua. Если недоступны оба способа доступа к буферу, кнопки сообщат ошибку.
Без csgo_weapons применяются запасные значения скорости.

ПРЕСЕТЫ И КОНФИГИ

Presets: Search, список, Name, New/Save, Load, Delete, Sort, Import/Export.
Save создаёт или обновляет пресет с указанным Name. Export экспортирует выбранный
сохранённый пресет. Import применяет данные из буфера, но не создаёт запись:
для сохранения импортированного пресета введи Name и нажми Save.

Формат пресета: GAZOLINA_GS1: + JSON.
Формат отдельного состояния: GAZOLINA_STATE1: + JSON.
Импорт проверяет формат, версию, команды, состояния и значения до применения.
Исполняемый Lua-код из буфера не запускается.

18 профилей сохраняются также внутри обычного конфига GameSense через
ui.new_string и обработчики pre_config_save/post_config_load.
Текущие настройки и список именованных пресетов сохраняются в database GameSense.
Именованные пресеты хранятся локально в database, а не внутри каждого GS-конфига.
Клавиши и их режимы сохраняются обычным конфигом GameSense; собственный JSON
пресет переносит значения настроек, но не назначения горячих клавиш и не Enable.
Дата пресета включает время компьютера и Unix timestamp.

СТАРЫЕ пресеты Neverlose не совместимы: в исходнике используется PUI +
MessagePack + LZSS/Z85. Их сериализация и внутренние пути не совпадают с этим
редактором GameSense. Импорт такого пресета возвращает ошибку, не применяя его.

ЧТО ОТЛИЧАЕТСЯ ОТ NEVERLOSE

Это перенос с максимально близкими настройками, а не обещание идентичного
поведения двух разных движков чита.

1. Интерфейс построен на штатном ui GameSense. Вложенные gear-окна заменены
   обычными выпадающими списками и раскрываемыми параметрами. Названия,
   варианты, диапазоны и цвета
   сохранены по возможности. FontAwesome, исходная боковая панель с UID,
   welcome.png и разметка Neverlose не перенесены.

2. Body Yaw: знак стороны и пределы преобразуются в Static body yaw GameSense.
   Jitter стороны рассчитывается скриптом. При наличии Fake yaw limit он также
   задаётся. Внутренний desync/анимации/пределы двух клиентов различаются.

3. 3-Way и 5-Way рассчитываются как последовательности yaw offset. Spin
   рассчитывается скриптом. Остальные модификаторы используют Yaw jitter GS.
   Идентичность формы и тайминга внутренним модификаторам Neverlose не заявляется.

4. Break LC использует force_defensive и доступные настройки Double tap GS.
   Таймер строится по globals.tickcount(), поскольку server_tick Neverlose
   не доступен как тот же источник данных. Hide Shots:
     Favor Fire Rate — восстановить исходный Double tap fake lag limit;
     Favor Fake Lag  — Double tap fake lag limit = 2;
     Break LC        — Double tap fake lag limit = 1; force_defensive следует
                       выбранному интервалу Choke и Action Triggers.
   В режиме Custom выбор Hide Shots -> Break LC не отменяет настроенный интервал.
   Это приближение; внутренние политики Neverlose не экспортируются GS API.
   Флаг force_defensive зависит от поддержки конкретной сборкой GameSense
   и активного Double tap/On shot anti-aim.

5. Warmup Fake Up/Fake Down сопоставлены обычным Up/Down GameSense. Отдельный
   режим fake-pitch Neverlose таким сопоставлением не воспроизводится.

6. Grenade Release: сохранены расчёты броска, гравитация, отскоки, проверка
   HE-урона, близости противника для огня и дыма возле огня. simulate_movement
   Neverlose заменён ограниченной экстраполяцией игрока с hull-трассировками.
   Точная симуляция команд, jitter_move и exploit charge Neverlose недоступны.
   Это приближение, особенно для движения игрока и попаданий в других игроков.

7. No Fall Damage переносит логику попытки jumpbug. Результат зависит от карты,
   сервера и физики; название сохранено из исходника и не означает гарантии.
   Increase speed ограничивает ввод скоростью fakeduck; не увеличивает слабый
   ввод до максимума. Отсутствующий createmove_run не подменяется чужим событием.

8. Keep Model Transparency временно изменяет alpha сетевого m_clrRender своего
   игрока и возвращает его после кадра. Нет callback localplayer_transparency
   Neverlose и принудительных weapon-chams. Собственные chams GameSense могут
   переопределить этот эффект.

9. Scope Overlay использует renderer.gradient; шрифты стрелок используют
   доступные флаги renderer.text. Console сохранён в списке, но отображается
   обычным шрифтом GS: отдельный шрифт Console этот API не предоставляет.

10. Extended Ping Spike управляет штатным Ping spike, его клавишей и величиной,
    когда соответствующие reference доступны. Пределы сервера не обходятся.

11. Протокол Shared ESP Gazolina из Neverlose не перенесён. Публичный API
    GameSense не предоставляет тот же voice_message/voice buffer. Подменять
    его бездействующим переключателем или переносить внутренние структуры
    памяти Neverlose было бы некорректно. Shared ESP здесь включает штатную
    функцию GS, если её reference найден. Apply GS Shared ESP как мост в
    Neverlose в самом GameSense не требуется. Обмен Gazolina с Neverlose этим
    скриптом НЕ поддерживается.

12. Новые события aim_hit/aim_miss заменяют aim_ack Neverlose. Текст логов близок
    к исходнику, но часть данных доступна только из соответствующего aim_fire.

ИСПРАВЛЕНИЯ ОШИБОК ИСХОДНИКА

  Safe Head использует девятый профиль, а не несуществующий десятый.
  Список состояний не изменяется при создании меню Freestanding.
  Taser проверяет отдельное условие Taser, а не Knife.
  Anti-Bruteforce реально применяет смещение после близкого выстрела на 3 секунды;
  cmd не передаётся вместо контекста AA.
  Рандомизация принимает границы в любом порядке.
  Выключение Scope Overlay возвращает штатную настройку.
  Циклы симуляции ограничены; начальные hitmarker не рисуются без попадания.
  Любая ошибка игрового обработчика выключает скрипт и пытается восстановить
  захваченные настройки; подробность выводится в консоль с префиксом [Gazolina].

ПРОВЕРКА

Синтаксис проверен настоящим LuaJIT 2.1 / Lua 5.1 через lupa.
35 основных сценариев пройдены на имитации GameSense API: меню, независимость
профилей, Copy/Paste, AA, девять состояний, задержки, модификаторы, лимиты,
anti-bruteforce, defensive, warmup, ladder, fall, grenade release, fakeduck,
cvar, анимации, отрисовка, логи, пресеты, невалидные данные, конфиги,
выключение/горячая клавиша/смерть/disconnect/shutdown.
Дополнительно проверяются отсутствие необязательных библиотек/reference,
вариант Freestanding с checkbox, значения cvar вне диапазона редактора,
настоящая JSON-сериализация, полный обход 18 профилей и аварийное выключение.
Все шесть дополнительных сценариев также пройдены.

В редакции 1.1 добавлено ещё 13 сценариев: независимость всех значений,
сброс состояния, доступность редактора Safe Head, комбинации режимов,
Custom Choke с Hide Shots -> Break LC, Freestanding со строковым селектором,
Ping spike с двумя reference и восстановлением hotkey mode, явная обработка
недостающих trace/entity, приоритет одновременно нажатых клавиш, reload без
доступного netprop, сброс временного состояния и адаптер буфера обмена.
В редакции 1.3 меню проверено ещё 17 сценариями: отсутствие видимых кнопок в
начальном билдере, порядок элементов как в образце, надписи anti-aim/builder/down/
off, отсутствие приватного адаптера, раскрытие действий, привязки Add Yaw и
Body Yaw, сохранение исходных параметров, Force Break LC для выбранного State,
настройки defensive в билдере, Pitch по профилям и его передача в настоящий
reference-мок, миграция старых пресетов, профильные действия, действия пресетов,
скрытие и восстановление штатных контролов, один чекбокс и выгрузка.
Итого: 71 сценарий на модели GameSense API, включая прежние 54 сценария логики.
Внутри проверки режимов выполнены 3402 комбинации.

Схема исходного меню извлечена из загруженной Lua отдельным скриптом и сверена
с редактором: 18 профилей по 65 исходных параметров, всего 1170 определений.
Проверены ключи, типы, диапазоны, списки и начальные значения. Исходные параметры
не удалены. Новый Pitch даёт 66 параметров на профиль. См. BUILDER_COVERAGE.txt.

Сам GameSense и CS:GO в рабочей среде отсутствуют. Запуск в настоящем клиенте,
наличие конкретных reference, поведение библиотек и результат в игре здесь
не проверены. Тесты с имитацией API не заменяют этот этап. Для ошибки запуска
нужен точный текст консоли с номером строки и название сборки GameSense.

ИСТОЧНИКИ ДЛЯ СВЕРКИ API

GameSense UI:
https://gamesensical.gitbook.io/docs/developers/globals/ui
GameSense events:
https://gamesensical.gitbook.io/docs/developers/development/events
GameSense entity:
https://gamesensical.gitbook.io/docs/developers/globals/entity
GameSense client:
https://gamesensical.gitbook.io/docs/developers/globals/client
GameSense cvar:
https://gamesensical.gitbook.io/docs/developers/globals/cvar
GameSense renderer:
https://gamesensical.gitbook.io/docs/developers/globals/renderer
Интерфейс буфера обмена Source / VGUI:
https://github.com/ValveSoftware/source-sdk-2013/blob/master/src/public/vgui/ISystem.h
Архивная официальная документация Neverlose:
https://neverlose.gitbook.io/neverlose
Ранее опубликованная документация Neverlose v3:
https://lua.neverlose.cc/
https://docs-csgo.neverlose.cc/
На дату работы старые адреса документации v3 недоступны либо перенаправляют
на CS2. Их актуальное содержимое не выдаётся за документацию исходного CS:GO
API. Для конкретной логики Neverlose опорным материалом был загруженный исходник.

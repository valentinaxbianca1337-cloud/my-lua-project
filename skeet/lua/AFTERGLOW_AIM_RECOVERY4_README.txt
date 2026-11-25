Afterglow Aim Recovery 4

Это восстановительный вариант имеющейся afterglow.lua, а не новый resolver.
Использовать ВМЕСТО старой Lua, после полного перезапуска игры. Не загружать
старый afterglow.lua одновременно: другой экземпляр может снова ставить патчи.

Основной builder, обычные manual/freestanding, конфиги, оформление и логгер
сохранены в исходнике. Названия причин промаха не переименованы. Полное поведение
меню/AA в реальной игре после изменений ещё не проверено.

Что отключено
Блокируются entrypoints Native Air Strafe, Accurate Quick Stop, Shot Delay Fix,
DT Stability/Return Fix, Preserve Animation Flags, Air Autostop, Scan Accuracy,
Spread & Autostop, Backtrack Record Fix/Lag Records, Force Shot, Custom Quick
Switch, Defensive DT on Peek, Hide Shots Fakelag Fix. Импорт конфига не может
снова включить их enabled-флажки. Общая функция записи этих патчей возвращает
отказ. Их старый код сохранён для аудита, но соответствующие обработчики не работают.

Также отключены Extended yaw/Flick/Defensive AA exploits, break-lc memory limit,
скриптовый Reset Fake Lag on Shot, duck-peek mode override, Animation Breaker,
скриптовый Performance Optimizer и Unlock Hidden Cvars. Регистрация Force
Teammate Aimbot override удалена. Обычные AA-настройки остаются за builder/native.
Hitchance, min damage и multipoint автоматически на новые числа не выставляются.
Другие Lua/загруженные конфиги всё ещё могут менять их независимо от этой версии.

Почему
Старый Force Shot мог переключать Safe point/Delay shot. Старые record-патчи
расширяли допуск разрыва позиции/промежутков записей. Эти изменения сами по себе
не доказывают причину каждого промаха, но их нельзя смешивать со штатной проверкой.
Данный вариант прекращает их применение, а не придумывает другой набор чисел.
Оставшиеся FFI/GUI/visual библиотеки не удалены: это не заявление, что вся Lua
стала полностью свободна от любых обращений к native API.

Проверка
Полная Lua компилируется LuaJIT 2.1. Изолированный слой блокировки проверен на
396 вызовах методов 22 модулей и попытках включения через конфиг. В этих проверках
записей в память не было. Сам Afterglow с настоящими GameSense/PUI и библиотеками
в игре здесь не запускался. Нельзя по этому тесту объявлять исправленными все
correction/prediction error либо обещать повышение hit rate.

Установка
1. Снять автозагрузку старых Lua и полностью закрыть игру. Заменить DLL+injector комплектом Aim Recovery 4.
2. Первый короткий запуск сделать без Lua: проверить исходный путь стрельбы.
3. Затем загрузить только afterglow_aim_recovery.lua. AI Peek, NL movement,
   старый afterglow и другие Lua native aiming fixes пока не загружать.
Полный перезапуск нужен, потому что ранее установленные изменения памяти
не исчезают от простой замены файла на диске. Чужие патчи эта Lua не восстанавливает.

Тесты: Python + lupa==2.8, python tests/test_quarantine.py.

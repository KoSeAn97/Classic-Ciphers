# Classic ciphers
### Шифры Цезаря, Вижинера, Плэйфера, Полибия и маршрутной перестановки

## Запуск программы отдельно в терминале
    # Для создания экземпляра программы выполнить
        make all
    # Запуск
        ./program
    # Доступна команда
        make clean

## Комментарии к реализации
* **Шифр Цезаря**  
    Корректно обрабатывает случаи с прописными и строчными буквами латиницы
    и кириллицы.
    Все символы, не являющиеся буквой оставляет без изменений.
    Присутствует виртуальная функция, которая никак не влияет на работу
    алгоритма. Необходима для реализации шифра Виженера.

* **Шифр маршрутной перестановки**  
    Корректно обрабатывает случаи с прописными и строчными буквами латиницы
    и кириллицы.
    Разделений на буквы и прочие символы отсутствует.

* **Квадрат Полибия-1**  
    Корректно обрабатывает латиницу и кириллицу. Символ `J` заменен на `I`.
    При обработке сообщения в любом направлении приводит его к верхнему регистру.
    Все символы, не являющиеся буквой оставляет без изменений.

* **Квадрат Полибия-2**  
    Корректно обрабатывает только латиницу. Символ `J` заменен на `I`.
    Сообщения приводятся к верхнему регистру.
    Прочие символы отбрасываются.

    Случай с кириллицей (пример):  
    в случае нахождения в определенном месте подстроки `ЕЕ` становится
    невозможным однозначное кодирование не выходя из заданного алфавита.

* **Шифр Вижинера**  
    Реализация целиком опирается на реализацию шифра Цезаря.
    Хранится вектор из сдвигов, который определяется по кодовому слову
    в соответствии с языком и регистром конкретной буквы этого слова.
    В случае, когда в кодовом слове встречаются прочие символы, сдвиг берется
    равным разности номера этого символа и номера символа `space`

* **Шифр Плейфера**  
    Определен для английского языка. Все сообщение приводится к верхнему регистру.
    Корректно обрабатываются включения в текст прочих символов. Они остаются
    в тексте без изменений. Символ `J` заменен на `I`.
    Необходимо заметить, что обратный алгоритм не является детерминированным,
    в некоторых случаях возможно вкрапление символа, заданного алгоритму, как
    символ наиболее редко встречающийся в тексте `X`.

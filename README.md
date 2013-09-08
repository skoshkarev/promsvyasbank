promsvyasbank
=============

Интеграция с платежным шлюзом Промсвязьбанка

- psb_config.php - файл конфигурации;
- psb.inc.php - сам класс

Использование класса:

1) Установить актуальные значения в файле psb_config.php;
 - PSB_TERMINAL;
 - PSB_MERCHANT;
 - PSB_MERCHANT_NAME;
 - PSB_MERCHANT_EMAIL;
 - PSB_KEY;
 - PSB_BACK_REF - адрес, на который платежный шлюз будет редиректить после завершения операции;
 - PSB_SANDBOX - true для тестовой среды;
 - PSB_LOG_ENABLED - true, если хотите писать в лог все POST ответы, которые присылает шлюз банка;
 
1) Подключить класс любым удобным способом:
```php
    require_once 'psb_config.php';
    require_once 'psb.inc.php';
```
2) Обработка любых ответов от банка:

Следующий участок кода следует разместить там, куда будут приходить POST уведомленя об операциях (спросить отдел электронной коммерции PSB).

```php
    $psb = new Psb();
    $psb -> process_answer();
```

Для последующей кастомизации и подстроек с удовольствием редактируйте метод 'process_answer'.

3) Покупка:

Существует 3-хминутный интервал, в течение которого по одной карте можно совершить только 1 операцию
Платежный шлюз, посылая ответ на указанные URL, каким - то магическим образом определяет, жив ли сервер или нет (говорят, у него есть 7 попыток)

Необходимо указать всего 3 параметра для передачи в метод класса
- amount - сумма покупки в рублях;
- order - номер заказа/покупки;
- desc - описание заказа.
- backref - страница, на которую пользователь может вернуться по завершению платежа

```php
  $config = array(
      'amount'    =>  29,
      'order'     =>  rand(10000000000, 100000000000),
      'desc'      =>  'desc',
      'backref'   =>  'www.yoursite.com'
  );
  $psb = new Psb($config);
  $psb -> purchase();

```
Класс автоматически сгенерирует HTML форму со всеми нужными полями (скрытыми) и сразу отправит ее на страницу оплаты.

4) Отмена покупки:

Скорее всего, эта операция будет полезна для панели администратора, т.к. давать возможность покупателям отменять покупку с автоматическим возвратом - самоубийство.

Любую покупку можно отменить в 180 - дневный срок.

- amount - сумма отмены в рублях;
- org_amount -  оригинальная сумма покупки. Если указать amount < org_amount, то можно отменить только часть суммы заказа.
- order - номер заказа/покупки;
- desc - описание заказа.
- backref - страница, на которую пользователь может вернуться по завершению операции
- rrn - Retrieval Reference Number. Универсальный идентификатор запроса на списание средств с карты. Значение данного параметра можно посмотреть в логах, но рекомендую сохранять все транзакции в БД
- int_ref - Internal Reference - уникальный идентификатор операции на платежном шлюзе. Тоже берется из логов или из БД после операции оплаты/предавторизации

```php
$config = array(
        'amount'        =>  29,
        'org_amount'    =>  29,
        'order'         =>  15955794239,
        'rrn'           =>  322717128594,
        'int_ref'       =>  '0413BDA090B5BE32',
        'backref'       =>  'www.yoursite.com'
    );
    $psb = new Psb($config);
    $psb -> cancel();
```
5) Предавторизация:

Параметры точно такие же, как и при покупке

- amount - сумма покупки в рублях;
- order - номер заказа/покупки;
- desc - описание заказа.
- backref - страница, на которую пользователь может вернуться по завершению платежа

```php
$config = array(
    'amount'    =>  777.77,
    'order'     =>  10788808,
    'desc'      =>  'Описание покупк',
    'backref'   =>  'www.yoursite.com'
);
$psb = new Psb($config);
$psb -> pre_authorize();
```
6) Завершение расчета (снятие суммы, заблокированной на предавторизации):

- amount - сумма покупки в рублях;
- order - номер заказа/покупки;
- desc - описание заказа.
- backref - страница, на которую пользователь может вернуться по завершению платежа
- rrn - Retrieval Reference Number. Универсальный идентификатор запроса на списание средств с карты. Значение данного параметра можно посмотреть в логах, но рекомендую сохранять все транзакции в БД
- int_ref - Internal Reference - уникальный идентификатор операции на платежном шлюзе. Тоже берется из логов или из БД после операции оплаты/предавторизации

```php
$config = array(
    'amount'        =>  745,
    'org_amount'    =>  745,
    'order'         =>  45070744739,
    'rrn'           =>  '322747128712',
    'int_ref'       =>  '6C53D92626FEF455',
    'backref'       =>  'www.yoursite.com'
);
$psb = new Psb($config);
$psb -> end_payment();
```

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
```php
    $psb = new Psb();
    $psb -> process_answer();
```
3) Покупка:

Необходимо указать всего 3 параметра для передачи в метод класса
- amount - сумма покупки в рублях;
- order - номер заказа/покупки;
- desc - описание заказа.

```php
  $config = array(
      'amount'    =>  29,
      'order'     =>  rand(10000000000, 100000000000),
      'desc'      =>  'desc',
  );
  $psb = new Psb($config);
  $psb -> purchase();

```
Класс автоматически сгенерирует HTML форму со всеми нужными полями (скрытыми) и сразу отправит ее на страницу оплаты.

<?php
/**
 * Created by Sergey Koshkarev (www.sergeykoshkarev.com)
 * Date: 02.08.13
 * Time: 22:18
 */


Class Psb
{
    private $terminal = null; // Уникальный номер виртуального терминала торговой точки
    private $transaction_type =  null; // 1 - Оплата, 22 - отмена, 0 - предавторизация, 21 - завершение расчетов
    private $merchant_name = 'TEST_MERCH'; // Название торговой точки
    private $key = null; // Секретный ключ
    private $merchant = null; // Номер торговой точки
    private $email = 'youremail@email.ru'; // Адрес электронной почты торговой точки
    private $amount = '0.00'; // Сумма операции
    private $currency = 'RUB'; // Валюта операции
    private $order = null; // Уникальный номер заказа
    private $backref = null; // URL для возврата на сайт торговой точки после проведения операции
    private $p_sign = null; // HMAC запроса и ответа
    private $rc = null; // Response code. Код ответа на попытку проведения операции.
    private $rc_text = null; // Response Code Text. Расшифровка кода ответа на попытку проведения операции
    private $auth_code = null; // Код авторизации. Буквенно цифровой код, выдаваемый банком, выпустившим карту, в случае успешной операции
    private $rrn = null; // Retrieval Reference Number. Универсальный идентификатор запроса на списание средств с карты
    private $int_ref = null; // Internal Reference - уникальный идентификатор операции на платежном шлюзе
    private $result = null; // Результат обработки операции. 0 - успешная операция, 1 - повторный запрос, 2 - запрос отклонен банком, 3 - запрос отклонен платежным шлюзом
    private $org_amount = null; // Сумма оригинальной операции (сумма уплаты или предавторизации)
    private $cardholder_name = null; // Имя держателя карты
    private $card_number = null; // Маскированный номер карты
    public $desc = null; // Описание заказа
    public $timestamp = ''; // UTC время проведения - формат "YYYYMMDDHHMISS"
    public $nonce = ''; // Случайное число в шестнадцатиричном формате
    public $gateway_url = ''; // PSB Bank gateway URL

    public $result_desc_rus = array(
        0   =>  'Операция успешно завершена',
        1   =>  'Запрос идентифицирован как повторный',
        2   =>  'Запрос отклонен банком',
        3   =>  'Запрос отклонен платежным шлюзом'
    );
    public $log_path = null;
    public $log_file = null;

    public function __construct($params = null)
    {
        $this -> initialize($params);
    }

    /**
     * Инициализация класса
     *
     * @access  private
     * @param   array|null
     * @return  void
     */
    private function initialize($params = null)
    {
        if (defined('PSB_TERMINAL'))
        {
            $this -> terminal = PSB_TERMINAL;
        }

        if (defined('PSB_MERCHANT'))
        {
            $this -> merchant = PSB_MERCHANT;
        }

        if (defined('PSB_KEY'))
        {
            $this -> key = PSB_KEY;
        }

        if (defined('PSB_MERCHANT_NAME'))
        {
            $this -> merchant_name = PSB_MERCHANT_NAME;
        }

        if (defined('PSB_BACK_REF'))
        {
            $this -> backref = PSB_BACK_REF;
        }

        if (defined('PSB_MERCHANT_EMAIL'))
        {
            $this -> email = PSB_MERCHANT_EMAIL;
        }

        if (defined('PSB_LOG_ENABLED'))
        {
            if (PSB_LOG_ENABLED)
            {
                if (defined('PSB_LOG_PATH'))
                {
                    $this -> log_path = PSB_LOG_PATH;
                }

                $this -> log_path = __DIR__ . DIRECTORY_SEPARATOR . $this -> log_path;
                if ( ! file_exists($this -> log_path))
                {
                    mkdir($this -> log_path, 0777);
                }

                $log_file = $this -> log_path . DIRECTORY_SEPARATOR . 'log_psb_' . date('Ymd') . '.log';
                if ( ! file_exists($log_file))
                {
                    touch($log_file);
                    chmod($log_file, 0775);
                }

                $this -> log_file = $log_file;
            }
        }

        $this -> gateway_url = PSB_GATEWAY_URL_LIVE;
        if (defined('PSB_SANDBOX') && PSB_SANDBOX == TRUE)
        {
            $this -> gateway_url = PSB_GATEWAY_URL_SANDBOX;
        }

        $this -> nonce =  strtoupper(dechex(rand(999999999999999999, 9999999999999999999)));

        $utc = new DateTimeZone("UTC");
        $date = new DateTime(date('Y-m-d H:i:s'), $utc);
        $this -> timestamp = $date -> format('YmdHis');

        if (is_array($params))
        {
            foreach ($params as $param_name => $param_value)
            {
                if (property_exists($this, $param_name))
                {
                    $this -> $param_name = $param_value;
                }
            }
        }
    }

    /**
     * Генерирует специальный HMAC код для отправки в каждой посылке
     *
     * @access  public
     * @return  string
     */
    public function generate_hmac($hmac_params = array())
    {
        $hmac_string = '';

        foreach ($hmac_params as $param)
        {
            $temp_hmac_string = '-';
            if (property_exists($this, $param))
            {
                if (is_null($this -> {$param}) == false)
                {
                    $temp_hmac_string = strlen($this -> {$param}) . $this -> {$param} ;
                }
            }

            $hmac_string .= $temp_hmac_string;
        }

        file_put_contents($this -> log_file, '================================================================'  . PHP_EOL, FILE_APPEND | LOCK_EX);
        file_put_contents($this -> log_file, 'Строка:'  . $hmac_string . PHP_EOL . PHP_EOL, FILE_APPEND | LOCK_EX);
        file_put_contents($this -> log_file, PHP_EOL, FILE_APPEND | LOCK_EX);
        file_put_contents($this -> log_file, PHP_EOL, FILE_APPEND | LOCK_EX);

        return hash_hmac('sha1', $hmac_string, pack('H*', $this -> key));
    }

    /**
     * Генерирует авто-форму, которая отправит подготовленные данные в банковский шлюз
     *
     * @access  public
     * @param   array
     * @return  string
     */
    public function generate_psb_form($fields = array())
    {
        $form = '';
        if (is_array($fields))
        {
            $form = sprintf('<form action="%s" id="psb_form" name="psb_form" method="post">', $this -> gateway_url);
            foreach ($fields as $var_name => $var_value)
            {
                $form .= sprintf('<input type="hidden" name="%s" value="%s" />', strtoupper($var_name), $var_value);
            }
            $form .= '</form>';
            $form .= '<script type="text/javascript">
                        window.onload = function(){
                            document.forms["psb_form"].submit();
                        }
                      </script>';
        }

        return $form;
    }

    /**
     * Покупка
     *
     * @access  public
     * @return  string
     */
    public function purchase()
    {
        $post_data = array();
        $post_data['AMOUNT']        = strval($this -> amount);
        $post_data['ORDER']         = $this -> order;
        $post_data['DESC']          = $this -> desc;
        $post_data['CURRENCY']      = $this -> currency;
        $post_data['MERCH_NAME']    = $this -> merchant_name;
        $post_data['MERCHANT']      = $this -> merchant;
        $post_data['TERMINAL']      = $this -> terminal;
        $post_data['EMAIL']         = $this -> email;
        $post_data['TRTYPE']        = $this -> transaction_type = 1;
        $post_data['TIMESTAMP']     = $this -> timestamp;
        $post_data['NONCE']         = $this -> nonce;
        $post_data['BACKREF']       = $this -> backref;

        $hmac_params = array(
            'amount',
            'currency',
            'order',
            'merchant_name',
            'merchant',
            'terminal',
            'email',
            'transaction_type',
            'timestamp',
            'nonce',
            'backref'
        );

        $post_data['P_SIGN']        = $this -> generate_hmac($hmac_params);

        file_put_contents($this -> log_file, '================================================================'  . PHP_EOL, FILE_APPEND | LOCK_EX);
        file_put_contents($this -> log_file, 'P_SIGN::'  . PHP_EOL, FILE_APPEND | LOCK_EX);

        file_put_contents($this -> log_file, $post_data['P_SIGN']  . PHP_EOL, FILE_APPEND | LOCK_EX);
        file_put_contents($this -> log_file, PHP_EOL, FILE_APPEND | LOCK_EX);
        file_put_contents($this -> log_file, '================================================================'  . PHP_EOL, FILE_APPEND | LOCK_EX);

        echo $this -> generate_psb_form($post_data);
    }

    /**
     * Отмена
     *
     * @access  public
     * @return  string
     */
    public function cancel()
    {
        $post_data = array();
        $post_data['ORDER']         = $this -> order;
        $post_data['AMOUNT']        = strval($this -> amount);
        $post_data['CURRENCY']      = $this -> currency;
        $post_data['ORG_AMOUNT']    = strval($this -> org_amount);
        $post_data['RRN']           = $this -> rrn;
        $post_data['INT_REF']       = $this -> int_ref;
        $post_data['TRTYPE']        = $this -> transaction_type = 22;
        $post_data['MERCH_NAME']    = $this -> merchant_name;
        $post_data['MERCHANT']      = $this -> merchant;
        $post_data['TERMINAL']      = $this -> terminal;
        $post_data['BACKREF']       = $this -> backref;
        $post_data['EMAIL']         = $this -> email;
        $post_data['TIMESTAMP']     = $this -> timestamp;
        $post_data['NONCE']         = $this -> nonce;

        $hmac_params = array(
            'order',
            'amount',
            'currency',
            'org_amount',
            'rrn',
            'int_ref',
            'transaction_type',
            'terminal',
            'backref',
            'email',
            'timestamp',
            'nonce',
        );

        $post_data['P_SIGN']        = $this -> generate_hmac($hmac_params);

        echo $this -> generate_psb_form($post_data);
    }

    /**
     * Предавторизация покупки
     *
     * @access  public
     * @return  string
     */
    public function pre_authorize()
    {
        $post_data = array();
        $post_data['AMOUNT']        = strval($this -> amount);
        $post_data['CURRENCY']      = $this -> currency;
        $post_data['ORDER']         = $this -> order;
        $post_data['DESC']          = $this -> desc;
        $post_data['TERMINAL']      = $this -> terminal;
        $post_data['TRTYPE']        = $this -> transaction_type = 0;
        $post_data['MERCH_NAME']    = $this -> merchant_name;
        $post_data['MERCHANT']      = $this -> merchant;
        $post_data['EMAIL']         = $this -> email;
        $post_data['TIMESTAMP']     = $this -> timestamp;
        $post_data['NONCE']         = $this -> nonce;
        $post_data['BACKREF']       = $this -> backref;

        $hmac_params = array(
            'amount',
            'currency',
            'order',
            'merchant_name',
            'merchant',
            'terminal',
            'email',
            'transaction_type',
            'timestamp',
            'nonce',
            'backref',
        );

        $post_data['P_SIGN']        = $this -> generate_hmac($hmac_params);

        echo $this -> generate_psb_form($post_data);
    }

    /**
     * Завершение расчета
     *
     * @access  public
     * @return  string
     */
    public function end_payment()
    {
        $post_data = array();
        $post_data['ORDER']         = $this -> order;
        $post_data['AMOUNT']        = strval($this -> amount);
        $post_data['CURRENCY']      = $this -> currency;
        $post_data['ORG_AMOUNT']    = $this -> org_amount;
        $post_data['RRN']           = $this -> rrn;
        $post_data['INT_REF']       = $this -> int_ref;
        $post_data['TRTYPE']        = $this -> transaction_type = 21;
        $post_data['TERMINAL']      = $this -> terminal;
        $post_data['BACKREF']       = $this -> backref;
        $post_data['EMAIL']         = $this -> email;
        $post_data['TIMESTAMP']     = $this -> timestamp;
        $post_data['NONCE']         = $this -> nonce;

        $hmac_params = array(
            'order',
            'amount',
            'currency',
            'org_amount',
            'rrn',
            'int_ref',
            'transaction_type',
            'terminal',
            'backref',
            'email',
            'timestamp',
            'nonce'
        );

        $post_data['P_SIGN']        = $this -> generate_hmac($hmac_params);

        echo $this -> generate_psb_form($post_data);
    }

    /**
     * Определяет, в ответ на какую операцию пришел ответ от банка
     *
     * @access  private
     * @return  int|false
     */
    private function detect_operation()
    {
        $transaction_type = isset($_POST['TRTYPE']) ? $_POST['TRTYPE'] : false;

        if ($transaction_type)
            $this -> transaction_type = $transaction_type;

        return $transaction_type;
    }

    /**
     * Заполняет свойства класса данными из $_POST массива
     *
     * @access  private
     * @return  void
     */
    private function fill_properties()
    {
        $post_data = (array)$_POST;

        $this -> order              = isset($post_data['ORDER']) ? $post_data['ORDER'] : null;
        $this -> desc               = isset($post_data['DESC']) ? $post_data['DESC'] : null;
        $this -> amount             = isset($post_data['AMOUNT']) ? $post_data['AMOUNT'] : null;
        $this -> currency           = isset($post_data['CURRENCY']) ? $post_data['CURRENCY'] : null;
        $this -> org_amount         = isset($post_data['ORG_AMOUNT']) ? $post_data['ORG_AMOUNT'] : null;
        $this -> rrn                = isset($post_data['RRN']) ? $post_data['RRN'] : null;
        $this -> int_ref            = isset($post_data['INT_REF']) ? $post_data['INT_REF'] : null;
        $this -> transaction_type   = isset($post_data['TRTYPE']) ? $post_data['TRTYPE'] : null;
        $this -> terminal           = isset($post_data['TERMINAL']) ? $post_data['TERMINAL'] : null;
        $this -> backref            = isset($post_data['BACKREF']) ? $post_data['BACKREF'] : null;
        $this -> email              = isset($post_data['EMAIL']) ? $post_data['EMAIL'] : null;
        $this -> timestamp          = isset($post_data['TIMESTAMP']) ? $post_data['TIMESTAMP'] : null;
        $this -> nonce              = isset($post_data['NONCE']) ? $post_data['NONCE'] : null;
        $this -> psign              = isset($post_data['P_SIGN']) ? $post_data['P_SIGN'] : null;
        $this -> merchant           = isset($post_data['MERCHANT']) ? $post_data['MERCHANT'] : null;
        $this -> merchant_name      = isset($post_data['MERCH_NAME']) ? $post_data['MERCH_NAME'] : null;
        $this -> rc                 = isset($post_data['RC']) ? $post_data['RC'] : null;
        $this -> rc_text            = isset($post_data['RCTEXT']) ? $post_data['RCTEXT'] : null;
        $this -> auth_code          = isset($post_data['AUTHCODE']) ? $post_data['AUTHCODE'] : null;
        $this -> cardholder         = isset($post_data['NAME']) ? $post_data['NAME'] : null;
        $this -> card_number        = isset($post_data['CARD']) ? $post_data['CARD'] : null;
        $this -> result             = isset($post_data['RESULT']) ? $post_data['RESULT'] : null;
    }

    /**
     * Обработка любых ответов от банка
     *
     * @access  public
     * @return  void
     */
    public function process_answer()
    {
        if ($operation = $this -> detect_operation())
        {
            switch ($operation)
            {
                case 1: // Оплата
                    break;
                case 22: // Отмена
                    break;
                case 0: // Предавторизация
                    break;
                case 21: // Завершение расчетов
                    break;
            }

            $this -> fill_properties();

            // Здесь можно добавить свой код для обработки результатов
            // У меня - простое изменение данных по инвойсу
            if ($this -> result == '0')
            {
                global $dbh;
                $q = 'UPDATE `inv_invoices`
                      SET `paid_on` = NOW(),
                          `amount` = %s,
                          `status` = "paid",
                          `method` = "card"
                      WHERE `number` = "%s"';
                $stmt = $dbh -> prepare(sprintf($q, $this -> amount, $this -> order));
                $stmt -> execute();
                // Отправить email о результатах операции
            }
        }

        if (PSB_LOG_ENABLED == true)
            $this -> log_operation();
    }

    /**
     * Записывает все данные, пришедшие из банковского шлюза
     *
     * @access  public
     * @return  void
     */
    public function log_operation()
    {
        if (is_array($_POST) && count($_POST) > 0)
        {
            file_put_contents($this -> log_file, '================================================================'  . PHP_EOL, FILE_APPEND | LOCK_EX);
            file_put_contents($this -> log_file, date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND | LOCK_EX);
            file_put_contents($this -> log_file, PHP_EOL, FILE_APPEND | LOCK_EX);
            foreach ($_POST as $var_name => $var_value)
            {
                file_put_contents($this -> log_file, sprintf('%s => %s', $var_name, $var_value)  . PHP_EOL, FILE_APPEND | LOCK_EX);
            }
            file_put_contents($this -> log_file, '================================================================'  . PHP_EOL, FILE_APPEND | LOCK_EX);
            file_put_contents($this -> log_file, PHP_EOL, FILE_APPEND | LOCK_EX);
        }
    }
}

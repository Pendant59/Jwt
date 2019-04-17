<?php
namespace jwt;

/**
 * Class Jwt
 * header头里 Authorization 只需要放入token字符串
 */
class Jwt 
{
    private static $Header = [
        'alg' => 'sha256',
        'typ' => 'Jwt'
        ];
    private $config = [
        'key' => 'b7xBa9sj8JxZxcA9fZ-pendant59',        # 加密Key
        'iss' => 'pendant59',                           # 签发者
        'aud' => 'https://github.com/Pendant59',        # 接收jwt的用户
        'expire' => 3 * 3600,                           # 过期时间 默认3小时
        'return_array' => true,                         # true 返回 playload 中的data数组;false 返回 playload 中的data数组中的uid键值;
        'data' => [                                     # token 中包含的加密字段 uid 为固定值
            'uid'
        ]
    ];

    /**
     * Jwt constructor.
     * @param $self_config
     */
    public function __construct($self_config)
    {
        if ($self_config && is_array($self_config)) {
            $this->config  = array_merge($this->config, $self_config);
        }
    }

    /**
     * 生成Jwt
     * @param array $data
     * @return string
     */
    public function createJwt($data)
    {
        if (!is_array($data)) {
            return '参数应为关联数组';
        }
        $keys_array = array_keys($data);
        if (!in_array('uid', $keys_array)) {
            return 'uid 为固有字段';
        }
        $token_data = [];
        try {
            foreach ($this->config['data'] as $value) {
                $token_data[$value] = $data[$value];
            }
        } catch (\Exception $e) {
            return '未找到键值';
        }

        $begin_time = time();
        $token = [
            'iss' => $this->config['iss'],
            'aud' => $this->config['aud'],
            'iat' => $begin_time, # 签发时间
            'exp' => $begin_time + $this->config['expire'],
            'data' => $token_data
        ];

        $h = self::safeEncode(base64_encode(json_encode(self::$Header)));
        $p = self::safeEncode(base64_encode(json_encode($token)));
        $s = self::createSignature(self::$Header['alg'], $h . $p, $this->config['key']);
        $jwt_token = $h . '.' . $p . '.' . $s;
        return $jwt_token;
    }

    /**
     * 校验token
     * @return array|int|string
     */
    public function checkJwt()
    {
        $time = time();
        $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (empty($token)){
            # token为空 未登录
            return -1;
        }
        $tokenArr = explode('.', $token);
        list($header, $playload, $signature) = $tokenArr;
        $headerArr = json_decode(base64_decode(self::safeDecode($header)),true);
        $playloadArr = json_decode(base64_decode(self::safeDecode($playload)),true);

        if (!is_array($headerArr) || !is_array($playloadArr)){
            # token非法
            return -2;
        }
        $diff = array_diff($headerArr, self::$Header);
        if ($diff){
            # token非法
            return -2;
        }

        if ($time > $playloadArr['exp']){
            # token过期
            return -3;
        }

        $data = [];
        $data['uid']  = $playloadArr['data']['uid'] ?? '';
        $data['type'] = $playloadArr['data']['type'] ?? '';

        if (!$data['uid']) {
            # 用户不存在
            return -4;
        }

        $sign = self::createSignature(self::$Header['alg'], $header.$playload, $this->config['key']);
        if ($sign != $signature) {
            # 签名错误
            return -5;
        }

        if ($this->config['return_array']) {
            return $data;
        } else {
            return $data['uid'];
        }
    }


    /**
     * 生成签名
     * @param string $alg
     * @param string $input
     * @param string $key
     * @return string
     */
    public static function createSignature(string $alg, string $input, string $key)
    {
        return hash_hmac($alg, $input, $key);
    }

    /**
     * 编码字符串替换
     * @param string $input
     * @return string
     */
    public static function safeEncode($input)
    {
        return strtr($input,['+' => '-', "/"=>'_']);
    }

    /**
     * 解码字符串替换
     * @param $input
     * @return string
     */
    public static function safeDecode($input)
    {
        return strtr($input, ['-' => '+', '_' => '/']);
    }


}
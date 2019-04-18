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
        'data' => [                                     # token 中包含的加密字段 user_id 为固定值
            'user_id'
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
     * @param $data
     * @return string
     * @throws \Exception
     */
    public function createJwt($data)
    {
        # 参数类型检测
        if (!is_array($data) || empty($data)) {
            throw new \Exception('参数应为非空关联数组');
        }
        # 参数键值检测
        $keys_array = array_keys($data);
        if (!in_array('user_id', $keys_array)) {
            throw new \Exception('必须包含key为user_id的键值对');
        }
        # 生成playload需要的参数
        $token_data = [];
        try {
            foreach ($this->config['data'] as $value) {
                $token_data[$value] = $data[$value];
            }
        } catch (\Exception $e) {
            throw new \Exception("参数数组中未包含键值{$value}");
        }
        # 生成Jwt
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
     * @return array|int
     */
    public function checkJwt()
    {
        $time = time();
        # 返回值
        $return = [];
        $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (empty($token)){
            # token为空 未登录
            return -1;
        }
        $token_arr = explode('.', $token);
        list($header, $playload, $signature) = $token_arr;
        $header_arr = json_decode(base64_decode(self::safeDecode($header)),true);
        $playload_arr = json_decode(base64_decode(self::safeDecode($playload)),true);

        if (!is_array($header_arr) || !is_array($playload_arr)){
            # token非法
            return -2;
        }
        $diff = array_diff($header_arr, self::$Header);
        if ($diff){
            # token非法
            return -2;
        }

        if ($time >= $playload_arr['exp']){
            # token过期
            return -3;
        } else {
            # 返回剩余有效时间(秒)
            $return['expire'] = $playload_arr['exp'] - $time;
        }

        foreach ($playload_arr['data'] as $key => $value) {
            $return[$key] = $value;
        }

        if (!isset($return['user_id']) && empty($return['user_id'])) {
            # token非法
            return -2;
        }

        $reproduce_sign = self::createSignature(self::$Header['alg'], $header . $playload, $this->config['key']);
        if ($reproduce_sign != $signature) {
            # token非法
            return -2;
        }

        return $return;
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
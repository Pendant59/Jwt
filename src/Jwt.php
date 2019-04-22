<?php
namespace jwt;

/**
 * Class Jwt
 * @author Pendant 861618191@qq.com
 */
class Jwt 
{
    private static $Header = [
        'alg' => 'sha256',
        'typ' => 'Jwt'
        ];

    private $config = [
        'key' => 'b7xBa9sj8Jx2019xcA9fZ-pendant59',     # 加密Key
        'iss' => 'pendant59',                           # 签发者
        'aud' => 'https://github.com/Pendant59',        # 接收jwt的用户
        'expire' => 3 * 3600,                           # 过期时间(秒) 默认3小时
        'data' => [                                     # token 中包含的加密字段 user_id 为固定值(createJwt()只会选取此处data定义的字段参与加密)
            'user_id'
        ]
    ];

    /**
     * Jwt constructor.
     * @param array $self_config
     * @throws \Exception
     */
    public function __construct(array $self_config = [])
    {
        if (version_compare(PHP_VERSION, '7.0.0', '<')) {
            throw new \Exception('PHP版本最低为7.0.0');
        }
        if ($self_config) {
            $this->config  = array_merge($this->config, $self_config);
        }
    }

    /**
     * 生成Jwt
     * @param array  $data  关联数组['user_id'=> XXX, .....]
     * @return array
     */
    public function createJwt($data = [])
    {
        # 参数类型检测
        if (!is_array($data) || empty($data)) {
            return $this->api_return(400, '参数应为非空关联数组');

        }
        # 参数键值检测
        $keys_array = array_keys($data);

        if (!in_array('user_id', $keys_array, true)) {

        }
        # 生成playload需要的参数
        $token_data = [];

        foreach ($this->config['data'] as $value) {
            $token_data[$value] = isset($data[$value]) ? $data[$value] : null;
        }

        if (empty($token_data['user_id'])) {
            return $this->api_return(400, 'user_id的值不可为空');
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

        $return = [];
        $return['token'] = $h . '.' . $p . '.' . $s;
        $return['expire'] = $token['exp'];

        return $this->api_return(200, '', $return);
    }

    /**
     * 校验token
     * @param string $input_token  可传入或自动获得
     * @return array|int
     */
    public function checkJwt(string $input_token = null)
    {
        $time = time();
        # 返回值
        $return = [];
        # Token
        $token = $input_token ?: ($_SERVER['HTTP_AUTHORIZATION'] ?? null);
        if (empty($token)){
            return $this->api_return(401, '未知Token');
        }
        # Token 分解
        $token_arr = explode('.', $token);
        list($header, $playload, $signature) = $token_arr;
        $header_arr = json_decode(base64_decode(self::safeDecode($header)),true);
        $playload_arr = json_decode(base64_decode(self::safeDecode($playload)),true);

        # 校验解密结果
        if (!is_array($header_arr) || !is_array($playload_arr)){
            return $this->api_return(401, '非法Token');
        }

        # 校验Header
        $diff = array_diff($header_arr, self::$Header);
        if ($diff){
            return $this->api_return(401, 'Token校验失败');
        }

        # 校验过期时间
        if ($time >= $playload_arr['exp']){
            return $this->api_return(401, 'Token已过期');
        } else {
            $return['expire'] = $playload_arr['exp'];
        }

        # 获取用户自定义加密array $data
        foreach ($playload_arr['data'] as $key => $value) {
            $return[$key] = $value;
        }

        # 校验用户身份标识
        if (!isset($return['user_id']) && empty($return['user_id'])) {
            return $this->api_return(401, '无法识别用户身份');
        }

        $reproduce_sign = self::createSignature(self::$Header['alg'], $header . $playload, $this->config['key']);
        if ($reproduce_sign != $signature) {
            return $this->api_return(401, 'Token签名错误');
        }

        return $this->api_return(200, '', $return);
    }

    /**
     * 更改配置参数
     * @param array $self_config
     * @return $this
     */
    public function setConfig(array $self_config)
    {
        if ($self_config) {
            $this->config  = array_merge($this->config, $self_config);
        }
        return $this;
    }

    /**
     * 获取配置参数
     * @return array
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * 返回
     * @param int $code             状态标识 401 200
     * @param string $message       提示信息
     * @param array $data           返回数据
     * @return array
     */
    public function api_return(int $code, string $message, array $data = [])
    {
        $return = [
            'code' => $code,
            'message'  => $message ?: ($code == 200 ? 'Success' : 'Error'),
        ];
        if (!empty($data)){
            $return['data'] = $data;
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
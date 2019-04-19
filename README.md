# Jwt
- **JsonWebToken**
- 简单的Jwt 生成和校验类
- author Pendant 861618191@qq.com

### 使用方法
- 将生成的jwt字符串放到 Header 头中的 Authorization 中即可(不需要拼接Basic) 

- example 1：
```
$config = [
    'key' => '2019-pendant59',                      # 加密Key
    'iss' => 'pendant59',                           # 签发者
    'aud' => 'https://github.com/Pendant59',        # 接收jwt的用户
    'expire' => 6 * 3600,                           # 过期时间(秒) 默认3小时
    'data' => [                                     # token 中包含的加密字段 user_id 为固定值(createJwt()只会选取此处data定义的字段参与加密,如果传入createJwt()的参数中不没有包含此处定义的非固定值键值对,则默认为空)
        'user_id',
        'nickname'
    ]
];

$data = [
    'user_id' => 1,
    'nickname' => 'pendant59',
    ];


$jwt = new Jwt($config);
# 生成Jwt
$jwt_token = $jwt->createJwt($data);

# 校验Jwt
# 此处校验jwt 不传值的情况下，checkJwt() 会自己取值
# 可以自己从header 头中的 Authorization 中取出传入checkJwt() 
# 如果传值, 以传值为准
if ($jwt_token['code'] == 200) {
    $result = $jwt->checkJwt($jwt_token['data']['token']);
    print_r($result);
} else {
  print($jwt_token['message']);
}



# 返回值
array(3) {
  ["code"]=>
  int(200)
  ["message"]=>
  string(7) "Success"
  ["data"]=>
  array(3) {
    ["expire"]=>
    int(1555690828)
    ["user_id"]=>
    int(1)
    ["nickname"]=>
    string(9) "pendant59"
  }
}

```

- example 2：
```
$config = [
    'key' => '2019-pendant59',                      # 加密Key
    'iss' => 'pendant59',                           # 签发者
    'aud' => 'https://github.com/Pendant59',        # 接收jwt的用户
    'expire' => 6 * 3600,                           # 过期时间(秒) 默认3小时
    'data' => [                                     # token 中包含的加密字段 user_id 为必有固定值(createJwt()只会选取此处data定义的字段参与加密,如果传入createJwt()的参数中不没有包含此处定义的非固定值键值对,则默认为空)
        'user_id',
        'nickname',
        'otherKeys'
    ]
];

$data = [
    'user_id' => 1,
    'nickname' => 'pendant59',
    ];


$jwt = new Jwt();
# 生成Jwt
$jwt_token = $jwt->setConfig($config)->createJwt($data);

# 校验Jwt
# 此处校验jwt 不传值的情况下，checkJwt() 会自己取值
# 可以自己从header 头中的 Authorization 中取出传入checkJwt() 
# 如果传值, 以传值为准
if ($jwt_token['code'] == 200) {
    $result = $jwt->checkJwt($jwt_token['data']['token']);
    print_r($result);
} else {
  print($jwt_token['message']);
}

# 返回值 - 此处$config 定义了多个字段,但是传入createJwt的$data仅包含user_id 所以其他字段默认为空
array(3) {
  ["code"]=>
  int(200)
  ["message"]=>
  string(7) "Success"
  ["data"]=>
  array(4) {
    ["expire"]=>
    int(1555690828)
    ["user_id"]=>
    int(1)
    ["nickname"]=>
    NULL
    ["otherKeys"]=>
    NULL
  }
}
```

## 返回值 code
- 200 成功
- 400 参数错误
- 401 Toekn校验失败

### 生成
```
# 失败
array(2) {
  ["code"]=>
  int(400)
  ["message"]=>
  string(30) "参数应为非空关联数组"
}

# 成功
array(3) {
  ["code"]=>
  int(200)
  ["message"]=>
  string(7) "Success"
  ["data"]=>
  array(2) {
    ["token"]=>
    string(282) "eyJhbGciOiJzaGEyNTYiLCJ0eXAiOiJKd3QifQ==.eyJpc3MiOiJwZW5kYW50NTkiLCJhdWQiOiJodHRwczpcL1wvZ2l0aHViLmNvbVwvUGVuZGFudDU5IiwiaWF0IjoxNTU1NjY5MjI4LCJleHAiOjE1NTU2OTA4MjgsImRhdGEiOnsidXNlcl9pZCI6MSwibmlja25hbWUiOm51bGx9fQ==.ffd86f4bd5550b81ac3b5af4fa22e86c40253d111537f61022795e5a0342202e"
    ["expire"]=>
    int(1555690828)         # expire Token过期时间戳
  }
}
```

### 校验
```
# 失败
array(2) {
  ["code"]=>
  int(401)
  ["message"]=>
  string(17) "Token签名错误"
}

# 成功
array(3) {
  ["code"]=>
  int(200)
  ["message"]=>
  string(7) "Success"
  ["data"]=>
  array(3) {
    ["expire"]=>
    int(1555690828)     # expire Token过期时间戳
    ["user_id"]=>
    int(1)              # user_id 用户标识
    ["nickname"]=>
    NULL                # 自定义字段
  }
}
```



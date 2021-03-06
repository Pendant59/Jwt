# Jwt
- **JsonWebToken**
- 简单的Jwt 生成和校验类
- Pendant 861618191@qq.com
- QQ群 316497602

### Token使用方法
- **将生成的jwt字符串放到 Header 头中的 Authorization 中即可(不需要拼接Basic)** 

### 其他说明
- 默认使用 sha256
- 有建议或问题欢迎 issues

### 当前版本更新内容
- v1.0.3
- 新增更新Token方法
- 修改Token校验返回的提示信息

### 安装
```
composer require pendant59/jwt
```
### 使用示例

- example 1：
```
$config = [
    'key' => '2019-pendant59',                      # 加密Key
    'iss' => 'pendant59',                           # 签发者
    'aud' => 'https://github.com/Pendant59',        # 接收jwt的用户
    'expire' => 6 * 3600,                           # 过期时间(秒) 默认3小时
    'update_limit' => 300,                          # Token 过期多少秒内可以用于更新 默认300秒
    'data' => [                                     # Token 中包含的加密字段 user_id 为固定值(createJwt()只会选取此处data定义的字段参与加密,如果传入createJwt()的参数中不没有包含此处定义的非固定值键值对,则默认为空)
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
# 可以自己从header 头中的 Authorization 中取出jwt字符串并传入checkJwt() 
# 如果传值, 以传值为准
if ($jwt_token['code'] == 200) {
    # 校验Token
    $result = $jwt->checkJwt($jwt_token['data']['token']);
    print_r($result);
    
    sleep(5);  # 假装客户端 5 秒后 请求更新
    # 更新Token
    $result = $jwt->updateJwt($jwt_token['data']['token']);
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
    'update_limit' => 300,                          # Token 过期多少秒内可以用于更新 默认300秒
    'data' => [                                     # Token 中包含的加密字段 user_id 为必有固定值(createJwt()只会选取此处data定义的字段参与加密,如果传入createJwt()的参数中不没有包含此处定义的非固定值键值对,则默认为空)
        'user_id',
        'nickname',
        'otherKeys'
    ]
];

$data = [
    'user_id' => 1,
    'nickname' => 'pendant59',
    ];


$jwt = (new Jwt())->setConfig($config);
# 生成Jwt
$jwt_token = $jwt->createJwt($data);

# 校验Jwt
# 此处校验jwt 不传值的情况下，checkJwt() 会自己取值
# 可以自己从header 头中的 Authorization 中取出传入checkJwt() 
# 如果传值, 以传值为准
if ($jwt_token['code'] == 200) {
    # 校验Token
    $result = $jwt->checkJwt($jwt_token['data']['token']);
    print_r($result);
    
    sleep(5);  # 假装客户端 5 秒后 请求更新
    # 更新Token
    $result = $jwt->updateJwt($jwt_token['data']['token']);
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
    ["user_id"]=>
    int(1)              # user_id 用户标识
    ["nickname"]=>
    NULL                # 自定义字段
  }
}
```



# 设备码登录授权流

电视端用设备码登录，攻击者在一旁反复猜用户码，猜中就把自己的设备绑进了别人账号：设备码必须高熵且短时效；用户码必须限次尝试；轮询必须有间隔下限；授权后只能兑换一次；设备码与用户码必须一一对应；批量处理各请求独立。不变量：同一设备码只能兑换一次；用户码连续失败达到上限即作废。

## 数据形状

存储是普通字典，含 devices、user_codes、tokens 与 seq。devices 以设备码为键，记录含 status、account、created_at、expires_at、attempts、max_attempts、poll_interval、last_poll_at、used 与 token。user_codes 把用户码映射到设备码。tokens 以令牌为键。

策略是普通字典，含 device_code_length、device_code_entropy_bits、device_code_max_length、user_code_length、max_attempts、poll_interval 与 expires_in。

批量请求是普通字典，含 request_id、entropy 与 policy。

## 接口

issue 签发一对设备码和用户码，并返回过期时刻与轮询间隔。

check_code_format 检查设备码的字符集与长度是否满足策略。

check_user_code 检查给定尝试次数是否仍低于策略上限。

check_polling 检查两次轮询之间的间隔是否达到策略下限。

authorize 用用户码把账号授权给对应设备。

exchange 在授权完成后兑换一次性令牌。

validate_policy 返回策略问题列表，空列表表示策略可用。

device_batch 按顺序处理多条签发请求，每条请求的结果互不影响。

## 运行

在仓库根目录运行 python -m pytest tests -q。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |


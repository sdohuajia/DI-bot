# DI 签到脚本

本包不包含任何真实私钥、代理、登录令牌或本地状态数据库。

## 环境

- Python 3.10+
- 网络可访问 DI、Privy 和 BSC RPC

## 安装

```bash
cd DI-share
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 配置

1. 将 `keys.example.txt` 复制为 `keys.txt`，每行填入一个私钥。`keys.txt` 已在 `.gitignore` 中排除，切勿分享。
2. 如需代理，将 `proxy.example.txt` 复制为 `proxy.txt`，每行与 `keys.txt` 同行钱包对应；留空表示直连。

```bash
cp keys.example.txt keys.txt
cp proxy.example.txt proxy.txt   # 可选
chmod 600 keys.txt proxy.txt 2>/dev/null || true
```

## 运行

先建议演练模式（不会提交写操作）：

```bash
python3 di_checkin.py --once --dry-run
```

实际执行一轮：

```bash
python3 di_checkin.py --once
```

更多参数：

```bash
python3 di_checkin.py --help
```

## 隐私与安全

- `keys.txt`：私钥，绝不分享。
- `proxy.txt`：可能含代理账号和密码，绝不分享。
- `di_state.sqlite3*`：含 Privy 登录/刷新令牌及账户档案，绝不分享。
- 运行后生成的 `.venv/`、`__pycache__/`、日志和数据库均不需要分享。
- 发给最终用户时仅发送本压缩包；由用户在本地自行创建 `keys.txt` 和可选的 `proxy.txt`。

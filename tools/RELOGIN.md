# 本机自动重登助手

`relogin_helper.py` 不把密码、TOTP 密钥或代理凭据上传到服务器，而是保存到 macOS Keychain。

```bash
python3 tools/relogin_helper.py set account-1 \
  --email you@example.com \
  --password '在本机输入' \
  --totp-secret 'BASE32_TOTP_SECRET' \
  --proxy 'socks5://127.0.0.1:1080' \
  --profile-dir "$HOME/Library/Application Support/Google/Chrome-Account-1"

python3 tools/relogin_helper.py launch account-1
python3 tools/relogin_helper.py code account-1
```

启动后在该 Profile 完成 Google 登录；TOTP 可以用 `code` 命令在本机生成。Google 手机确认、短信验证码和安全密钥无法安全地无人值守提交，仍需要人工确认。

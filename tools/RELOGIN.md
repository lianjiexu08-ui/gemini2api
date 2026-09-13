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
# 本机辅助自动填写（需要给 Terminal/osascript 开启辅助功能权限）
python3 tools/relogin_helper.py auto account-1
```

`auto` 只在本机尝试填写邮箱、密码和 TOTP，不会把秘密发到服务器。Google 手机确认、短信验证码、安全密钥或风控页面仍会暂停，需要人工完成。

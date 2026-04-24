#!/usr/bin/env python3
"""
Example: Generate a test JWT token for use with jwtpeek.
Run: python3 gen_test_token.py
"""
import json
import hmac
import hashlib
import base64
import time

def b64url(data):
    """Base64URL 编码"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def make_jwt(payload, secret, algorithm="HS256"):
    """创建一个 JWT token"""
    header = {"alg": algorithm, "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")))
    p = b64url(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"

# 示例 1: 标准 Auth0 风格 token
token1 = make_jwt({
    "sub": "auth0|1234567890",
    "name": "Jane Smith",
    "email": "jane@example.com",
    "picture": "https://example.com/avatar.jpg",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,  # 1 小时后过期
    "iss": "https://dev-example.us.auth0.com/",
    "aud": "my-api",
    "scope": "read:users write:posts",
    "roles": ["admin", "editor"],
}, secret="my-super-secret-key-2024")

# 示例 2: 最小化 token
token2 = make_jwt({
    "sub": "user42",
    "iat": int(time.time()),
}, secret="simple-key")

# 示例 3: 已过期的 token
token3 = make_jwt({
    "sub": "expired-user",
    "name": "Old User",
    "iat": int(time.time()) - 86400 * 30,  # 30 天前签发
    "exp": int(time.time()) - 3600,  # 1 小时前过期
    "iss": "legacy-auth.example.com",
}, secret="old-key")

print("=== Test JWT Tokens ===\n")
print(f"1. Standard token:\n   {token1}\n")
print(f"   Try: jwtpeek {token1}\n")
print(f"   Verify: jwtpeek verify {token1} --secret my-super-secret-key-2024\n")
print(f"2. Minimal token:\n   {token2}\n")
print(f"3. Expired token:\n   {token3}\n")

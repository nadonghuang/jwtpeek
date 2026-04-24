#!/usr/bin/env python3
"""
jwtpeek — 🔍 Beautiful JWT token inspector for your terminal.
Decode, inspect, and validate JSON Web Tokens with style.

Usage:
    jwtpeek <token>
    echo <token> | jwtpeek
    jwtpeek decode <token>
    jwtpeek verify <token> --secret <key>
    jwtpeek age <token>
    jwtpeek --json <token>
"""

import sys
import json
import base64
import hmac
import hashlib
import time
import struct
import argparse
import os

# ─── ANSI Colors ───────────────────────────────────────────────────

class C:
    """终端颜色工具"""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"
    BG_MAGENTA= "\033[45m"
    BG_CYAN   = "\033[46m"
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"

    @staticmethod
    def supports_color():
        """检测终端是否支持颜色"""
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        if not hasattr(sys.stdout, "isatty"):
            return False
        if not sys.stdout.isatty():
            return False
        if os.environ.get("TERM") == "dumb":
            return False
        return True

# 如果不支持颜色，所有颜色代码置空
if not C.supports_color():
    for attr in dir(C):
        if attr.isupper():
            setattr(C, attr, "")


# ─── Box Drawing ──────────────────────────────────────────────────

BOX_TL = "╭"
BOX_TR = "╮"
BOX_BL = "╰"
BOX_BR = "╯"
BOX_H  = "─"
BOX_V  = "│"


def box_line(width, left, right):
    """生成盒子的水平边"""
    return f"{left}{BOX_H * width}{right}"


def box_content(text, width, color=""):
    """生成盒子内容行"""
    # 处理中文字符宽度
    display_width = visual_width(text)
    padding = width - display_width
    return f"{BOX_V} {color}{text}{C.RESET}{' ' * max(0, padding)} {BOX_V}"


def visual_width(text):
    """计算字符串的可视宽度（中文占2格）"""
    import unicodedata
    width = 0
    for ch in text:
        if unicodedata.east_asian_width(ch) in ('F', 'W'):
            width += 2
        else:
            width += 1
    return width


def wrap_box(title, lines, color=C.CYAN):
    """将内容包装在漂亮的盒子中"""
    # 计算最大宽度
    max_width = max(visual_width(l) for l in lines) if lines else 20
    max_width = max(max_width, visual_width(title) + 4, 30)
    inner_width = max_width + 2  # 两侧空格

    result = []
    result.append(color + box_line(inner_width, BOX_TL, BOX_TR) + C.RESET)
    # 标题行
    title_pad = inner_width - visual_width(title)
    result.append(f"{color}{BOX_V}{C.RESET} {C.BOLD}{title}{C.RESET}{' ' * max(0, title_pad - 1)} {color}{BOX_V}{C.RESET}")
    result.append(color + box_line(inner_width, "├", "┤") + C.RESET)

    for line in lines:
        result.append(box_content(line, inner_width, ""))

    result.append(color + box_line(inner_width, BOX_BL, BOX_BR) + C.RESET)
    return "\n".join(result)


# ─── JWT Core ─────────────────────────────────────────────────────

class JWTError(Exception):
    """JWT 解析错误"""
    pass


def b64url_decode(data):
    """Base64URL 解码"""
    # 补齐 padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise JWTError(f"Base64URL 解码失败: {e}")


def b64url_encode(data):
    """Base64URL 编码"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_jwt(token):
    """解析 JWT 令牌，返回 (header, payload, signature_bytes, header_b64, payload_b64, sig_b64)"""
    token = token.strip()
    # 移除可能的 "Bearer " 前缀
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError(f"无效的 JWT 格式：期望 3 个部分，得到 {len(parts)} 个")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
    except Exception:
        raise JWTError("无法解码 JWT 头部")

    try:
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        raise JWTError("无法解码 JWT 载荷")

    try:
        signature = b64url_decode(sig_b64)
    except Exception:
        raise JWTError("无法解码 JWT 签名")

    return header, payload, signature, header_b64, payload_b64, sig_b64


def verify_signature(token, secret, algorithm=None):
    """验证 JWT 签名"""
    header, payload, signature, h_b64, p_b64, s_b64 = parse_jwt(token)

    if algorithm is None:
        algorithm = header.get("alg", "HS256")

    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    alg_upper = algorithm.upper()

    if alg_upper.startswith("HS"):
        # HMAC 算法
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        if alg_upper not in hash_map:
            raise JWTError(f"不支持的 HMAC 算法: {algorithm}")
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        expected = hmac.new(secret, signing_input, hash_map[alg_upper]).digest()
        return hmac.compare_digest(signature, expected)

    elif alg_upper in ("RS256", "RS384", "RS512"):
        raise JWTError(f"RSA 算法 ({algorithm}) 验证需要公钥，请使用 --public-key 参数")

    elif alg_upper == "NONE" or algorithm == "none":
        return len(signature) == 0

    else:
        raise JWTError(f"不支持的签名算法: {algorithm}")


# ─── Claims 分析 ──────────────────────────────────────────────────

# 常见 JWT 声明的人类可读名称
CLAIM_NAMES = {
    "iss": "Issuer (签发者)",
    "sub": "Subject (主题)",
    "aud": "Audience (受众)",
    "exp": "Expires At (过期时间)",
    "nbf": "Not Before (生效时间)",
    "iat": "Issued At (签发时间)",
    "jti": "JWT ID (唯一标识)",
    "name": "Name (姓名)",
    "email": "Email (邮箱)",
    "role": "Role (角色)",
    "roles": "Roles (角色列表)",
    "scope": "Scope (权限范围)",
    "scopes": "Scopes (权限列表)",
    "permissions": "Permissions (权限)",
    "user_id": "User ID (用户ID)",
    "userId": "User ID (用户ID)",
    "uid": "User ID (用户ID)",
    "username": "Username (用户名)",
    "preferred_username": "Preferred Username",
    "given_name": "Given Name (名)",
    "family_name": "Family Name (姓)",
    "avatar": "Avatar (头像)",
    "picture": "Picture (头像)",
    "tenant": "Tenant (租户)",
    "tenant_id": "Tenant ID (租户ID)",
    "org_id": "Organization ID",
    "azp": "Authorized Party (授权方)",
    "nonce": "Nonce",
    "at_hash": "Access Token Hash",
    "c_hash": "Code Hash",
    "auth_time": "Auth Time (认证时间)",
    "acr": "Auth Context Reference",
    "amr": "Auth Methods References",
    "sid": "Session ID",
}


def format_timestamp(ts):
    """将时间戳格式化为人类可读的字符串"""
    if not isinstance(ts, (int, float)):
        return str(ts)
    try:
        local_time = time.localtime(ts)
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
        # 计算相对时间
        now = time.time()
        diff = ts - now
        if diff > 0:
            rel = format_duration(diff)
            return f"{time_str} ({rel}后)"
        else:
            rel = format_duration(-diff)
            return f"{time_str} ({rel}前)"
    except (ValueError, OSError):
        return str(ts)


def format_duration(seconds):
    """将秒数格式化为人类可读的时长"""
    if seconds < 60:
        return f"{int(seconds)}秒"
    elif seconds < 3600:
        return f"{int(seconds / 60)}分钟"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        mins = int((seconds % 3600) / 60)
        return f"{hours}小时{mins}分钟" if mins else f"{hours}小时"
    elif seconds < 86400 * 365:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return f"{days}天{hours}小时" if hours else f"{days}天"
    else:
        years = int(seconds / (86400 * 365))
        return f"{years}年"


def analyze_claims(payload):
    """分析 payload 中的声明，返回 (claims_list, status_info)"""
    claims = []
    now = time.time()

    exp_status = None  # None, "valid", "expired", "no_exp"

    for key, value in payload.items():
        human_name = CLAIM_NAMES.get(key, "")
        label = f"{key}" + (f"  ({human_name})" if human_name else "")

        # 特殊处理时间戳字段
        if key in ("exp", "nbf", "iat", "auth_time") and isinstance(value, (int, float)):
            formatted = format_timestamp(value)

            if key == "exp":
                if value < now:
                    exp_status = "expired"
                    claims.append((f"🔴 {label}", f"{formatted}  ⚠ 已过期", C.RED))
                else:
                    exp_status = "valid"
                    claims.append((f"🟢 {label}", f"{formatted}  ✅ 有效", C.GREEN))
            elif key == "nbf":
                if value > now:
                    claims.append((f"🟡 {label}", f"{formatted}  ⚠ 尚未生效", C.YELLOW))
                else:
                    claims.append((f"🟢 {label}", f"{formatted}  ✅ 已生效", C.GREEN))
            elif key == "iat":
                claims.append((f"📅 {label}", formatted, C.BLUE))
            else:
                claims.append((f"⏰ {label}", formatted, C.BLUE))
        else:
            # 格式化值
            if isinstance(value, (dict, list)):
                val_str = json.dumps(value, ensure_ascii=False, indent=2)
                # 缩进多行
                lines = val_str.split("\n")
                claims.append((f"📋 {label}", lines[0], C.BRIGHT_CYAN))
                for extra_line in lines[1:]:
                    claims.append(("", f"   {extra_line}", C.BRIGHT_CYAN))
            elif isinstance(value, str) and len(value) > 60:
                claims.append((f"📋 {label}", value[:57] + "...", C.BRIGHT_CYAN))
            elif isinstance(value, bool):
                claims.append((f"📋 {label}", "true ✓" if value else "false ✗", C.BRIGHT_CYAN))
            else:
                claims.append((f"📋 {label}", str(value), C.BRIGHT_CYAN))

    if exp_status is None:
        exp_status = "no_exp"

    return claims, exp_status


# ─── Display Functions ────────────────────────────────────────────

def display_header(header):
    """显示 JWT 头部信息"""
    lines = []
    alg = header.get("alg", "none")
    typ = header.get("typ", "JWT")

    # 算法着色
    if alg.startswith("HS"):
        alg_display = f"{C.GREEN}HS (HMAC){C.RESET}"
    elif alg.startswith("RS"):
        alg_display = f"{C.YELLOW}RS (RSA){C.RESET}"
    elif alg.startswith("ES"):
        alg_display = f"{C.MAGENTA}ES (ECDSA){C.RESET}"
    elif alg.startswith("PS"):
        alg_display = f"{C.CYAN}PS (RSA-PSS){C.RESET}"
    elif alg.lower() == "none":
        alg_display = f"{C.RED}none (不安全!){C.RESET}"
    else:
        alg_display = alg

    lines.append(f"  Algorithm: {alg_display}")
    lines.append(f"  Type:      {C.BOLD}{typ}{C.RESET}")

    for key, value in header.items():
        if key not in ("alg", "typ"):
            lines.append(f"  {key}: {value}")

    print(wrap_box("🔑 JWT Header", lines, C.BLUE))
    print()


def display_payload(payload):
    """显示 JWT 载荷"""
    claims, exp_status = analyze_claims(payload)

    # 状态标签
    if exp_status == "valid":
        status = f"  {C.BG_GREEN}{C.BOLD} ✅ TOKEN VALID {C.RESET}"
    elif exp_status == "expired":
        status = f"  {C.BG_RED}{C.BOLD} ⚠ EXPIRED {C.RESET}"
    else:
        status = f"  {C.BG_YELLOW}{C.BOLD} ℹ NO EXP {C.RESET}"

    lines = []
    max_label = 0
    for label, value, color in claims:
        if label:
            max_label = max(max_label, visual_width(label))

    for label, value, color in claims:
        if label:
            padding = max_label - visual_width(label)
            lines.append(f"  {label}{' ' * padding}  {color}{value}{C.RESET}")
        else:
            lines.append(f"{' ' * (max_label + 4)}{color}{value}{C.RESET}")

    print(wrap_box("📦 JWT Payload", lines, C.MAGENTA))
    print(status)
    print()


def display_signature_info(header, sig_bytes):
    """显示签名信息"""
    alg = header.get("alg", "none")
    sig_hex = sig_bytes.hex()
    # 截断显示
    if len(sig_hex) > 48:
        sig_display = f"{sig_hex[:24]}{C.DIM}...{C.RESET}{sig_hex[-24:]}"
    else:
        sig_display = sig_hex

    lines = [
        f"  Algorithm:   {C.BOLD}{alg}{C.RESET}",
        f"  Length:      {len(sig_bytes)} bytes",
        f"  Hex (short): {sig_display}",
    ]

    print(wrap_box("✍ Signature", lines, C.YELLOW))
    print()


def display_token_visual(token):
    """以彩色显示原始令牌"""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return

    colors = [C.BRIGHT_BLUE, C.BRIGHT_MAGENTA, C.BRIGHT_YELLOW]
    labels = ["HEADER", "PAYLOAD", "SIGNATURE"]

    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2]

    # 计算终端宽度
    term_width = 80
    try:
        term_width = os.get_terminal_size().columns
    except (OSError, AttributeError):
        pass

    max_part = max(len(header_b64), len(payload_b64), len(sig_b64))
    display_width = min(max_part, term_width - 6)

    print(f"{C.DIM}┌─ JWT Token ─────────────────────────────────{C.RESET}")

    for i, (part, color, label) in enumerate(zip(parts, colors, labels)):
        if len(part) <= display_width:
            display = part
        else:
            half = display_width // 2 - 2
            display = f"{part[:half]}{C.DIM}···{C.RESET}{color}{part[-half:]}"

        print(f"{C.DIM}│{C.RESET} {color}{display}{C.RESET}  {C.DIM}{label}{C.RESET}")

    print(f"{C.DIM}└──────────────────────────────────────────────{C.RESET}")
    print()


def display_summary(header, payload, sig_bytes, token):
    """显示快速摘要"""
    alg = header.get("alg", "none")
    sub = payload.get("sub", payload.get("name", payload.get("email", "N/A")))
    iss = payload.get("iss", "N/A")
    exp = payload.get("exp")
    iat = payload.get("iat")
    now = time.time()

    # 计算 token 大小
    token_size = len(token.encode("utf-8"))

    summary_lines = [
        f"  Algorithm:  {C.BOLD}{alg}{C.RESET}",
        f"  Subject:    {C.CYAN}{sub}{C.RESET}",
        f"  Issuer:     {C.CYAN}{iss}{C.RESET}",
    ]

    if iat:
        age = now - iat
        summary_lines.append(f"  Age:        {C.BLUE}{format_duration(age)}{C.RESET}")

    if exp:
        remaining = exp - now
        if remaining > 0:
            summary_lines.append(f"  Expires in: {C.GREEN}{format_duration(remaining)}{C.RESET}")
        else:
            summary_lines.append(f"  Expired:    {C.RED}{format_duration(-remaining)}前{C.RESET}")

    summary_lines.append(f"  Token size: {C.DIM}{token_size} bytes{C.RESET}")

    print(wrap_box("🔍 Token Summary", summary_lines, C.GREEN))


# ─── JSON Output ──────────────────────────────────────────────────

def output_json(token):
    """以 JSON 格式输出解码结果"""
    header, payload, sig_bytes, _, _, _ = parse_jwt(token)
    now = time.time()

    result = {
        "header": header,
        "payload": payload,
        "signature": sig_bytes.hex(),
        "signature_bytes": len(sig_bytes),
    }

    # 添加状态信息
    exp = payload.get("exp")
    if exp:
        result["status"] = "expired" if exp < now else "valid"
        result["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp))
        result["expires_in_seconds"] = max(0, exp - now)
    else:
        result["status"] = "no_expiration"

    iat = payload.get("iat")
    if iat:
        result["issued_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(iat))
        result["age_seconds"] = now - iat

    print(json.dumps(result, indent=2, ensure_ascii=False))


# ─── Main CLI ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="jwtpeek",
        description="🔍 jwtpeek — Beautiful JWT token inspector for your terminal",
        epilog="Examples:\n"
               "  jwtpeek eyJhbGciOiJIUzI1NiJ9...\n"
               "  echo $TOKEN | jwtpeek\n"
               "  jwtpeek verify $TOKEN --secret mysecret\n"
               "  jwtpeek --json $TOKEN\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "token",
        nargs="?",
        help="JWT token to inspect (or pipe via stdin)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # verify 子命令
    verify_parser = subparsers.add_parser("verify", help="Verify token signature")
    verify_parser.add_argument("token", help="JWT token to verify")
    verify_parser.add_argument("--secret", "-s", required=True, help="Secret key for HMAC verification")
    verify_parser.add_argument("--algorithm", "-a", help="Algorithm (default: auto-detect from header)")

    # decode 子命令
    decode_parser = subparsers.add_parser("decode", help="Decode and display token")
    decode_parser.add_argument("token", help="JWT token to decode")

    # age 子命令
    age_parser = subparsers.add_parser("age", help="Show token age and expiration info")
    age_parser.add_argument("token", help="JWT token to check")

    # 通用选项
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    parser.add_argument("--json-only", action="store_true", help="Output only decoded payload as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--compact", "-c", action="store_true", help="Compact summary view")
    parser.add_argument("--version", "-v", action="version", version="jwtpeek 1.0.0")

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(C):
            if attr.isupper():
                setattr(C, attr, "")

    # 获取 token
    token = None

    if args.command in ("verify", "decode", "age"):
        # 子命令的 token 参数
        if args.command == "verify":
            token = args.token
        elif args.command == "decode":
            token = args.token
        elif args.command == "age":
            token = args.token
    else:
        token = args.token

    # 如果没有通过参数提供，尝试从 stdin 读取
    if not token:
        if not sys.stdin.isatty():
            token = sys.stdin.read().strip()
        else:
            parser.print_help()
            sys.exit(1)

    try:
        # 解析 JWT
        header, payload, sig_bytes, h_b64, p_b64, s_b64 = parse_jwt(token)

        if args.json_only:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return

        if args.json:
            output_json(token)
            return

        # 处理子命令
        if args.command == "verify":
            try:
                valid = verify_signature(token, args.secret, args.algorithm)
                if valid:
                    print(f"\n  {C.BG_GREEN}{C.BOLD} ✅ SIGNATURE VALID {C.RESET}\n")
                    print(f"  Token signature verified successfully with {C.GREEN}{header.get('alg', 'unknown')}{C.RESET}")
                else:
                    print(f"\n  {C.BG_RED}{C.BOLD} ❌ SIGNATURE INVALID {C.RESET}\n")
                    print(f"  Token signature does NOT match the provided secret.")
                    sys.exit(1)
            except JWTError as e:
                print(f"\n  {C.BG_RED}{C.BOLD} ⚠ ERROR {C.RESET}\n")
                print(f"  {C.RED}{e}{C.RESET}")
                sys.exit(1)
            return

        if args.command == "age":
            now = time.time()
            iat = payload.get("iat")
            exp = payload.get("exp")
            nbf = payload.get("nbf")

            print()
            if iat:
                age = now - iat
                print(f"  📅 Issued:     {format_timestamp(iat)}")
                print(f"  ⏱  Age:        {C.BLUE}{format_duration(age)}{C.RESET}")
            if exp:
                remaining = exp - now
                if remaining > 0:
                    print(f"  ⏳ Expires in: {C.GREEN}{format_duration(remaining)}{C.RESET}")
                else:
                    print(f"  ⛔ Expired:    {C.RED}{format_duration(-remaining)}前{C.RESET}")
                print(f"  📆 Expire at:  {format_timestamp(exp)}")
            if nbf:
                if nbf > now:
                    print(f"  🔒 Valid in:   {C.YELLOW}{format_duration(nbf - now)}{C.RESET}")
                else:
                    print(f"  🔓 Valid from: {format_timestamp(nbf)}")

            if not any([iat, exp, nbf]):
                print(f"  {C.DIM}No time-based claims found in this token{C.RESET}")
            print()
            return

        # 默认：完整展示
        print()
        print(f"  {C.BOLD}{C.BRIGHT_CYAN}🔍 jwtpeek{C.RESET}  {C.DIM}— JWT Token Inspector{C.RESET}")
        print()

        # 显示原始 token
        display_token_visual(token)

        # 紧凑模式只显示摘要
        if args.compact:
            display_summary(header, payload, sig_bytes, token)
            return

        # 完整模式
        display_header(header)
        display_payload(payload)
        display_signature_info(header, sig_bytes)

        # 底部提示
        print(f"  {C.DIM}💡 Tip: use --json for JSON output, 'verify' to check signature{C.RESET}")
        print()

    except JWTError as e:
        print(f"\n  {C.RED}❌ JWT Error:{C.RESET} {e}\n", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n  {C.RED}❌ JSON Decode Error:{C.RESET} {e}\n", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  {C.DIM}Interrupted{C.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n  {C.RED}❌ Error:{C.RESET} {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

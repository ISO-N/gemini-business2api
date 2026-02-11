"""
Gemini 自动化登录模块（DrissionPage 引擎）

说明：
- 该模块既会被“注册新账号”流程调用，也会被“刷新已有账号”流程调用；
- 自动化登录的核心验证方式是“邮箱验证码（OTP）”，页面提示仅用于辅助判定；
- 该模块的行为边界以 `docs/prd/gemini-business-automation-login-refresh-boundaries.md` 为准。
"""
import os
import json
import random
import string
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from urllib.parse import quote

from DrissionPage import ChromiumPage, ChromiumOptions
from core.base_task_service import TaskCancelledError


# 常量
AUTH_HOME_URL = "https://auth.business.gemini.google/"
DEFAULT_XSRF_TOKEN = "KdLRzKwwBTD5wo8nUollAbY6cW0"

# Linux 下常见的 Chromium 路径
CHROMIUM_PATHS = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
]


def _find_chromium_path() -> Optional[str]:
    """
    查找可用的 Chromium/Chrome 浏览器路径。

    返回值：
    - Optional[str]：可执行的浏览器路径；找不到则返回 None
    """
    for path in CHROMIUM_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


class GeminiAutomation:
    """
    Gemini 自动化登录（DrissionPage）。

    设计要点：
    - 以“模拟真实用户行为”为目标，但不承诺 100% 绕过风控；
    - “验证码是否发送成功”的判定优先使用网络监听，其次使用页面提示；
    - “验证码是否收到”以邮箱为准（最终可信来源）。
    """

    def __init__(
        self,
        user_agent: str = "",
        proxy: str = "",
        headless: bool = True,
        timeout: int = 60,
        log_callback=None,
    ) -> None:
        """
        初始化自动化实例。

        参数：
        - user_agent: 浏览器 UA 字符串；为空时会自动生成随机 UA
        - proxy: 代理地址（例如 http://host:port）；为空则不使用代理
        - headless: 是否无头模式（DP 支持有头/无头）
        - timeout: 页面级超时（秒）
        - log_callback: 日志回调函数，签名为 (level: str, message: str) -> None
        """
        self.user_agent = user_agent or self._get_ua()
        self.proxy = proxy
        self.headless = headless
        self.timeout = timeout
        self.log_callback = log_callback
        self._page = None
        self._user_data_dir = None
        self._last_send_error = ""

    def stop(self) -> None:
        """外部请求停止：尽力关闭浏览器实例。"""
        page = self._page
        if page:
            try:
                page.quit()
            except Exception:
                pass

    def login_and_extract(self, email: str, mail_client) -> dict:
        """
        执行登录并提取配置。

        参数：
        - email: 需要登录的邮箱地址（也是账号 ID）
        - mail_client: 邮箱客户端对象，必须提供 poll_for_code(timeout, interval, since_time) 方法

        返回值：
        - dict：统一返回结构：
          - success: bool
          - config: dict（成功时）/ error: str（失败时）
        """
        page = None
        user_data_dir = None
        try:
            page = self._create_page()
            user_data_dir = getattr(page, 'user_data_dir', None)
            self._page = page
            self._user_data_dir = user_data_dir
            return self._run_flow(page, email, mail_client)
        except TaskCancelledError:
            raise
        except Exception as exc:
            self._log("error", f"automation error: {exc}")
            return {"success": False, "error": str(exc)}
        finally:
            if page:
                try:
                    page.quit()
                except Exception:
                    pass
            self._page = None
            self._cleanup_user_data(user_data_dir)
            self._user_data_dir = None

    def _create_page(self) -> ChromiumPage:
        """创建浏览器页面"""
        options = ChromiumOptions()

        # 自动检测 Chromium 浏览器路径（Linux/Docker 环境）
        chromium_path = _find_chromium_path()
        if chromium_path:
            options.set_browser_path(chromium_path)

        options.set_argument("--incognito")
        options.set_argument("--no-sandbox")
        options.set_argument("--disable-dev-shm-usage")
        options.set_argument("--disable-setuid-sandbox")
        options.set_argument("--disable-blink-features=AutomationControlled")
        options.set_argument("--window-size=1280,800")
        options.set_user_agent(self.user_agent)

        # 语言设置（确保使用中文界面）
        options.set_argument("--lang=zh-CN")
        options.set_pref("intl.accept_languages", "zh-CN,zh")

        if self.proxy:
            options.set_argument(f"--proxy-server={self.proxy}")

        if self.headless:
            # 使用新版无头模式，更接近真实浏览器
            options.set_argument("--headless=new")
            options.set_argument("--disable-gpu")
            options.set_argument("--no-first-run")
            options.set_argument("--disable-extensions")
            # 反检测参数
            options.set_argument("--disable-infobars")
            options.set_argument("--enable-features=NetworkService,NetworkServiceInProcess")

        options.auto_port()
        page = ChromiumPage(options)
        page.set.timeouts(self.timeout)

        # 反检测：注入脚本隐藏自动化特征
        if self.headless:
            try:
                page.run_cdp("Page.addScriptToEvaluateOnNewDocument", source="""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
                    window.chrome = {runtime: {}};

                    // 额外的反检测措施
                    Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 1});
                    Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
                    Object.defineProperty(navigator, 'vendor', {get: () => 'Google Inc.'});

                    // 隐藏 headless 特征
                    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
                    Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});

                    // 模拟真实的 permissions
                    const originalQuery = window.navigator.permissions.query;
                    window.navigator.permissions.query = (parameters) => (
                        parameters.name === 'notifications' ?
                            Promise.resolve({state: Notification.permission}) :
                            originalQuery(parameters)
                    );
                """)
            except Exception:
                pass

        return page

    def _restart_network_listen(self, page) -> None:
        """
        重启网络监听（最佳努力）。

        说明：
        - 发送验证码时需要抓 `batchexecute` 等请求以判断是否触发风控；
        - DrissionPage 的 listen 缓冲是“消费型”的，重启可以避免读取到旧包造成误判；
        - 该方法失败不应影响主流程（因此全部 try/except）。
        """
        try:
            if hasattr(page, "listen") and page.listen:
                try:
                    page.listen.stop()
                except Exception:
                    pass
                page.listen.start(
                    targets=["batchexecute", "browserinfo", "verify-oob-code"],
                    is_regex=False,
                    method=("GET", "POST"),
                    res_type=("XHR", "FETCH", "DOCUMENT"),
                )
        except Exception:
            pass

    def _run_flow(self, page, email: str, mail_client) -> dict:
        """
        执行登录流程（验证码邮件验证）。

        参数：
        - page: ChromiumPage 实例
        - email: 登录邮箱
        - mail_client: 邮箱客户端（用于轮询验证码）

        返回值：
        - dict：与 login_and_extract 相同的 success/config/error 结构
        """

        # 记录任务开始时间，用于邮件时间过滤（全流程固定，不随重发更新）。
        # 说明：
        # - 这里使用“任务开始时间”而不是“每次发送时间”，避免“重发验证码”导致 since_time 前移，
        #   从而错过首封验证码邮件（部分邮箱存在投递延迟、或同一线程多封邮件的时间戳不稳定）。
        task_start_time = datetime.now()

        # Step 1: 导航到首页并设置 Cookie
        self._log("info", f"🌐 打开登录页面: {email}")

        page.get(AUTH_HOME_URL, timeout=self.timeout)
        time.sleep(2)

        # 设置两个关键 Cookie
        try:
            self._log("info", "🍪 设置认证 Cookies...")
            page.set.cookies({
                "name": "__Host-AP_SignInXsrf",
                "value": DEFAULT_XSRF_TOKEN,
                "url": AUTH_HOME_URL,
                "path": "/",
                "secure": True,
            })
        except Exception as e:
            self._log("warning", f"⚠️ Cookie 设置失败: {e}")

        login_hint = quote(email, safe="")
        login_url = f"https://auth.business.gemini.google/login/email?continueUrl=https%3A%2F%2Fbusiness.gemini.google%2F&loginHint={login_hint}&xsrfToken={DEFAULT_XSRF_TOKEN}"

        # 提前启动网络监听（最佳努力）：用于捕获“页面加载后默认触发发送验证码”的请求/响应
        self._restart_network_listen(page)

        page.get(login_url, timeout=self.timeout)
        time.sleep(5)

        # Step 2: 检查当前页面状态
        current_url = page.url
        self._log("info", f"📍 当前 URL: {current_url}")
        has_business_params = "business.gemini.google" in current_url and "csesidx=" in current_url and "/cid/" in current_url

        if has_business_params:
            self._log("info", "✅ 已登录，提取配置")
            return self._extract_config(page, email)

        # Step 3: 点击发送验证码按钮（最多5轮，每轮间隔10秒；遇到明确风控信号则尽快失败）
        self._log("info", "📧 发送验证码...")
        max_send_rounds = 5  # 文档边界：最多 5 轮
        resend_delay_seconds = 10  # 文档边界：失败每轮固定间隔 10 秒
        send_ok = False

        for send_round in range(1, max_send_rounds + 1):
            # 从第二轮起重启一次网络监听，避免读取到旧包造成误判；首轮保留“提前监听”的包用于判定
            if send_round > 1:
                self._restart_network_listen(page)
            self._last_send_error = ""

            if self._click_send_code_button(page):
                send_ok = True
                break

            # 遇到明确风控/发送失败信号时，尽快失败并给出建议（避免长时间空等）
            if self._last_send_error in ("captcha_check_failed", "send_email_otp_error"):
                self._log("error", "❌ 检测到风控/发送失败信号，建议更换代理/IP 并降低刷新频率")
                self._save_screenshot(page, "send_code_risk_or_failed")
                self._stop_listen(page)
                return {"success": False, "error": self._last_send_error}

            if send_round < max_send_rounds:
                self._log("warning", f"⚠️ 发送失败，{resend_delay_seconds}秒后重试 ({send_round}/{max_send_rounds})")
                time.sleep(resend_delay_seconds)

        # 发送阶段结束后停止监听，避免后续流程无限积累监听缓冲
        self._stop_listen(page)

        if not send_ok:
            self._log("error", "❌ 验证码发送失败（可能触发风控），建议更换代理IP")
            self._save_screenshot(page, "send_code_button_failed")
            return {"success": False, "error": "send code failed after retries"}

        # Step 4: 等待验证码输入框出现
        code_input = self._wait_for_code_input(page)
        if not code_input:
            self._log("error", "❌ 验证码输入框未出现")
            self._save_screenshot(page, "code_input_missing")
            return {"success": False, "error": "code input not found"}

        # Step 5: 轮询邮件获取验证码（3次，每次5秒间隔）
        self._log("info", "📬 等待邮箱验证码...")
        code = mail_client.poll_for_code(timeout=15, interval=5, since_time=task_start_time)

        if not code:
            self._log("warning", "⚠️ 验证码超时，15秒后重新发送...")
            time.sleep(15)
            # 尝试点击重新发送按钮
            if self._click_resend_code_button(page):
                # 再次轮询验证码（3次，每次5秒间隔）
                code = mail_client.poll_for_code(timeout=15, interval=5, since_time=task_start_time)
                if not code:
                    self._log("error", "❌ 重新发送后仍未收到验证码")
                    self._save_screenshot(page, "code_timeout_after_resend")
                    return {"success": False, "error": "verification code timeout after resend"}
            else:
                self._log("error", "❌ 验证码超时且未找到重新发送按钮")
                self._save_screenshot(page, "code_timeout")
                return {"success": False, "error": "verification code timeout"}

        self._log("info", f"✅ 收到验证码: {code}")

        # Step 6: 输入验证码并提交
        code_input = page.ele("css:input[jsname='ovqh0b']", timeout=3) or \
                     page.ele("css:input[type='tel']", timeout=2)

        if not code_input:
            self._log("error", "❌ 验证码输入框已失效")
            return {"success": False, "error": "code input expired"}

        # 尝试模拟人类输入，失败则降级到直接注入
        self._log("info", "⌨️ 输入验证码...")
        if not self._simulate_human_input(code_input, code):
            self._log("warning", "⚠️ 模拟输入失败，降级为直接输入")
            code_input.input(code, clear=True)
            time.sleep(0.5)

        # 直接使用回车提交，不再查找按钮
        self._log("info", "⏎ 提交验证码")
        code_input.input("\n")

        # Step 7: 等待页面自动重定向（提交验证码后 Google 会自动跳转）
        self._log("info", "⏳ 等待验证后跳转...")
        time.sleep(12)

        # 记录当前 URL 状态
        current_url = page.url
        self._log("info", f"📍 验证后 URL: {current_url}")

        # 检查是否还停留在验证码页面（说明提交失败）
        if "verify-oob-code" in current_url:
            self._log("error", "❌ 验证码提交失败")
            self._save_screenshot(page, "verification_submit_failed")
            return {"success": False, "error": "verification code submission failed"}

        # Step 8: 处理协议页面（如果有）
        self._handle_agreement_page(page)

        # Step 9: 检查是否已经在正确的页面
        current_url = page.url
        has_business_params = "business.gemini.google" in current_url and "csesidx=" in current_url and "/cid/" in current_url

        if has_business_params:
            return self._extract_config(page, email)

        # Step 10: 如果不在正确的页面，尝试导航
        if "business.gemini.google" not in current_url:
            page.get("https://business.gemini.google/", timeout=self.timeout)
            time.sleep(5)

        # Step 11: 检查是否需要设置用户名
        if "cid" not in page.url:
            if self._handle_username_setup(page):
                time.sleep(5)

        # Step 12: 等待 URL 参数生成（csesidx 和 cid）
        if not self._wait_for_business_params(page):
            page.refresh()
            time.sleep(5)
            if not self._wait_for_business_params(page):
                self._log("error", "❌ URL 参数生成失败")
                self._save_screenshot(page, "params_missing")
                return {"success": False, "error": "URL parameters not found"}

        # Step 13: 提取配置
        self._log("info", "🎊 登录成功，提取配置...")
        return self._extract_config(page, email)

    def _click_send_code_button(self, page) -> bool:
        """
        点击发送验证码按钮（单次尝试）。

        说明：
        - 该方法只负责“找按钮 + 点一次 + 做一次发送成功判定”；
        - 重试策略由上层（_run_flow 的 Step 3）控制，避免出现重复叠加的重试；
        - 若已经进入验证码输入页，则通常表示验证码已触发发送（或发送入口已通过），直接继续流程。

        参数：
        - page: ChromiumPage 页面对象

        返回值：
        - bool：True 表示“允许继续流程”（发送成功或无法判断但保守继续）；
                False 表示“明确失败”（例如检测到风控信号、页面报错、按钮缺失/不可点击）。
        """
        time.sleep(2)

        # 若已出现验证码输入框，视为已进入验证阶段，不再重复点发送按钮。
        code_input = page.ele("css:input[jsname='ovqh0b']", timeout=1) or page.ele(
            "css:input[name='pinInput']",
            timeout=1,
        )
        if code_input:
            self._log("info", "✅ 已在验证码输入页面（跳过发送按钮点击）")
            return True

        # 方法1: 直接通过 ID 查找（优先）
        direct_btn = page.ele("#sign-in-with-email", timeout=5)
        if direct_btn:
            try:
                direct_btn.click()
                return self._verify_send_code_after_click(page)
            except Exception as e:
                self._last_send_error = "send_button_click_failed"
                self._log("warning", f"⚠️ 点击失败: {e}")
                return False

        # 方法2: 通过关键词查找按钮
        keywords = ["通过电子邮件发送验证码", "通过电子邮件发送", "email", "Email", "Send code", "Send verification", "Verification code"]
        try:
            buttons = page.eles("tag:button")
            for btn in buttons:
                text = (btn.text or "").strip()
                if text and any(kw in text for kw in keywords):
                    try:
                        btn.click()
                        return self._verify_send_code_after_click(page)
                    except Exception as e:
                        self._last_send_error = "send_button_click_failed"
                        self._log("warning", f"⚠️ 点击失败: {e}")
                        return False
        except Exception as e:
            self._log("warning", f"⚠️ 搜索按钮异常: {e}")

        # 仍未找到发送按钮，且也不在验证码输入页面：明确失败
        self._last_send_error = "send_button_not_found"
        self._log("error", "❌ 未找到发送验证码按钮")
        return False

    def _stop_listen(self, page) -> None:
        """
        安全地停止网络监听（最佳努力）。

        参数：
        - page: ChromiumPage 页面对象
        """
        try:
            if hasattr(page, 'listen') and page.listen:
                page.listen.stop()
        except Exception:
            pass

    def _verify_code_send_by_network(self, page) -> Optional[bool]:
        """
        通过监听网络请求验证验证码是否成功发送（优先级最高）。

        返回值语义：
        - True：捕获到关键请求，且未发现明确错误信号 → 认为发送成功
        - False：捕获到关键请求，且发现 `CAPTCHA_CHECK_FAILED` / `SendEmailOtpError` → 认为发送失败（风控/发送失败）
        - None：未捕获到关键请求/监听不可用 → 无法判断（交由页面提示或邮箱收码最终判定）
        """
        try:
            time.sleep(1)

            packets = []
            max_wait_seconds = 6
            deadline = time.time() + max_wait_seconds
            try:
                while time.time() < deadline:
                    got_any = False
                    for packet in page.listen.steps(timeout=1, gap=1):
                        packets.append(packet)
                        got_any = True
                    if got_any:
                        time.sleep(0.2)
                    else:
                        break
            except Exception:
                return None

            if not packets:
                return None

            # 保存网络日志（仅用于调试）
            self._save_network_packets(packets)

            found_batchexecute = False
            found_batchexecute_error = False

            for packet in packets:
                try:
                    url = str(packet.url) if hasattr(packet, 'url') else str(packet)

                    if 'batchexecute' in url:
                        found_batchexecute = True

                        try:
                            response = packet.response if hasattr(packet, 'response') else None
                            if response and hasattr(response, 'raw_body'):
                                body = response.raw_body
                                raw_body_str = str(body)
                                if "CAPTCHA_CHECK_FAILED" in raw_body_str:
                                    found_batchexecute_error = True
                                    self._last_send_error = "captcha_check_failed"
                                elif "SendEmailOtpError" in raw_body_str:
                                    found_batchexecute_error = True
                                    self._last_send_error = "send_email_otp_error"
                        except Exception:
                            pass

                except Exception:
                    continue

            if found_batchexecute:
                if found_batchexecute_error:
                    return False
                return True
            else:
                return None

        except Exception:
            return None

    def _verify_code_send_status(self, page) -> Optional[bool]:
        """
        检测页面提示判断是否发送成功（辅助判定）。

        返回值语义：
        - True：命中成功提示关键词
        - False：命中错误提示关键词
        - None：未找到可判断的提示（上层按“保守继续”策略处理）
        """
        time.sleep(2)
        try:
            success_keywords = ["验证码已发送", "code sent", "email sent", "check your email", "已发送"]
            error_keywords = [
                "出了点问题",
                "something went wrong",
                "error",
                "failed",
                "try again",
                "稍后再试",
                "选择其他登录方法"
            ]
            selectors = [
                "css:.zyTWof-gIZMF",
                "css:[role='alert']",
                "css:aside",
            ]
            for selector in selectors:
                try:
                    elements = page.eles(selector, timeout=1)
                    for elem in elements[:20]:
                        text = (elem.text or "").strip()
                        if not text:
                            continue
                        if any(kw in text for kw in error_keywords):
                            self._last_send_error = "send_toast_error"
                            return False
                        if any(kw in text for kw in success_keywords):
                            return True
                except Exception:
                    continue
            return None
        except Exception:
            return None

    def _verify_send_code_after_click(self, page) -> bool:
        """
        在“点击发送验证码”之后，综合网络监听与页面提示进行判定。

        判定优先级：
        1) 网络监听：若捕获到明确错误信号（CAPTCHA/SendEmailOtpError）则立即判定失败；
        2) 页面提示：若捕获到错误提示则失败；若捕获到成功提示则成功；
        3) 无法判断：按产品边界“保守继续流程”，最终以邮箱收码为准。

        参数：
        - page: ChromiumPage 页面对象

        返回值：
        - bool：是否允许继续流程
        """
        network_result = self._verify_code_send_by_network(page)
        if network_result is True:
            return True
        if network_result is False:
            # 明确风控/发送失败：不允许继续，避免进入长时间空等
            return False

        toast_result = self._verify_code_send_status(page)
        if toast_result is False:
            return False
        # toast_result=True 或 None：均按“保守继续流程”处理
        return True

    def _truncate_text(self, text: str, max_len: int = 2000) -> str:
        """
        截断文本，避免日志/抓包文件过大。

        参数：
        - text: 原始文本
        - max_len: 最大保留长度

        返回值：
        - str：截断后的文本
        """
        if text is None:
            return ""
        if len(text) <= max_len:
            return text
        return text[:max_len] + f"...(truncated, total={len(text)})"

    def _save_network_packets(self, packets) -> None:
        """
        保存网络日志（仅用于调试）。

        安全/隐私说明：
        - 网络日志属于本地文件证据，禁止通过公开接口直接暴露；
        - 本方法会对 body/postData 做截断与字符串化，避免写入不可序列化对象或过大内容。
        """
        try:
            from core.storage import _data_file_path
            base_dir = _data_file_path(os.path.join("logs", "network"))
            os.makedirs(base_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            file_path = os.path.join(base_dir, f"network-{ts}.jsonl")

            def safe_str(value: Any, max_len: int = 2000) -> str:
                """
                将任意对象转换为可写入 JSONL 的字符串（并做长度截断）。

                参数：
                - value: 任意对象（可能是 bytes/dict/list/异常等）
                - max_len: 最大长度（字符）

                返回值：
                - str：可读字符串
                """
                try:
                    if value is None:
                        return ""
                    if isinstance(value, (bytes, bytearray)):
                        try:
                            text = value.decode("utf-8", errors="replace")
                        except Exception:
                            text = repr(value)
                        return self._truncate_text(text, max_len=max_len)
                    if isinstance(value, str):
                        return self._truncate_text(value, max_len=max_len)
                    return self._truncate_text(str(value), max_len=max_len)
                except Exception:
                    return "<unprintable>"

            def safe_headers(headers: Any) -> dict:
                """
                将 headers 规范化为 dict[str, str]，避免写入不可序列化对象。

                参数：
                - headers: 原始 headers（可能是 dict/None/其他类型）

                返回值：
                - dict：规范化后的 headers
                """
                if not headers or not isinstance(headers, dict):
                    return {}
                result: dict = {}
                for k, v in headers.items():
                    result[safe_str(k, max_len=256)] = safe_str(v, max_len=512)
                return result

            with open(file_path, "a", encoding="utf-8") as f:
                for packet in packets:
                    try:
                        req = packet.request if hasattr(packet, "request") else None
                        resp = packet.response if hasattr(packet, "response") else None
                        fail = packet.fail_info if hasattr(packet, "fail_info") else None

                        item = {
                            "url": safe_str(packet.url) if hasattr(packet, "url") else safe_str(packet),
                            "method": safe_str(packet.method) if hasattr(packet, "method") else "UNKNOWN",
                            "resourceType": safe_str(packet.resourceType) if hasattr(packet, "resourceType") else "",
                            "is_failed": bool(packet.is_failed) if hasattr(packet, "is_failed") else False,
                            "fail_info": safe_str(fail) if fail else "",
                            "request": {
                                "headers": safe_headers(req.headers) if req and hasattr(req, "headers") else {},
                                "postData": safe_str(req.postData, max_len=4000) if req and hasattr(req, "postData") else "",
                            },
                            "response": {
                                "status": resp.status if resp and hasattr(resp, "status") else 0,
                                "headers": safe_headers(resp.headers) if resp and hasattr(resp, "headers") else {},
                                "raw_body": safe_str(resp.raw_body, max_len=8000) if resp and hasattr(resp, "raw_body") else "",
                            },
                        }
                        f.write(json.dumps(item, ensure_ascii=False) + "\n")
                    except Exception as e:
                        f.write(json.dumps({"error": safe_str(e)}, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _wait_for_code_input(self, page, timeout: int = 30):
        """等待验证码输入框出现"""
        selectors = [
            "css:input[jsname='ovqh0b']",
            "css:input[type='tel']",
            "css:input[name='pinInput']",
            "css:input[autocomplete='one-time-code']",
        ]
        for _ in range(timeout // 2):
            for selector in selectors:
                try:
                    el = page.ele(selector, timeout=1)
                    if el:
                        return el
                except Exception:
                    continue
            time.sleep(2)
        return None

    def _simulate_human_input(self, element, text: str) -> bool:
        """模拟人类输入（逐字符输入，带随机延迟）

        Args:
            element: 输入框元素
            text: 要输入的文本

        Returns:
            bool: 是否成功
        """
        try:
            # 先点击输入框获取焦点
            element.click()
            time.sleep(random.uniform(0.1, 0.3))

            # 逐字符输入
            for char in text:
                element.input(char)
                # 随机延迟：模拟人类打字速度（50-150ms/字符）
                time.sleep(random.uniform(0.05, 0.15))

            # 输入完成后短暂停顿
            time.sleep(random.uniform(0.2, 0.5))
            return True
        except Exception:
            return False

    def _find_verify_button(self, page):
        """查找验证按钮（排除重新发送按钮）"""
        try:
            buttons = page.eles("tag:button")
            for btn in buttons:
                text = (btn.text or "").strip().lower()
                if text and "重新" not in text and "发送" not in text and "resend" not in text and "send" not in text:
                    return btn
        except Exception:
            pass
        return None

    def _click_resend_code_button(self, page) -> bool:
        """点击重新发送验证码按钮"""
        time.sleep(2)

        # 查找包含重新发送关键词的按钮（与 _find_verify_button 相反）
        try:
            buttons = page.eles("tag:button")
            for btn in buttons:
                text = (btn.text or "").strip().lower()
                if text and ("重新" in text or "resend" in text):
                    try:
                        self._log("info", f"🔄 点击重新发送按钮")
                        btn.click()
                        time.sleep(2)
                        return True
                    except Exception:
                        pass
        except Exception:
            pass

        return False

    def _handle_agreement_page(self, page) -> None:
        """处理协议页面"""
        if "/admin/create" in page.url:
            agree_btn = page.ele("css:button.agree-button", timeout=5)
            if agree_btn:
                agree_btn.click()
                time.sleep(2)

    def _wait_for_cid(self, page, timeout: int = 10) -> bool:
        """等待URL包含cid"""
        for _ in range(timeout):
            if "cid" in page.url:
                return True
            time.sleep(1)
        return False

    def _wait_for_business_params(self, page, timeout: int = 30) -> bool:
        """等待业务页面参数生成（csesidx 和 cid）"""
        for _ in range(timeout):
            url = page.url
            if "csesidx=" in url and "/cid/" in url:
                return True
            time.sleep(1)
        return False

    def _handle_username_setup(self, page) -> bool:
        """处理用户名设置页面"""
        current_url = page.url

        if "auth.business.gemini.google/login" in current_url:
            return False

        selectors = [
            "css:input[type='text']",
            "css:input[name='displayName']",
            "css:input[aria-label*='用户名' i]",
            "css:input[aria-label*='display name' i]",
        ]

        username_input = None
        for selector in selectors:
            try:
                username_input = page.ele(selector, timeout=2)
                if username_input:
                    break
            except Exception:
                continue

        if not username_input:
            return False

        suffix = "".join(random.choices(string.ascii_letters + string.digits, k=3))
        username = f"Test{suffix}"

        try:
            # 清空输入框
            username_input.click()
            time.sleep(0.2)
            username_input.clear()
            time.sleep(0.1)

            # 尝试模拟人类输入，失败则降级到直接注入
            if not self._simulate_human_input(username_input, username):
                username_input.input(username)
                time.sleep(0.3)

            buttons = page.eles("tag:button")
            submit_btn = None
            for btn in buttons:
                text = (btn.text or "").strip().lower()
                if any(kw in text for kw in ["确认", "提交", "继续", "submit", "continue", "confirm", "save", "保存", "下一步", "next"]):
                    submit_btn = btn
                    break

            if submit_btn:
                submit_btn.click()
            else:
                username_input.input("\n")

            time.sleep(5)
            return True
        except Exception:
            return False

    def _extract_config(self, page, email: str) -> dict:
        """提取配置"""
        try:
            if "cid/" not in page.url:
                page.get("https://business.gemini.google/", timeout=self.timeout)
                time.sleep(3)

            url = page.url
            if "cid/" not in url:
                return {"success": False, "error": "cid not found"}

            config_id = url.split("cid/")[1].split("?")[0].split("/")[0]
            csesidx = url.split("csesidx=")[1].split("&")[0] if "csesidx=" in url else ""

            cookies = page.cookies()
            ses = next((c["value"] for c in cookies if c["name"] == "__Secure-C_SES"), None)
            host = next((c["value"] for c in cookies if c["name"] == "__Host-C_OSES"), None)

            ses_obj = next((c for c in cookies if c["name"] == "__Secure-C_SES"), None)
            # 使用北京时区，确保时间计算正确（Cookie expiry 是 UTC 时间戳）
            beijing_tz = timezone(timedelta(hours=8))
            if ses_obj and "expiry" in ses_obj:
                # 将 UTC 时间戳转为北京时间，再减去12小时作为刷新窗口
                cookie_expire_beijing = datetime.fromtimestamp(ses_obj["expiry"], tz=beijing_tz)
                expires_at = (cookie_expire_beijing - timedelta(hours=12)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                expires_at = (datetime.now(beijing_tz) + timedelta(hours=12)).strftime("%Y-%m-%d %H:%M:%S")

            config = {
                "id": email,
                "csesidx": csesidx,
                "config_id": config_id,
                "secure_c_ses": ses,
                "host_c_oses": host,
                "expires_at": expires_at,
            }
            return {"success": True, "config": config}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _save_screenshot(self, page, name: str) -> None:
        """保存截图"""
        try:
            from core.storage import _data_file_path
            screenshot_dir = _data_file_path("automation")
            os.makedirs(screenshot_dir, exist_ok=True)
            path = os.path.join(screenshot_dir, f"{name}_{int(time.time())}.png")
            page.get_screenshot(path=path)
        except Exception:
            pass

    def _log(self, level: str, message: str) -> None:
        """记录日志"""
        if self.log_callback:
            try:
                self.log_callback(level, message)
            except TaskCancelledError:
                raise
            except Exception:
                pass

    def _cleanup_user_data(self, user_data_dir: Optional[str]) -> None:
        """清理浏览器用户数据目录"""
        if not user_data_dir:
            return
        try:
            import shutil
            if os.path.exists(user_data_dir):
                shutil.rmtree(user_data_dir, ignore_errors=True)
        except Exception:
            pass

    @staticmethod
    def _get_ua() -> str:
        """生成随机User-Agent"""
        v = random.choice(["120.0.0.0", "121.0.0.0", "122.0.0.0"])
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36"

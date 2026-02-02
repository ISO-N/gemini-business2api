"""
Mihomo External Controller 客户端封装。

本模块用于在应用侧通过 mihomo 的 RESTful API（External Controller）完成以下操作：
1) 读取策略组（例如 select 组）的当前选中节点与候选列表；
2) 对“候选节点”进行延迟/可用性测试（delay）；
3) 将策略组切换到指定节点（select）。

设计原则：
- 只做最小必要封装，避免引入与业务强耦合的逻辑；
- 所有请求默认“直连 controller”（不走代理），避免出现“请求走代理再回到 controller”的套娃问题；
- 所有异常交由调用方决定如何处理（调用方可选择吞掉并记录日志，避免影响主流程）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx


@dataclass(frozen=True)
class MihomoProxyGroupSnapshot:
    """
    策略组快照（只包含本项目需要的字段）。

    参数：
    - name: 策略组名称（例如 NCloud）
    - now: 当前选中节点名称
    - all: 候选节点名称列表（保持 controller 返回顺序）

    返回值：
    - 本数据类本身（用于在调用链中传递 group 状态）
    """

    name: str
    now: str
    all: List[str]


class MihomoControllerClient:
    """
    Mihomo External Controller API 客户端。

    说明：
    - controller_base_url 形如 "http://127.0.0.1:9090"
    - 若 controller 配置了 secret，本客户端会以 `Authorization: Bearer <secret>` 发送请求
    """

    def __init__(
        self,
        controller_base_url: str,
        secret: str,
        timeout_seconds: float = 3.0,
    ) -> None:
        """
        初始化客户端。

        参数：
        - controller_base_url: controller 基础地址（带协议与端口）
        - secret: controller 的鉴权密钥（mihomo 配置中的 secret）
        - timeout_seconds: controller 请求超时（秒）；不建议太大，避免阻塞主流程
        """
        self._base_url = (controller_base_url or "").strip().rstrip("/")
        self._secret = str(secret or "")
        self._timeout = float(timeout_seconds)

    def _headers(self) -> Dict[str, str]:
        """
        生成请求头。

        返回值：
        - dict: http headers（包含 Authorization）
        """
        return {"Authorization": f"Bearer {self._secret}"} if self._secret else {}

    @staticmethod
    def _encode_path_segment(name: str) -> str:
        """
        对 controller 路径中的名称进行 URL 编码（避免中文/空格导致 404）。

        参数：
        - name: 原始名称（策略组名/节点名）

        返回值：
        - 编码后的字符串，可安全拼接到 URL path
        """
        return quote(str(name or ""), safe="")

    async def get_proxy_group(self, group_name: str) -> MihomoProxyGroupSnapshot:
        """
        获取策略组状态（当前选中与候选列表）。

        参数：
        - group_name: 策略组名称（例如 NCloud）

        返回值：
        - MihomoProxyGroupSnapshot: 策略组快照（包含 now/all）
        """
        group = str(group_name or "").strip()
        if not group:
            raise ValueError("group_name 不能为空")

        encoded = self._encode_path_segment(group)
        async with httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout, connect=self._timeout),
            proxy=None,
            verify=False,
        ) as client:
            resp = await client.get(f"/proxies/{encoded}", headers=self._headers())
            resp.raise_for_status()
            data: Dict[str, Any] = resp.json() or {}

        now = str(data.get("now") or "")
        all_list = data.get("all") or []
        if not isinstance(all_list, list):
            all_list = []
        all_names = [str(x) for x in all_list if str(x)]
        return MihomoProxyGroupSnapshot(name=group, now=now, all=all_names)

    async def test_delay_ms(self, proxy_name: str, test_url: str, timeout_ms: int) -> Optional[int]:
        """
        对指定节点/策略做延迟测试。

        说明：
        - mihomo/clash controller 通常提供 `/proxies/{name}/delay` 接口；
        - 本方法只关心“是否可用”与“返回的 delay（毫秒）”，返回 None 表示不可用/异常。

        参数：
        - proxy_name: 节点名称（通常为具体节点名，而非组名）
        - test_url: 用于探测的 URL（建议使用 generate_204）
        - timeout_ms: 探测超时（毫秒）

        返回值：
        - Optional[int]: 成功返回延迟（毫秒），失败返回 None
        """
        name = str(proxy_name or "").strip()
        if not name:
            return None

        encoded = self._encode_path_segment(name)
        params = {
            "url": str(test_url or "").strip() or "http://www.gstatic.com/generate_204",
            "timeout": int(max(int(timeout_ms or 0), 1)),
        }
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout, connect=self._timeout),
                proxy=None,
                verify=False,
            ) as client:
                resp = await client.get(f"/proxies/{encoded}/delay", headers=self._headers(), params=params)
                resp.raise_for_status()
                data: Dict[str, Any] = resp.json() or {}
            delay = data.get("delay")
            if delay is None:
                return None
            return int(delay)
        except Exception:
            return None

    async def select_proxy(self, group_name: str, proxy_name: str) -> None:
        """
        将策略组切换到指定节点。

        参数：
        - group_name: 策略组名称（必须是可切换的 select/selector 类组）
        - proxy_name: 要切换到的候选名称（必须在该组的 all 列表中）

        返回值：
        - None（成功则正常返回；失败则抛异常给调用方处理）
        """
        group = str(group_name or "").strip()
        target = str(proxy_name or "").strip()
        if not group:
            raise ValueError("group_name 不能为空")
        if not target:
            raise ValueError("proxy_name 不能为空")

        encoded_group = self._encode_path_segment(group)
        payload = {"name": target}
        async with httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout, connect=self._timeout),
            proxy=None,
            verify=False,
        ) as client:
            resp = await client.put(f"/proxies/{encoded_group}", headers=self._headers(), json=payload)
            resp.raise_for_status()


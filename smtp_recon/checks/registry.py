from __future__ import annotations

from .auth_method_check import AuthMethodCheck
from .banner_grab import BannerGrabCheck
from .ehlo_capabilities import EhloCapabilitiesCheck
from .expn_user_enum import ExpnUserEnumCheck
from .open_relay_check import OpenRelayCheck
from .port_detection import PortDetectionCheck
from .rcpt_to_user_enum import RcptToUserEnumCheck
from .spoofing_check import SpoofingCheck
from .starttls_check import StartTlsCheck
from .vrfy_user_enum import VrfyUserEnumCheck

CHECK_REGISTRY: dict[str, type] = {
    "port_detection": PortDetectionCheck,
    "banner_grab": BannerGrabCheck,
    "ehlo_capabilities": EhloCapabilitiesCheck,
    "starttls": StartTlsCheck,
    "auth_methods": AuthMethodCheck,
    "vrfy_user_enum": VrfyUserEnumCheck,
    "expn_user_enum": ExpnUserEnumCheck,
    "rcpt_to_user_enum": RcptToUserEnumCheck,
    "open_relay": OpenRelayCheck,
    "spoofing": SpoofingCheck,
}

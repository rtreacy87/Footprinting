from .service_detection import ServiceDetectionCheck
from .listener_enum import ListenerEnumerationCheck
from .sid_enum import SidEnumerationCheck
from .auth_enum import AuthenticationEnumerationCheck
from .post_auth_enum import PostAuthEnumerationCheck
from .abuse_path_review import AbusePathReviewCheck

CHECK_REGISTRY = {
    "service_detection": ServiceDetectionCheck,
    "listener_enum": ListenerEnumerationCheck,
    "sid_enum": SidEnumerationCheck,
    "auth_enum": AuthenticationEnumerationCheck,
    "post_auth_enum": PostAuthEnumerationCheck,
    "abuse_path_review": AbusePathReviewCheck,
}

__all__ = [
    "ServiceDetectionCheck",
    "ListenerEnumerationCheck",
    "SidEnumerationCheck",
    "AuthenticationEnumerationCheck",
    "PostAuthEnumerationCheck",
    "AbusePathReviewCheck",
    "CHECK_REGISTRY",
]

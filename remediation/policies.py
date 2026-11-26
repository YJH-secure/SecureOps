"""E가 관리하는 고정 MOCK 조치 정책. 보고서 내용으로 정책을 등록하지 않는다."""

from dataclasses import dataclass
from types import MappingProxyType

from .handlers import SSH01MockHandler
from .file01 import File01MockHandler, actions as file01_actions


@dataclass(frozen=True)
class RemediationPolicy:
    check_id: str
    policy_version: str
    supported_os: frozenset[str]
    actions: tuple[tuple[str, str, str], ...]
    handler: type


REMEDIATION_POLICIES = MappingProxyType({
    "SSH-01": RemediationPolicy(
        check_id="SSH-01",
        policy_version="ssh-01-proposal-v1",
        supported_os=frozenset({"ubuntu-24.04", "ubuntu-24.04.5"}),
        actions=(("ssh_dropin", "/etc/ssh/sshd_config.d/01-secureops.conf", "PermitRootLogin no\n"),),
        handler=SSH01MockHandler,
    ),
    "FILE-01": RemediationPolicy(
        check_id="FILE-01", policy_version="file01-offline-mock-20261123",
        supported_os=frozenset({"ubuntu-24.04", "ubuntu-24.04.5"}),
        actions=file01_actions(), handler=File01MockHandler,
    ),
})

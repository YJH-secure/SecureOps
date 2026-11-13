"""E가 관리하는 고정 MOCK 조치 정책. 보고서 내용으로 정책을 등록하지 않는다."""

from dataclasses import dataclass
from types import MappingProxyType

from .handlers import SSH01MockHandler


@dataclass(frozen=True)
class RemediationPolicy:
    check_id: str
    policy_version: str
    supported_os: frozenset[str]
    actions: tuple[tuple[str, str, str], ...]
    handler: type[SSH01MockHandler]


REMEDIATION_POLICIES = MappingProxyType({
    "SSH-01": RemediationPolicy(
        check_id="SSH-01",
        policy_version="ssh-01-proposal-v1",
        supported_os=frozenset({"ubuntu-24.04", "ubuntu-24.04.5"}),
        actions=(("ssh_dropin", "/etc/ssh/sshd_config.d/01-secureops.conf", "PermitRootLogin no\n"),),
        handler=SSH01MockHandler,
    ),
})

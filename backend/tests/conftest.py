import ipaddress
import socket
from collections.abc import Generator
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def block_nonlocal_network(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    original_connect = socket.socket.connect

    def local_only(sock: socket.socket, address: Any) -> Any:
        if isinstance(address, tuple):
            host = str(address[0])
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    raise RuntimeError(f"tests forbid non-local network access: {host}")
            except ValueError as error:
                message = f"tests require a loopback IP, not a hostname: {host}"
                raise RuntimeError(message) from error
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", local_only)
    yield

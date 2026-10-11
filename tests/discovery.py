"""Test Avahi service announcements, peer discovery, and CLI responsiveness."""
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from chat_cli import Chat, finish_connection, message


def discovery_result(chat, mark):
    deadline = time.monotonic() + 10
    with chat.condition:
        while not any(line.startswith(("Found ", "No active peers found.", "Failed to discover:"))
                      for line in chat.lines[mark:]):
            if chat.process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f"Discovery did not finish: {chat.lines}")
            chat.condition.wait(0.1)
    # Следующая команда выполняется после вывода полного списка на исполнителе CLI.
    chat.wait("Available commands:", chat.command("help"))
    lines = chat.lines[mark:]
    failures = [line for line in lines if line.startswith("Failed to discover:")]
    entries = []
    for line in lines:
        if line.startswith("["):
            match = re.fullmatch(r"\[(\d+)\] (\S+)(?: \(\+(\d+) addresses?\))?", line)
            assert match, line
            entries.append((int(match[1]), match[2], int(match[3] or 0)))
    return entries, failures


def test_unavailable(root, chats):
    environment = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS=f"unix:path={root / 'missing-bus'}")
    alice = Chat(root / "alice", environment=environment)
    bob = Chat(root / "bob", environment=environment)
    chats += [alice, bob]
    mark = alice.command("discover")
    started = time.monotonic()
    alice.wait("Available commands:", alice.command("help"))
    assert time.monotonic() - started < 1.5, "Discovery blocked CLI commands"
    entries, failures = discovery_result(alice, mark)
    assert not entries and any("Avahi" in line for line in failures), "Missing Avahi did not produce a clear error"

    # Прямой чат доступен независимо от состояния системной службы обнаружения.
    receiver_mark = bob.mark()
    marks = alice.command(f"connect localhost:{bob.port}"), receiver_mark
    alice.wait("Trust this peer?", marks[0])
    bob.wait("Trust this peer?", marks[1])
    alice.command("yes")
    bob.command("yes")
    finish_connection(alice, bob, marks)
    message(alice, bob, "chat works without Avahi")
    alice.command("discover")
    alice.wait("Discovery is in progress", alice.command("discover"))
    started = time.monotonic()
    alice.stop()
    assert time.monotonic() - started < 1.5, "Discovery prevented quit"
    bob.stop()


def test_available(root, chats):
    alice = Chat(root / "alice")
    bob = Chat(root / "bob")
    carol = Chat(root / "carol")
    chats += [alice, bob, carol]
    found = []
    for _ in range(3):
        found, failures = discovery_result(alice, alice.command("discover"))
        assert not failures, failures
        if all(any(entry[1].endswith(f":{chat.port}") for entry in found) for chat in (bob, carol)):
            break
    assert all(any(entry[1].endswith(f":{chat.port}") for entry in found) for chat in (bob, carol)), found
    assert not any(entry[1].endswith(f":{alice.port}") for entry in found), "Discovery returned its own service"
    assert len(found) == len(set(found)), "Discovery returned duplicate services"
    for chat in (bob, carol):
        assert sum(entry[1].endswith(f":{chat.port}") for entry in found) == 1, "Service addresses were not grouped"
    assert [entry[0] for entry in found] == list(range(1, len(found) + 1)), "Peer numbers are not consecutive"
    assert not alice.saved_peers() and not bob.saved_peers(), "Discovery saved peer trust"

    # Адрес из объявления используется для настоящего подключения и обмена сообщениями.
    entry = next(entry for entry in found if entry[1].endswith(f":{bob.port}"))
    detail_mark = alice.command(f"discover {entry[0]}")
    alice.wait(f"Addresses for peer [{entry[0]}]:", detail_mark)
    alice.wait("Available commands:", alice.command("help"))
    lines = alice.lines[detail_mark:]
    start = lines.index(f"Addresses for peer [{entry[0]}]:") + 1
    addresses = lines[start:lines.index("Available commands:")]
    assert len(addresses) == 1 + entry[2] and len(addresses) == len(set(addresses)), addresses
    assert entry[1] in addresses and all(endpoint.endswith(f":{bob.port}") for endpoint in addresses), addresses
    receiver_mark = bob.mark()
    marks = alice.command(f"connect {entry[0]}"), receiver_mark
    alice.wait("Trust this peer?", marks[0])
    bob.wait("Trust this peer?", marks[1])
    alice.command("yes")
    bob.command("yes")
    finish_connection(alice, bob, marks)
    mark = alice.command("discover")
    started = time.monotonic()
    alice.wait("Available commands:", alice.command("help"))
    message(alice, bob, "chat stays responsive during discovery")
    assert time.monotonic() - started < 1.5, "Discovery blocked active chat"
    found, failures = discovery_result(alice, mark)
    assert not failures and any(entry[1].endswith(f":{bob.port}") for entry in found), (found, failures)

    # Завершение процесса снимает объявление, сохраняя другие записи в списке.
    carol.stop()
    found, failures = discovery_result(alice, alice.command("discover"))
    assert not failures and not any(entry[1].endswith(f":{carol.port}") for entry in found), (found, failures)
    assert any(entry[1].endswith(f":{bob.port}") for entry in found), found

    # Разные объявления с одинаковым портом остаются отдельными пирами.
    publisher = shutil.which("avahi-publish-service")
    if publisher:
        advertised_port = bob.port
        publishers = [subprocess.Popen(
            [publisher, f"{root.name}-service-{index}", "_p2p-chat._tcp", str(advertised_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        ) for index in range(2)]
        try:
            for _ in range(3):
                found, failures = discovery_result(alice, alice.command("discover"))
                assert not failures, failures
                assert all(process.poll() is None for process in publishers), "Service announcement failed"
                if sum(entry[1].endswith(f":{advertised_port}") for entry in found) == 3:
                    break
            assert sum(entry[1].endswith(f":{advertised_port}") for entry in found) == 3, found
        finally:
            for process in publishers:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()
    alice.command("discover")
    started = time.monotonic()
    alice.stop()
    assert time.monotonic() - started < 1.5, "Discovery prevented quit"
    bob.stop()


def run():
    mode = sys.argv[2]
    if mode == "available":
        daemon = shutil.which("avahi-daemon")
        if not daemon or subprocess.run([daemon, "--check"], capture_output=True, timeout=5).returncode != 0:
            print("Проверка mDNS пропущена: служба Avahi не запущена")
            return 77
    chats = []
    with tempfile.TemporaryDirectory(prefix="p2p-discovery-") as temporary:
        try:
            if mode == "available":
                test_available(Path(temporary), chats)
            elif mode == "unavailable":
                test_unavailable(Path(temporary), chats)
            else:
                raise ValueError("Неизвестный набор проверок обнаружения")
            print("Проверки обнаружения пиров и отзывчивости CLI пройдены")
        finally:
            for chat in chats:
                chat.stop()
    return 0


if __name__ == "__main__":
    sys.exit(run())

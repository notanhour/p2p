"""Test the CLI, persistent identities, and peer trust using real chat processes."""
import json
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

BINARY = str(Path(sys.argv[1]).resolve())
DEFAULT_PORT = 42000


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_line(sock):
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError("Socket closed before a complete frame")
        data.extend(chunk)
    return bytes(data)


class Chat:
    def __init__(self, directory, port=None, environment=None, extra_args=(), use_default_port=False):
        self.port = DEFAULT_PORT if use_default_port else port or free_port()
        self.directory = Path(directory) if directory is not None else None
        self.lines = []
        self.condition = threading.Condition()
        arguments = [BINARY, *extra_args]
        if not use_default_port:
            arguments += ["--port", str(self.port)]
        if directory is not None:
            arguments += ["--data-dir", str(directory)]
        self.process = subprocess.Popen(
            arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1, env=environment,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.wait("p2p · ")
        self.wait("Type 'help' for commands.")
        assert not any("SHA-256:" in line for line in self.lines), "Startup printed the fingerprint"
        info_mark = self.command("info")
        self.wait(f"Port: {self.port}", info_mark)
        self.fingerprint = self.wait("SHA-256: ", info_mark).split()[-1]
        assert len(self.fingerprint) == 64

    def _read(self):
        line = ""
        while character := self.process.stdout.read(1):
            line += character
            # Приглашение ввода завершается пробелом и доступно без перевода строки.
            if character == "\n" or (line.startswith("Trust this peer?") and line.endswith(": ")):
                with self.condition:
                    self.lines.append(line.rstrip())
                    self.condition.notify_all()
                line = ""
        if line:
            with self.condition:
                self.lines.append(line.rstrip())
                self.condition.notify_all()

    def mark(self):
        with self.condition:
            return len(self.lines)

    def command(self, text):
        mark = self.mark()
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()
        return mark

    def wait(self, text, start=0, timeout=10):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for line in self.lines[start:]:
                    if text in line:
                        return line
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"Missing {text!r} on port {self.port}: {self.lines}")
                self.condition.wait(min(0.1, deadline - time.monotonic()))

    def trust(self, peer):
        self.wait("Trusted peer fingerprint updated.", self.command(
            f"trust localhost:{peer.port} {peer.fingerprint.upper()}"))

    def saved_peers(self):
        path = self.directory / "known_peers"
        return dict(line.split() for line in path.read_text().splitlines()) if path.exists() else {}

    def stop(self):
        if self.process.poll() is None:
            try:
                self.command("quit")
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
                self.process.wait()
                raise
        self.reader.join(timeout=2)
        if self.process.returncode != 0:
            raise RuntimeError(f"Process exited with {self.process.returncode}: {self.lines}")


def start_connection(sender, receiver):
    receiver_mark = receiver.mark()
    sender_mark = sender.command(f"connect 127.0.0.1:{receiver.port}")
    return sender_mark, receiver_mark


def finish_connection(sender, receiver, marks):
    sender.wait("Connected to ", marks[0])
    receiver.wait("Connected to ", marks[1])


def connect(sender, receiver):
    marks = start_connection(sender, receiver)
    finish_connection(sender, receiver, marks)
    assert not any("Trust this peer?" in line for line in sender.lines[marks[0]:])
    assert not any("Trust this peer?" in line for line in receiver.lines[marks[1]:])


def message(sender, receiver, text):
    mark = receiver.mark()
    sender_mark = sender.command("send " + text)
    sender.wait("You: " + text, sender_mark)
    receiver.wait(": " + text, mark)


def disconnect(sender, receiver):
    mark = receiver.mark()
    sender.command("disconnect")
    receiver.wait(" disconnected", mark)
    # Следующая команда CLI подтверждает завершение корутины отключения.
    sender.wait("Available commands:", sender.command("help"))


def test_default_options(root, chats):
    environment = dict(os.environ, HOME=str(root / "home"))
    chat = Chat(None, environment=environment, use_default_port=True)
    chats.append(chat)
    assert (root / "home" / ".config" / "p2p" / "identity.pem").exists()
    with socket.create_connection(("127.0.0.1", DEFAULT_PORT), timeout=3) as probe:
        probe.settimeout(3)
        probe.sendall(b"PING\n")
        assert read_line(probe) == b"PONG\n", "Default TCP port did not accept connections"

    # Порт собеседника по умолчанию не зависит от порта собственного процесса.
    client = Chat(root / "default-port-client")
    chats.append(client)
    assert client.port != DEFAULT_PORT
    receiver_mark = chat.mark()
    marks = client.command("connect localhost"), receiver_mark
    client.wait("Trust this peer?", marks[0])
    chat.wait("Trust this peer?", marks[1])
    client.command("yes")
    chat.command("yes")
    finish_connection(client, chat, marks)
    message(client, chat, "connected to the default port")
    assert client.saved_peers()[f"127.0.0.1:{DEFAULT_PORT}"] == chat.fingerprint
    disconnect(client, chat)
    receiver_mark = chat.mark()
    marks = client.command("connect 127.0.0.1"), receiver_mark
    finish_connection(client, chat, marks)
    assert not any("Trust this peer?" in line for line in client.lines[marks[0]:])
    message(chat, client, "reconnected with a numeric address")
    client.stop()
    chat.stop()


def test_endpoint_commands(root, chats):
    chat = Chat(root / "addresses")
    chats.append(chat)
    help_mark = chat.command("help")
    chat.wait("connect <host[:port]>", help_mark)
    chat.wait("trust <address[:port]> <fingerprint>", help_mark)
    chat.wait("info —", help_mark)
    chat.wait("quit —", help_mark)
    chat.wait("No peer with this number", chat.command("connect 1"))
    chat.wait("No peer with this number", chat.command("discover 1"))
    for command in ("send", "send "):
        chat.wait("Usage: send <message>", chat.command(command))
    mark = chat.command("send not connected")
    chat.wait("No peer connected.", mark)
    chat.wait("Available commands:", chat.command("help"))
    assert not any("You: not connected" in line for line in chat.lines[mark:])
    for endpoint in ("localhost:", "localhost:0", "localhost:65536", "localhost:-1",
                     "localhost:80x", "::1:8080", "[::1]8080", "[localhost]:8080"):
        chat.wait("Expected host", chat.command(f"connect {endpoint}"))
        chat.wait("Expected host", chat.command(f"trust {endpoint} {chat.fingerprint}"))
    for command, usage in (("connect", "Usage: connect"), ("connect localhost:8080 extra", "Usage: connect"),
                           ("trust localhost:8080", "Usage: trust"),
                           (f"trust localhost:8080 {chat.fingerprint} extra", "Usage: trust")):
        chat.wait(usage, chat.command(command))
    assert not chat.saved_peers()
    for address, endpoint in (("localhost", f"127.0.0.1:{DEFAULT_PORT}"),
                              ("127.0.0.1", f"127.0.0.1:{DEFAULT_PORT}"),
                              ("[0:0:0:0:0:0:0:1]", f"[::1]:{DEFAULT_PORT}")):
        chat.wait("Trusted peer fingerprint updated.", chat.command(f"trust {address} {chat.fingerprint}"))
        assert chat.saved_peers()[endpoint] == chat.fingerprint
    chat.wait("Trusted peer fingerprint updated.", chat.command(f"trust [0:0:0:0:0:0:0:1]:8080 {chat.fingerprint}"))
    assert chat.saved_peers()["[::1]:8080"] == chat.fingerprint
    chat.wait("Trusted peer fingerprint updated.", chat.command(f"trust localhost:8080 {chat.fingerprint}"))
    assert chat.saved_peers() == {endpoint: chat.fingerprint for endpoint in (
        f"127.0.0.1:{DEFAULT_PORT}", f"[::1]:{DEFAULT_PORT}", "[::1]:8080", "127.0.0.1:8080")}
    chat.stop()


def test_quit_during_confirmation(root, chats):
    sender = Chat(root / "pending-sender")
    receiver = Chat(root / "pending-receiver")
    chats += [sender, receiver]
    marks = start_connection(sender, receiver)
    sender.wait("Trust this peer?", marks[0])
    receiver.wait("Trust this peer?", marks[1])
    started = time.monotonic()
    sender.stop()
    receiver.stop()
    assert time.monotonic() - started < 3, "Confirmation prevented quit"
    assert not sender.saved_peers() and not receiver.saved_peers()


def run():
    locale_env = dict(os.environ, LC_ALL="locale-that-does-not-exist")
    help_result = subprocess.run([BINARY, "--help"], env=locale_env, capture_output=True, text=True, timeout=10)
    assert help_result.returncode == 0, help_result.stderr
    assert "peer-fingerprint" in help_result.stdout and "data-dir" in help_result.stdout
    assert str(DEFAULT_PORT) in help_result.stdout, "Help does not show the default port"
    chats = []
    with tempfile.TemporaryDirectory(prefix="p2p-cli-") as temporary:
        root = Path(temporary)
        try:
            alice = Chat(root / "alice")
            bob = Chat(root / "bob")
            chats += [alice, bob]

            # Проверяем отклонение некорректных первых кадров до установки сессии.
            for payload in (b"", b"not-a-key\n", b"bm90LWEta2V5\n", b"\n", b"AA==\n",
                            b'{"port":0,"public_key":"AA=="}\n'):
                with socket.create_connection(("127.0.0.1", alice.port), timeout=3) as probe:
                    if payload:
                        probe.sendall(payload)
                        assert probe.recv(1) == b"", "Malformed handshake was accepted"

            # Проверяем отказ каждой стороны и отсутствие сохраненного доверия.
            for sender_trusted, receiver_trusted in ((True, False), (False, True), (False, False)):
                marks = start_connection(alice, bob)
                alice.wait("Trust this peer?", marks[0])
                bob.wait("Trust this peer?", marks[1])
                alice.command("yes" if sender_trusted else "no")
                bob.command("yes" if receiver_trusted else "no")
                for chat, mark, trusted, prefix in (
                        (alice, marks[0], sender_trusted, "Connection failed:"),
                        (bob, marks[1], receiver_trusted, "Incoming connection failed:")):
                    expected = f"{prefix} Peer declined the connection" if trusted else "Peer trust declined."
                    chat.wait(expected, mark)
                    chat.wait("Available commands:", chat.command("help"))
                    output = chat.lines[mark:]
                    assert sum(line.startswith(prefix) for line in output) == int(trusted)
                    assert not any("Connection failed." == line or "End of file" in line or
                                   "asio.misc" in line or " in function " in line for line in output)
                assert not alice.saved_peers() and not bob.saved_peers()

            # Подтверждение доступно в обоих CLI и может занять больше времени, чем обмен ключами.
            marks = start_connection(alice, bob)
            alice.wait("Trust this peer?", marks[0])
            bob.wait("Trust this peer?", marks[1])
            assert not alice.saved_peers() and not bob.saved_peers()
            alice.command("yes")
            time.sleep(5.2)
            bob.command("yes")
            finish_connection(alice, bob, marks)
            assert alice.saved_peers()[f"127.0.0.1:{bob.port}"] == bob.fingerprint
            assert bob.saved_peers()[f"127.0.0.1:{alice.port}"] == alice.fingerprint
            message(alice, bob, "first message")

            # Проверяем сохранение активного чата при закрытии временных соединений.
            for payload in (b"", b"not-a-key\n", b"A" * 65536):
                with socket.create_connection(("127.0.0.1", alice.port), timeout=3) as probe:
                    if payload:
                        probe.sendall(payload)
                        probe.recv(1024)
            message(bob, alice, "chat survived probes")
            disconnect(alice, bob)
            connect(bob, alice)
            message(bob, alice, "reconnected in reverse direction")
            disconnect(bob, alice)

            # Оба процесса загружают тот же ключ и доверяют собеседнику после перезапуска.
            fingerprints = alice.fingerprint, bob.fingerprint
            ports = alice.port, bob.port
            alice.stop()
            bob.stop()
            alice = Chat(root / "alice", ports[0])
            bob = Chat(root / "bob", ports[1])
            chats += [alice, bob]
            assert (alice.fingerprint, bob.fingerprint) == fingerprints
            connect(alice, bob)
            message(alice, bob, "trust survives both restarts")
            disconnect(alice, bob)

            # Изменившийся ключ отклоняется до явного обновления записи пользователем.
            bob.stop()
            (root / "bob" / "identity.pem").unlink()
            bob = Chat(root / "bob", ports[1])
            chats.append(bob)
            assert bob.fingerprint != fingerprints[1]
            marks = start_connection(alice, bob)
            alice.wait("Peer key changed", marks[0])
            bob.wait("Incoming connection failed:", marks[1])
            assert not any("Trust this peer?" in line for line in alice.lines[marks[0]:])
            assert alice.saved_peers()[f"127.0.0.1:{bob.port}"] == fingerprints[1]
            alice.trust(bob)
            connect(alice, bob)
            disconnect(alice, bob)

            # Та же проверка действует для входящего соединения с известным адресом и портом.
            alice.stop()
            (root / "alice" / "identity.pem").unlink()
            alice = Chat(root / "alice", ports[0])
            chats.append(alice)
            marks = start_connection(alice, bob)
            bob.wait("Peer key changed", marks[1])
            alice.wait("Connection failed:", marks[0])
            assert bob.saved_peers()[f"127.0.0.1:{alice.port}"] == fingerprints[0]
            bob.trust(alice)
            connect(alice, bob)
            disconnect(alice, bob)

            # Проверяем резервирование исходящего соединения во время ожидания ответа сервиса.
            with socket.socket() as stalled_service:
                stalled_service.bind(("127.0.0.1", 0))
                stalled_service.listen()
                stalled_service.settimeout(3)
                start_time = time.monotonic()
                mark = alice.command(f"connect localhost:{stalled_service.getsockname()[1]}")
                stalled, _ = stalled_service.accept()
                with stalled:
                    stalled.settimeout(3)
                    alice_hello = read_line(stalled)
                    bob.wait("Already connected to a peer.", bob.command(f"connect localhost:{alice.port}"))
                    alice.wait("handshake timed out", mark, timeout=8)
                    assert time.monotonic() - start_time < 8
            connect(bob, alice)
            message(alice, bob, "chat works after outgoing timeout")
            disconnect(bob, alice)

            # Проверяем тайм-аут обмена секретами после подтверждения доверенного ключа.
            with socket.create_connection(("127.0.0.1", bob.port), timeout=3) as stalled:
                stalled.settimeout(8)
                stalled.sendall(alice_hello)
                assert json.loads(read_line(stalled))["public_key"]
                stalled.sendall(b"READY\n")
                assert read_line(stalled) == b"READY\n"
                assert stalled.recv(1) == b"", "Incoming handshake did not time out"
            connect(alice, bob)
            message(bob, alice, "chat works after incoming timeout")

            # Проверяем завершение работы при ожидании данных в активном и временных соединениях.
            probes = [socket.create_connection(("127.0.0.1", alice.port), timeout=3) for _ in range(5)]
            try:
                alice.stop()
            finally:
                for probe in probes:
                    probe.close()
            bob.stop()
            test_endpoint_commands(root, chats)
            test_quit_during_confirmation(root, chats)
            print("Проверки CLI, постоянных ключей, доверия, подключений, тайм-аутов и завершения работы пройдены")
        finally:
            for chat in chats:
                chat.stop()


def run_default_port():
    # Фиксированный порт проверяется отдельно, поскольку его может занимать пользовательский процесс.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("0.0.0.0", DEFAULT_PORT))
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
            print(f"Проверка порта по умолчанию пропущена: порт {DEFAULT_PORT} занят")
            return 77
    chats = []
    with tempfile.TemporaryDirectory(prefix="p2p-default-port-") as temporary:
        try:
            test_default_options(Path(temporary), chats)
        finally:
            for chat in chats:
                chat.stop()
    print("Проверки порта по умолчанию и каталога профиля пройдены")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[2] == "default-port":
        sys.exit(run_default_port())
    run()

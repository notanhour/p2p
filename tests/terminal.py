"""Test terminal editing, asynchronous chat output, and terminal restoration."""
import codecs
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

from chat_cli import BINARY, Chat, free_port

SGR = re.compile(r"\x1b\[[0-9;]*m")
INCOMPLETE_ESCAPE = re.compile(r"\x1b(?:\[[0-9;]*)?$")


class TerminalChat:
    def __init__(self, directory, environment=None):
        self.port = free_port()
        self.master, self.slave = pty.openpty()
        self.attributes = termios.tcgetattr(self.slave)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        self.condition = threading.Condition()
        self.output = ""
        self.raw_output = ""
        settings = dict(os.environ, TERM="xterm-256color")
        settings.pop("NO_COLOR", None)
        if environment:
            settings.update(environment)
        self.process = subprocess.Popen(
            [BINARY, "--port", str(self.port), "--data-dir", str(directory)],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env=settings,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.wait("> ")
        assert "SHA-256:" not in self.output, "Startup displayed the fingerprint"

    def _read(self):
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            try:
                ready, _, _ = select.select([self.master], [], [], 0.1)
                if not ready:
                    if self.process.poll() is not None:
                        return
                    continue
                data = os.read(self.master, 65536)
                if not data:
                    return
                with self.condition:
                    self.raw_output += decoder.decode(data)
                    # Цвет убирается из текста проверок, движения курсора остаются видимыми.
                    complete = INCOMPLETE_ESCAPE.sub("", self.raw_output)
                    self.output = SGR.sub("", complete)
                    self.condition.notify_all()
            except OSError:
                return

    def mark(self):
        with self.condition:
            return len(self.output)

    def send(self, text):
        mark = self.mark()
        os.write(self.master, text.encode())
        return mark

    def command(self, text):
        return self.send(text + "\r")

    def resize(self, columns):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, columns, 0, 0))

    def wait(self, text, mark=0, timeout=10, raw=False):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                output = self.raw_output if raw else self.output
                if text in output[mark:]:
                    return output[mark:]
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"Missing {text!r}: {output[mark:]!r}")
                self.condition.wait(0.1)

    def stop(self, termination="quit"):
        if self.process.poll() is None:
            if termination == "signal":
                self.process.send_signal(signal.SIGINT)
            elif termination == "eof":
                self.send("\x04")
            else:
                self.command("quit")
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise
        self.reader.join(timeout=1)
        assert self.process.returncode == 0, self.output
        assert termios.tcgetattr(self.slave) == self.attributes, "Terminal settings were not restored"
        os.close(self.master)
        os.close(self.slave)


def run():
    with tempfile.TemporaryDirectory(prefix="p2p-terminal-") as temporary:
        root = Path(temporary)
        alice = TerminalChat(root / "alice")
        bob = Chat(root / "bob")
        try:
            alice.wait("\x1b[38;5;110mp2p · ", raw=True)
            alice.wait("\x1b[38;5;110m> \x1b[0m", raw=True)
            # Полный отпечаток доступен в сведениях о профиле, а не в стартовом выводе.
            alice.wait("SHA-256: ", alice.command("info"))
            # Вопрос доверия сохраняет незавершенную команду и получает отдельный ввод ответа.
            mark = alice.send("info")
            alice.wait("> info", mark)
            mark = alice.mark()
            receiver_mark = bob.command(f"connect localhost:{alice.port}")
            alice.wait("Trust this peer? Type 'yes' or 'no': ", mark)
            bob.wait("Trust this peer?", receiver_mark)
            mark = alice.command("no")
            bob.command("no")
            alice.wait("Peer trust declined.", mark)
            alice.wait("\r\x1b[2K> info\r", mark)
            bob.wait("Peer trust declined.", receiver_mark)
            alice.wait("SHA-256: ", alice.send("\r"))

            receiver_mark = bob.mark()
            mark = alice.command(f"connect localhost:{bob.port}")
            alice.wait("Trust this peer? Type 'yes' or 'no': ", mark)
            bob.wait("Trust this peer?", receiver_mark)
            question = alice.output[mark:]
            assert "You have 60 seconds to answer.\r\n" in question
            assert "SHA-256: " + bob.fingerprint in question
            alice.wait("\x1b[38;5;186mTrust this peer? Type 'yes' or 'no': \x1b[0m", raw=True)
            mark = alice.command("yes")
            alice.wait("Trust this peer? Type 'yes' or 'no': yes\r\n", mark)
            bob.command("yes")
            alice.wait("Connected to ", mark)
            bob.wait("Connected to ", receiver_mark)
            alice.wait("\x1b[38;5;114m\r\nConnected to ", raw=True)
            assert "\x1b[38;5;114m\r\n\r\nConnected to " not in alice.raw_output
            connected_line = bob.wait("Connected to ", receiver_mark)
            connected_index = bob.lines.index(connected_line, receiver_mark)
            assert bob.lines[connected_index - 1] == "", bob.lines[receiver_mark:]
            assert bob.lines[connected_index - 2] != "", bob.lines[receiver_mark:]
            peer_name = next(line.removeprefix("Name: ") for line in bob.lines if line.startswith("Name: "))
            connection = f"Connected to {peer_name} · 127.0.0.1:{bob.port}"
            alice.wait(connection + "\r\n", mark)
            assert connection + "\r\n\r\n" not in alice.output[mark:]

            # Входящее сообщение восстанавливает черновик и положение курсора внутри текста.
            draft = "send привет"
            mark = alice.send(draft + "\x1b[D")
            alice.wait("> " + draft, mark)
            mark = alice.mark()
            bob.command("send incoming while typing")
            alice.wait(": incoming while typing\r\n", mark)
            assert re.search(r"\x1b\[38;5;110m[^\x1b\r\n]+:\x1b\[0m incoming while typing\r\n", alice.raw_output)
            alice.wait("\r\x1b[2K> " + draft + "\r\x1b[12C", mark)
            receiver_mark = bob.mark()
            mark = alice.send("-\x1b[C\r")
            alice.wait("You: приве-т\r\n", mark)
            bob.wait(": приве-т", receiver_mark)

            # Удаление символа UTF-8 и история команд сохраняют корректный текст.
            receiver_mark = bob.mark()
            mark = alice.send("send привет\x7f!\r")
            alice.wait("You: приве!\r\n", mark)
            bob.wait(": приве!", receiver_mark)
            receiver_mark = bob.mark()
            mark = alice.send("\x1b[A\r")
            alice.wait("You: приве!\r\n", mark)
            bob.wait(": приве!", receiver_mark)

            # Длинная строка прокручивается, не теряя текст при асинхронном выводе.
            text = "длинное сообщение " * 20 + "КОНЕЦ"
            mark = alice.send("send " + text)
            alice.wait("КОНЕЦ", mark)
            mark = alice.mark()
            bob.command("send another incoming message")
            alice.wait(": another incoming message\r\n", mark)
            receiver_mark = bob.mark()
            mark = alice.send("\r")
            alice.wait("You: длинное сообщение", mark)
            wrapped = alice.wait("КОНЕЦ\r\n", mark)
            assert "\r\n     длинное" in wrapped, wrapped
            bob.wait(": " + text, receiver_mark)

            # Строка отправки очищается, в выводе остается только собственное сообщение.
            mark = alice.send("send wow")
            alice.wait("> send wow", mark)
            mark = alice.send("\r")
            output = alice.wait("You: wow\r\n", mark)
            assert "> send wow\r\n" not in output, output
            assert "\r\x1b[2KYou: wow\r\n" in output, output
            assert "\x1b[38;5;183mYou:\x1b[0m wow\r\n" in alice.raw_output

            # Переносы вводятся через Ctrl+J и Alt+Enter, а входящий текст сохраняет все строки черновика.
            mark = alice.send("send first\nsecond\x1b\rthird")
            alice.wait("  third\r", mark)
            assert "You: first" not in alice.output[mark:]
            mark = alice.mark()
            bob.command("send incoming during multiline input")
            alice.wait(": incoming during multiline input\r\n", mark)
            restored = alice.wait("  third\r", mark)
            assert "> send first\r\n" in restored
            assert "  second\r\n" in restored
            mark = alice.send("\x1b[A\x05!\x1b[B")
            edited = alice.wait("  third\r\x1b[7C", mark)
            assert "  second!" in edited, edited
            receiver_mark = bob.mark()
            mark = alice.send("\r")
            output = alice.wait("You: first\r\n     second!\r\n     third\r\n", mark)
            assert "> send first\r\n" not in output, output
            bob.wait(": first", receiver_mark)
            bob.wait("second!", receiver_mark)
            bob.wait("third", receiver_mark)

            # Пустые строки и переносы сохраняются при удалении разделителя и вводе Shift+Enter.
            receiver_mark = bob.mark()
            mark = alice.send("send один\nдва\x01\x7f\x05\x1b[13;2u\nтри\r")
            alice.wait("You: одиндва\r\n\r\n     три\r\n", mark)
            bob.wait(": одиндва", receiver_mark)
            bob.wait("три", receiver_mark)

            # Высота черновика ограничена экраном, сообщение содержит все строки.
            lines = [f"row {index}" for index in range(30)]
            receiver_mark = bob.mark()
            mark = alice.send("send " + "\n".join(lines) + "\r")
            alice.wait("You: " + "\r\n     ".join(lines) + "\r\n", mark)
            bob.wait(": row 0", receiver_mark)
            bob.wait("row 29", receiver_mark)

            # Перенос по словам учитывает ширину окна, отступ продолжений и набираемый черновик.
            alice.resize(40)
            label = next(line.removeprefix("Name: ") for line in bob.lines if line.startswith("Name: ")) + ": "
            incoming = "word " * 12 + "END"
            mark = alice.send("send draft")
            alice.wait("> send draft", mark)
            mark = alice.mark()
            bob.command("send " + incoming)
            output = alice.wait("END\r\n", mark)
            start = output.index(label)
            end = output.index("END\r\n", start) + 3
            displayed = output[start:end].split("\r\n")
            assert len(displayed) > 1, displayed
            assert all(len(line) <= 39 for line in displayed), displayed
            assert all(line.startswith(" " * len(label)) for line in displayed[1:]), displayed
            assert " ".join([displayed[0][len(label):], *[line[len(label):] for line in displayed[1:]]]) == incoming
            alice.wait("\r\x1b[2K> send draft\r\x1b[12C", mark)
            receiver_mark = bob.mark()
            message = "one two three four five six seven eight nine ten"
            mark = alice.send("\x15send " + message + "\r")
            alice.wait("You: one two three four five six seven\r\n     eight nine ten\r\n", mark)
            bob.wait(": " + message, receiver_mark)

            # Широкие символы переносятся без разрезания UTF-8 и без изменения передаваемого текста.
            message = "界" * 20 + " конец"
            receiver_mark = bob.mark()
            mark = alice.command("send " + message)
            alice.wait("You: " + "界" * 17 + "\r\n     " + "界" * 3 + " конец\r\n", mark)
            bob.wait(": " + message, receiver_mark)
            alice.resize(80)

            # Управляющие последовательности из сообщения не управляют экраном терминала.
            mark = alice.mark()
            bob.command("send escape \x1b[2J text")
            alice.wait(": escape [2J text\r\n", mark)
            assert "\x1b[2J" not in alice.output[mark:]

            # Ошибка отправки сохраняет команду вместе с пояснением.
            mark = alice.command("disconnect")
            alice.wait("Disconnected from ", mark)
            alice.wait("\x1b[38;5;186mDisconnected from ", raw=True)
            assert "\x1b[38;5;186m\r\nDisconnected from " not in alice.raw_output
            mark = alice.command("send unsent")
            output = alice.wait("No peer connected.", mark)
            assert "> send unsent\r\n" in output, output
            assert "You: unsent" not in output, output
            alice.wait("Error: No peer is awaiting confirmation", alice.command("yes"))
            alice.wait("\x1b[38;5;167mError: No peer is awaiting confirmation\x1b[0m", raw=True)
            # Перенаправленный вывод содержит текст без цветовых последовательностей.
            assert not any(SGR.search(line) for line in bob.lines), bob.lines
        finally:
            alice.stop()
            bob.stop()

        # Выход, конец ввода и сигнал возвращают настройки терминала.
        for termination in ("eof", "signal"):
            chat = TerminalChat(root / termination)
            chat.stop(termination)

        # Цвет отключается по настройке пользователя и для простого терминала.
        for label, environment in (("no-color", {"NO_COLOR": "1"}), ("dumb", {"TERM": "dumb"})):
            chat = TerminalChat(root / label, environment)
            try:
                chat.wait("No peer connected.", chat.command("send unsent"))
                chat.wait("Error: No peer is awaiting confirmation", chat.command("yes"))
                assert not SGR.search(chat.raw_output), chat.raw_output
            finally:
                chat.stop()
    print("Проверки терминального ввода, черновиков, вывода сообщений и завершения работы пройдены")


if __name__ == "__main__":
    run()

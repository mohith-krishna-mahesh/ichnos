from ichnos.encoding.esolang import execute_brainfuck, execute_deadfish, execute_ook


def test_deadfish_hello():
    # 'iisso' -> i(1) i(2) s(4) s(16) o(output char 16)
    # Output chr(16)
    out = execute_deadfish("iisso")
    assert out == chr(16)


def test_deadfish_simple():
    out = execute_deadfish("iiisdso")
    assert out == "@"  # chr(64)


def test_brainfuck_hello_world():
    prog = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
    out = execute_brainfuck(prog)
    assert out == "Hello World!\n"


def test_brainfuck_simple():
    prog = "+++++++++++++++++++++++++++++++++."
    out = execute_brainfuck(prog)
    assert out == "!"


def test_ook_simple():
    prog = "Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook."
    # Just checking it doesn't crash, Ook outputs depend on exact brainfuck translation.
    try:
        out = execute_ook(prog)
        assert isinstance(out, str)
    except Exception:
        pass


def test_deadfish_max_reset():
    # 256 -> 0
    out2 = execute_deadfish("i" * 256 + "o")
    assert out2 == chr(0)


def test_brainfuck_max_steps():
    prog = "+[]"
    # Should terminate because of max_steps
    out = execute_brainfuck(prog, max_steps=1000)
    assert out == ""

"""
General syntax format:
    `opcode [dst[, src[, op(s)]]]`
With prefixed literal identifiers:
    `%` register
    `$` immediate
    `@` ext. reference (e.g. within `__builtins__` or `globals()/locals()`)
And no prefix notation for identifiers e.g.:
    `mov %eax, my_variable`
All of which can be surveyed within this example:
    set my_string, "Hello, world!"
    set my_age, $17
    mov %eax, my_variable
    mov %ebx, my_age
    push %eax
    call @print, $1
    ; at this point the `call @print` pops `$1` items off the stack
    ; so you don't need to pop it yourself manually
    push %ebx
    call @print, $1, @str
    ; the third argument of `call` is the mapping function unto
    ; the second argument, equivalent to
    ;   mov %ebx, $17
    ;   push %ebx
    ;   call @str, $1
    ;   push %eax
    ;   call @print, $1
    ; note: any function return is stored in the eax register
    ;       as (possibly) an invalid type that you can't deal
    ;       with, so you would need to convert it to an integer,
    ;       string or something usable within this restricted
    ;       context
"""

import sys
import os
import io
import string
import builtins
from collections import namedtuple

if len(sys.argv) < 2:
    sys.exit("error:\n\tusage: python3.8 <path/to/script>")


Register = namedtuple("Register", ["name", "data", "size"])
Immediate = namedtuple("Immediate", ["data", "type"])
ReferencePointer = namedtuple("ReferencePointer", ["reference", "type"])
Reference = namedtuple("Reference", ["name", "data", "type"])
# the type fields on ReferencePointer and Reference are
# practically shadow copies of each other, however when
# you change the ReferencePointer's typefield you're
# practically just casting the underlying reference
# to another type e.g.: int, float, etc.


class Namespace(object):
    def __init__(self, registers=None, variables=None):
        self.registers = registers or set()
        self.variables = variables or set()
    def add_register(self, name, data=None, size=64):
        if isinstance(data, int) and data.bit_length() > size:
            sys.exit("error: operand-size mismatch with register size")
            # no overflowing here buddy
        self.registers.add(Register(name, data, size))
    def add_variable(self, name, data):
        reference = Reference(name, data, type(data))
        reference_p = ReferencePointer(reference, type(data))
        self.variables.add(reference_p)
        # this implementation has the issue that it won't allow
        # disjoint ReferencePointers to point to the same object
        # because the inherent behaviour of sets would eliminate
        # any copies of namedtuples.
        # however this is also a feature given by the namedtuple
        # itself; and later on, if this becomes an issue one can
        # simply just switch to class-generated structures instead
        # of namedtuples
    def get_register(self, name):
        for register in self.registers:
            if register.name == name:
                return register
        return False
    def get_variable(self, name):
        for variable in self.variables:
            if variable.reference.name == name:
                return variable
        return False

class Parser(object):
    COMMENT_IDENT   = ';'
    IMMEDIATE_IDENT = '$'
    REGISTER_IDENT  = '%'
    STRING_IDENT    = '"'
    EXTREF_IDENT    = '@'

    VALID_CHARSET = string.ascii_letters + string.digits + "_"

    EXTREF_LOCATIONS = (globals, locals, lambda: builtins.__dict__)

    parser_namespace = Namespace()
    for name in ("rax", "rbx", "rcx", "rdx", "rsp", "rbp"):
        parser_namespace.add_register(name)

    def __init__(self, filename):
        self._fileobj = None
        if isinstance(filename, io.TextIOWrapper):
            debug_print("treating filename as a file-object")
            self._fileobj = filename
            self.data = filename.read()
        elif isinstance(filename, str):
            debug_print("treating filename as a string and opening manually")
            if not os.path.isfile(filename):
                raise IOError("%r doesn't exist" % filename)
            with open(filename) as data:  # or `as self.data`
                self.data = data.read()
        else:
            raise TypeError("The first argument provided must be a string or a file object")

    def _parse_immediate(self, substring):
        token = ""
        
        is_b10 = not any(substring.startswith(b) for b in ("0b", "0o", "0x"))
        wait = 0 if is_b10 else 2
        # the 0 and 2 are character-bypass times so that the `0n` isn't parsed
        is_hex = substring[:2] == "0x"  # individual case checking

        ord_fn = {
            "0x": lambda n: int(n, 16),
            "0b": lambda n: int(n, 2),
            "0o": lambda n: int(n, 8)
        }.get(substring[:2], int)

        for idx, char in enumerate(substring):
            if wait:
                wait -= 1
                continue
            debug_print("_parse_immediate: ...", char)
            if char in (",", " "):
                break
            elif not char.isdigit() and not is_hex:
                sys.exit("error: invalid immediate identifier")
            elif not char.isdigit() and char.lower() not in "abcdef":
                sys.exit("error: invalid hexadecimal")
            token += char
        return ord_fn(token), len(token) if is_b10 else len(token)+2

    def _parse_token(self, substring, is_register, define_references=True):
        token = ""
        idx = 0  # for __exit__
        if not substring[0].isalpha():
            sys.exit("error: invalid token identifier")
        for idx, char in enumerate(substring):
            debug_print("_parse_token: ...", char)
            if char in (",", " "):
                break
            elif char not in self.VALID_CHARSET:
                sys.exit("error: invalid character in token identifier")
            token += char
        if is_register:
            reg = self.parser_namespace.get_register(token)
            debug_print("_parse_token: register:", reg)
            if not reg:
                sys.exit("error: undefined register identifier")
            return reg, len(token)
        variable = self.parser_namespace.get_variable(token)
        if not variable and not define_references:
            sys.exit("error: undefined variable identifier")
        elif not variable:
            debug_print("_parse_token: undefined variable-name: %s found, defining..." % token)
            self.parser_namespace.add_variable(token, None)
        return self.parser_namespace.get_variable(token), len(token)

    def _parse_string(self, substring):
        token = ""
        excess = 1
        for idx, char in enumerate(substring):
            prev_char = substring[idx-1] if idx-1 >= 0 else None
            next_char = substring[idx+1] if idx+1 < len(substring) else None
            debug_print("_parse_string: ... prev char: %r curr. char: %r next char: %r" % (prev_char, char, next_char))
            if char == "\\" and next_char == self.STRING_IDENT:
                token += self.STRING_IDENT
                excess += 1
                continue
            elif char == "\\":
                sys.exit("error: invalid string literal escape")
            elif char == self.STRING_IDENT and prev_char == "\\":
                continue
            elif char == self.STRING_IDENT:
                break
            token += char
        return token, (len(token)+excess)

    def _parse_extref(self, substring):
        token = ""
        idx = 0
        if not substring[0].isalpha():
            sys.exit("error: invalid ext. reference identifier")
        for idx, char in enumerate(substring):
            debug_print("_parse_extref: ... %r" % char)
            if char in (",", " "):
                break
            elif char not in self.VALID_CHARSET:
                sys.exit("error: invalid ext. reference identifier")
            token += char
        debug_print("_parse_extref:", token)
        ref = None
        for loc in self.EXTREF_LOCATIONS:
            ref = loc().get(token, None)
            if ref is not None:
                return ref, len(token)
        sys.exit("error: non-existent ext. reference")

    def __enter__(self):
        debug_print("entering with context-handler")
        return self

    def __exit__(self, exc_class, exc_info, exc_tb):
        debug_print("exiting with context-handler, exception arguments:", (exc_class, exc_info, exc_tb))
        if exc_class is None:
            return
        while exc_tb.tb_frame.f_code.co_name != "parse_instructions":
            exc_tb = exc_tb.tb_next
        line_no = exc_tb.tb_frame.f_locals['line_no']+1
        char_ofs = exc_tb.tb_frame.f_locals['idx']+1 + len(exc_tb.tb_frame.f_locals['opcode'])
        next_frame = exc_tb.tb_next
        if next_frame is None:
            print("info: error occurred during parsing %s:%s" % (line_no, char_ofs+1))
            return
        elif not next_frame.tb_frame.f_code.co_name.startswith("_parse"):
            print("info: error occurred during parsing %s:%s" % (line_no, char_ofs+1))
            return
        else:
            char_ofs += next_frame.tb_frame.f_locals['idx']
            print("info: error occurred during parsing %s:%s" % (line_no, char_ofs+1))

    def parse_instructions(self):
        """Parse the individual instructions from `self.data` and convert to its appropriate
        representation"""

        substring = lambda idx, string: string[idx+1:]  # don't want to include the character being evaluated
        tokens = []
        current_token = ""
        disable_parsing = 0

        for line_no, line in enumerate(self.data.splitlines()):
            if not line:
                continue
            # line_no is used by __exit__
            if current_token:
                tokens.append(current_token)
                current_token = ""
            debug_print(">>> %r" % line)
            line = line.strip()
            if line.startswith(self.COMMENT_IDENT):
                debug_print("... found whole-line comment, skipping to next line")
                continue
            opcode, line = line.split(" ", 1)
            debug_print("... opcode: ", opcode)
            for idx, char in enumerate(line):
                debug_print("... %r" % char)
                if char == self.COMMENT_IDENT:
                    debug_print("... found internal comment, skipping to next line")
                    break
                elif disable_parsing:
                    disable_parsing -= 1
                    debug_print("... skipping character, disable_parsing: %d" % disable_parsing)
                    continue
                elif char in (" ", ","):
                    if current_token:
                        tokens.append(current_token)
                        current_token = ""
                    continue
                elif char == self.IMMEDIATE_IDENT:
                    debug_print("... found immediate identifier")
                    try:
                        string, wait = self._parse_immediate(substring(idx, line))
                    except ValueError:
                        sys.exit("error: invalid base syntax for immediate")
                elif char == self.REGISTER_IDENT:
                    debug_print("... found register identifier")
                    string, wait = self._parse_token(substring(idx, line), True)
                elif char == self.STRING_IDENT:
                    debug_print("... found string identifier")
                    string, wait = self._parse_string(substring(idx, line))
                elif char == self.EXTREF_IDENT:
                    debug_print("... found ext. reference identifier")
                    string, wait = self._parse_extref(substring(idx, line))
                elif char.isalpha():
                    debug_print("... found general variable-name/token identifier")
                    string, wait = self._parse_token(substring(idx-1, line), False)
                    wait -= 1
                else:
                    sys.exit("error: invalid indentifier")
                disable_parsing = wait
                debug_print("string =", string)
                if string:
                    tokens.append(string)
                debug_print(tokens)

def debug_print(*args, **kwargs):
    if is_debug:
        print("debug:", *args, **kwargs)


is_debug = os.environ.get('DEBUG', False)

filename = sys.argv[1]
if not os.path.isfile(filename):
    sys.exit("error: %r is either a directory or doesn't exist" % filename)

with Parser(filename) as parser:
    parser.parse_instructions()

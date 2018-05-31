import sys
import os
import io
import string
import builtins
from pprint import pprint
from collections import namedtuple

if len(sys.argv) < 2:
    sys.exit("error:\n\tusage: python3.8 <path/to/script>")


Register = namedtuple("Register", ["name", "data", "type", "size"])
Immediate = namedtuple("Immediate", ["data", "type"])
ReferencePointer = namedtuple("ReferencePointer", ["reference", "type"])
Reference = namedtuple("Reference", ["name", "data", "reference", "type"])
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
        self.registers.add(Register(name, data, type(data), size))
    def add_variable(self, name, data):
        debug_print("add_variable: name = %s data = %s" % (name, str(data)[:100]))
        reference = Reference(name, data, None, type(data))
        reference = reference._replace(reference=ReferencePointer(reference, type(data)))
        # one-layer circular reference pointing
        # so many fucking `reference`s
        self.variables.add(reference.reference)
        # this implementation has the issue that it won't allow
        # disjoint ReferencePointers to point to the same object
        # because the inherent behaviour of sets would eliminate
        # any copies of namedtuples.
        # however this is also a feature given by the namedtuple
        # itself; and later on, if this becomes an issue one can
        # simply just switch to class-generated structures instead
        # of namedtuples
    def set_variable(self, name, attr, newattr):
        debug_print("set_variable: name = %s attr = %s newattr = %s" % (name, attr, newattr))
        var_p = self.get_variable(name)
        reg = self.get_register(name)
        if reg:
            new_reg = reg._replace(**{attr: newattr})
            if attr == "data" and isinstance(newattr, int) and newattr.bit_length() > reg.size:
                sys.exit("error: operand-size mismatch with register size")
            new_reg = new_reg._replace(type=type(newattr))
            debug_print("set_register: from %s to %s" % (reg, new_reg))
            self.registers.remove(reg)
            self.registers.add(new_reg)
        elif var_p:
            var = var_p.reference
            new_var = var._replace(**{attr: newattr})
            new_var = new_var._replace(type=type(newattr))
            new_var_p = var_p._replace(type=type(newattr))
            new_var_p = new_var_p._replace(reference=new_var)
            # new_var = new_var._replace(reference=new_var_p) ; redundant?
            debug_print("set_variable: from %s to %s" % (var, new_var))
            self.variables.remove(var_p)
            self.variables.add(new_var_p)
        return True
    def get_register(self, name):
        for register in self.registers:
            debug_print("get_register: register.name = %s" % register.name)
            if register.name == name:
                return register
        return False
    def get_variable(self, name):
        for variable in self.variables:
            debug_print("get_variable: variable.name = %s" % variable.reference.name)
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

    opcode_function_map = {
        "mov": lambda self, op1, op2:
            self.parser_namespace.set_variable(op1.name, "data", op2.data),
        "call": lambda self, op1, op2=Immediate(0, int), op3=Reference(None, str, None, None):
            sys.exit("runtime error: #1 operand not callable in call")
            if not callable(op1.data) else
            sys.exit("runtime error: #2 operand not integer in call")
            if op2.type is not int else
            sys.exit("runtime error: #3 operand not callable in call")
            if not callable(op3.data) else
            op1.data(*[op3.data(item.data) for item in self.stack[:op2.data]]),
        "push": lambda self, op1:
            self.stack.insert(0, op1),
        "pop": lambda self, op1:
            (
                self.parser_namespace.set_variable(op1.name, "data", self.stack.pop()),
                self.parser_namespace.set_variable(op1.name, "type", type(op1.data)),
                self.parser_namespace.set_variable(op1.name, "reference", op1.reference._replace(type=type(op1.data)))
                if isinstance(op1, ReferencePointer) else None
            ),
        "inc": lambda self, op1:
            self.parser_namespace.set_variable(op1.name, "data", op1.data+1)
            if op1.type is int else
            sys.exit("runtime error: #1 operand not integer in inc"),
        "add": lambda self, op1, op2:
            self.parser_namespace.set_variable(op1.name, "data", op1.data+op2.data)
            if (op1.type is int and op2.type is int) or
               (op1.type is str and op2.type is str) else
            sys.exit("runtime error: #1/#2 operand types must be valid in add"),
        "breakpoint": lambda _:
            breakpoint()
    }

    opcode_operand_template = {
        (): ("breakpoint",),
        (Register,): ("call", "inc", "push", "pop"),
        (Reference,): ("call", "inc", "push", "pop"),
        (Immediate,): ("push",),

        (Register, Register): ("mov", "add"),
        (Register, Immediate): ("mov", "add"),
        (Register, Reference): ("mov", "add"),
        (Reference, Immediate): ("mov", "call", "add"),
        (Reference, Register): ("mov", "call", "add"),
        (Reference, Reference): ("mov", "call", "add"),  # typically mem <- mem operations aren't permissible
        
        (Reference, Register, Reference): ("call",),
        (Reference, Immediate, Reference): ("call",),
        (Reference, Reference, Reference): ("call",)
    }
    # a ReferencePointer is basically just a memory location
    
    parser_namespace = Namespace()
    for name in ("rax", "rbx", "rcx", "rdx", "rsp", "rbp"):
        parser_namespace.add_register(name)

    def __init__(self, filename):
        self._fileobj = None
        self.stack = []
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
        debug_print("_parse_token: variable = %s" % (variable,))
        if not variable and not define_references:
            sys.exit("error: undefined variable identifier")
        elif not variable:
            debug_print("_parse_token: undefined variable-name: %s found, defining..." % token)
            self.parser_namespace.add_variable(token, None)
        return self.parser_namespace.get_variable(token).reference, len(token)

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
        #print(token)
        for loc in self.EXTREF_LOCATIONS:
            ref = loc().get(token, None)
            if ref is not None:
                self.parser_namespace.add_variable("@%s" % token, ref)
                var = self.parser_namespace.get_variable("@%s" % token).reference
                debug_print("_parse_extref: var = %s" % (var,))
                return var, len(token)
        sys.exit("error: non-existent ext. reference")

    def __enter__(self):
        debug_print("entering with context-handler")
        return self

    def __exit__(self, exc_class, exc_info, exc_tb):
        debug_print("exiting with context-handler, exception arguments:", (exc_class, exc_info, exc_tb))
        if exc_class is None:
            return
        try:
            while exc_tb.tb_frame.f_code.co_name != "parse_instructions":
                exc_tb = exc_tb.tb_next
        except AttributeError:
            debug_print("attribute error on context-handler, cba handling this so just pass silently")
            return
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

    def parse_instructions(self, define_symbols=True):
        """Parse the individual instructions from `self.data` and convert to its appropriate
        representation"""

        substring = lambda idx, string: string[idx+1:]  # don't want to include the character being evaluated
        opcode_operand = []
        current_token = ""
        disable_parsing = 0

        for line_no, line in enumerate(self.data.splitlines()):
            tokens = []
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
            full_line = line.split(" ", 1)
            if len(full_line) == 1:
                opcode = full_line[0]
                opcode_operand.append([opcode])
                continue
            opcode, line = full_line

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
                        string = Immediate(string, int)
                    except ValueError:
                        sys.exit("error: invalid base syntax for immediate")
                elif char == self.REGISTER_IDENT:
                    debug_print("... found register identifier")
                    string, wait = self._parse_token(substring(idx, line), define_symbols)
                elif char == self.STRING_IDENT:
                    debug_print("... found string identifier")
                    string, wait = self._parse_string(substring(idx, line))
                    string = Immediate(string, str)
                elif char == self.EXTREF_IDENT:
                    debug_print("... found ext. reference identifier")
                    string, wait = self._parse_extref(substring(idx, line))
                elif char.isalpha():
                    debug_print("... found general variable-name/token identifier")
                    string, wait = self._parse_token(substring(idx-1, line), not define_symbols)
                    wait -= 1
                else:
                    sys.exit("error: invalid indentifier")
                disable_parsing = wait
                debug_print("string =", string)
                if string:
                    tokens.append(string)
                debug_print(tokens)
            opcode_operand.append([opcode, *tokens])
        return opcode_operand

    def verify_operands(self, instructions):
        new_opcodes = []
        for idx, instruction in enumerate(instructions):
            opcode, *operands = instruction
            debug_print("verify_operands: opcode = %s operands = %s" % (opcode, operands))
            if not any(opcode in v for v in self.opcode_operand_template.values()):
                sys.exit("error: no such opcode %r at instruction #%d" % (opcode, idx+1))
            templates = []
            for k, v in self.opcode_operand_template.items():
                if opcode in v:
                    templates.append(k)
            types = (*map(type, operands),)
            debug_print("verify_operands: types = %s" % (types,))
            debug_print("verify_operands: templates = %s" % (templates,))
            if types not in templates:
                sys.exit(("error: invalid operands for opcode %r at instruction #%d\n\t" % (opcode, idx+1)) + 
                         "expected %s\n\tgot %r" % ('\n\t\t '.join("%s %s" % (opcode, ', '.join("%s" % c for c in t)) for t in templates), types)
                        )
            new_opcodes.append([self.opcode_function_map[opcode], *operands])
        debug_print("verify_operands: new_opcodes = %s" % (new_opcodes,))
        return new_opcodes

    def execute_instructions(self, instructions):
        for instruction in instructions:
            new_ops = []  # this solution took 1.5 hours to find
            if len(instruction) > 1:
                for op in instruction[1:]:
                    if isinstance(op, Register):
                        new_ops.append(self.parser_namespace.get_register(op.name))
                    elif isinstance(op, Reference):
                        new_ops.append(self.parser_namespace.get_variable(op.name).reference)
                    else:
                        new_ops.append(op)
                instruction = [instruction[0], *new_ops]
            debug_print("execute_instruction:\n\t\t\b", '\n\t\t'.join("- %s" % (c,) for c in instruction))
            instruction[0](self, *instruction[1:])

    def print_registers(self):
        print("REGISTER DUMP:")
        for register in self.parser_namespace.registers:
            print("\t%s %r: %r" % (register.name, register.type, register.data))

    def print_stack(self):
        print("STACK DUMP:")
        for item in self.stack:
            print("\t%r: %r" % (type(item), item))


def debug_print(*args, **kwargs):
    if is_debug:
        is_pprint = os.environ.get("PPRINT", False)
        if is_pprint:
            pprint(*args, **kwargs)  # why this broke smh
        else:
            print("debug:", *args, **kwargs)


is_debug = os.environ.get('DEBUG', False)

filename = sys.argv[1]
if not os.path.isfile(filename):
    sys.exit("error: %r is either a directory or doesn't exist" % filename)

with Parser(filename) as parser:
    instructions = parser.parse_instructions()
    parsed_instructions = parser.verify_operands(instructions)
    parser.execute_instructions(parsed_instructions)
    parser.print_registers()
    parser.print_stack()

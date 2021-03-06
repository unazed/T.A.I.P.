# T.A.I.P.
the assembly interpeter [in] python (also taip means yes in my language)

at the moment (00:29 1st June '18), the interpreter supports:
- simple compilation-error tracebacks
- generation of dynamic opcode/operand listings from source
- namespaces (which could inherently allow support for stack-frames and heap)
- opcode parsing and operand signature generation/detection
- executing instructions
- some basic instructions

and at the moment (00:30 1st June '18), the interpreter plans on (soon) supporting:
- ~~genuine opcode parsing and detection~~
- ~~opcode operand template generation~~ (no idea what i even meant by this)
- stack frames (kinda supported but not fully implemented)
- the heap
- sections
- ~~branching labels~~ (added labels/jumping but soon enough i'll also add conditional branching)

it isn't an assembler, nor is it a compiler.
the syntax is defined in `asm.py`, alongside everything else. but for time's sake (for you), i'll redefine the syntax here (it's basically some GAS syntax + Intel dst-src operand ordering):

```
; whole-line comments
push "hello, world!" ; you can push immediates!!! how unusual (also internal comments)
call @print, $1, @str ; registers prefixed with %
                      ; (integer) immediates prefixed with $
                      ; external references (outwith the local scope)
                      ; are referred to by prefixing its name with @
                      ; e.g.: @print, @idx, @self etc.
mov my_variable, $0x69 ; support for octal, hexadecimal, binary and
                       ; standard base 10 integral notation.
                       ; also if variables aren't already defined in
                       ; operations, they're automatically defined.
; basically, most GPR registers (+ stack registers) are imported from
; x86_64 e.g. rax, rbx, rcx etc. and can store any type of information.
; however a small notice is that integer immediates can only be as big
; as the register is in size, i.e. 64 bits wide, else there's a
; compilation/run-time error (no overflow flag is set as of now).
;
; arguments are passed by the stack, though it wouldn't be hard to
; have them be passed by register. the call opcode takes three arguments
; 1) the function
; 2) amount of arguments to pop from the stack, by default $0
; 3) the mapping function unto the items on the stack e.g. @str would
;    map str(...) over each stack item that is popped so you could do
;     push $1
;     push $2
;     call @print, $2, @str
;    which would theoretically print "2 1"
;
; string literals support escaping strings to place internal `"`s or
; whatever `STRING_IDENT` is defined to be.
```

some further notes that'd probably be useful to know are that
- upon any error the compiler can give you the (approx.) area whereabouts the parsing error occurred ('approx.' because the context handler's `__exit__` is pretty shadily written with hard-coded offsets) and specifically the line/char. no. at which the error was.
- you can enable some fairly verbose debugging by setting `DEBUG=1` in your environment variables. For example I run my code with the command `DEBUG=1 python3.8 asm.py asm.S`.
- you can change around all the identities for the individual types of tokens e.g. string identifiers could be changed to \` instead of ", or literal identifiers could become \# instead of $ etc.
- python 3.8 is the version i've tested it on, however it probably works on other versions. mainly i just wanted you to know i'm in the future.
- the (perhaps seemingly) redundant `enumerate`ions performed in the `_parse_*` family of functions are (notably) done so that the traceback frame in the `__exit__` handler can recall specific character offsets during parsing and provide better traceback information when `sys.exit`/compilation errors occur.
- variables are called `Reference`s, and these `Reference`s are paired with a `ReferencePointer`; both of these are `collections.namedtuple`s.

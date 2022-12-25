class FnSig:
    def __init__(self, args, ret_ty):
        self.args = args
        self.ret_ty = ret_ty
        self.has_ret = False
        self.locals = None

class Fn:
    def __init__(self, name, sig, body, extern, loc):
        self.name = name
        self.sig = sig
        self.body = body
        self.extern = extern
        self.loc = loc

class Macro:
    def __init__(self, name, tokens, loc):
        self.name = name
        self.tokens = tokens
        self.loc = loc

class Import:
    def __init__(self, name, loc):
        self.name = name
        self.loc = loc

class If:
    def __init__(self, body, addr, else_body, else_addr, loc):
        self.body = body
        self.addr = addr
        self.else_body = else_body
        self.else_addr = else_addr
        self.loc = loc

class Do:
    def __init__(self, body, do_addr, end_addr, loc):
        self.body = body
        self.do_addr = do_addr
        self.end_addr = end_addr
        self.loc = loc

class While:
    def __init__(self, addr, loc):
        self.addr = addr
        self.loc = loc

class Const:
    def __init__(self, name, typ, value, loc):
        self.name = name
        self.typ = typ
        self.value = value
        self.loc = loc

class Return:
    def __init__(self, loc):
        self.loc = loc
        self.locals = None

class PushInt:
    def __init__(self, value, loc=None):
        self.value = value
        self.loc = loc

class PushFloat:
    def __init__(self, value, addr, loc=None):
        self.value = value
        self.addr = addr
        self.loc = loc

class PushStr:
    def __init__(self, value, addr, loc=None):
        self.value = value
        self.addr = addr
        self.loc = loc

class PushBool:
    def __init__(self, value, loc=None):
        self.value = value
        self.loc = loc

class Binary:
    def __init__(self, kind, ty, loc):
        self.kind = kind
        self.ty = ty
        self.loc = loc

class Intrinsic:
    def __init__(self, kind, loc):
        self.kind = kind
        self.ty = None
        self.loc = loc

class Call:
    def __init__(self, name, loc):
        self.name = name
        self.loc = loc

class MacroCall:
    def __init__(self, name, loc):
        self.name = name
        self.loc = loc

class PushVar:
    def __init__(self, name, loc):
        self.name = name
        self.loc = loc

class PushAddr:
    def __init__(self, name, loc):
        self.name = name
        self.loc = loc

class Deref:
    def __init__(self, name, loc):
        self.name = name
        self.ty = None
        self.loc = loc

class Destruct:
    def __init__(self, value, loc):
        self.value = value
        self.loc = loc

class Let:
    def __init__(self, symbols, loc):
        self.symbols = symbols
        self.loc = loc


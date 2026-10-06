"""Part (b): a small Python obfuscator built on the `ast` module.
Techniques: (1) strip comments/docstrings, (2) rename identifiers, (3) encode string literals,
(4) pack the whole program as zlib+base64 and exec() it at runtime."""
import ast, base64, builtins, zlib

BUILTINS = set(dir(builtins))


class _Collect(ast.NodeVisitor):
    def __init__(self):
        self.names, self.protected = set(), set()

    def visit_FunctionDef(self, n):
        self.names.add(n.name)
        for a in n.args.posonlyargs + n.args.args + n.args.kwonlyargs:
            self.names.add(a.arg)
        for a in (n.args.vararg, n.args.kwarg):
            if a: self.names.add(a.arg)
        self.generic_visit(n)

    def visit_Name(self, n):
        if isinstance(n.ctx, ast.Store):
            self.names.add(n.id)

    def visit_Import(self, n):
        for a in n.names: self.protected.add((a.asname or a.name).split(".")[0])

    visit_ImportFrom = visit_Import

    def visit_ClassDef(self, n):
        self.protected.add(n.name); self.generic_visit(n)


class _Rename(ast.NodeTransformer):
    def __init__(self, mapping): self.m = mapping

    def visit_FunctionDef(self, n):
        n.name = self.m.get(n.name, n.name)
        for a in n.args.posonlyargs + n.args.args + n.args.kwonlyargs + [x for x in (n.args.vararg, n.args.kwarg) if x]:
            a.arg = self.m.get(a.arg, a.arg)
        self.generic_visit(n); return n

    def visit_Name(self, n):
        n.id = self.m.get(n.id, n.id); return n

    def visit_keyword(self, n):
        if n.arg in self.m: n.arg = self.m[n.arg]
        self.generic_visit(n); return n


class _Strings(ast.NodeTransformer):
    def visit_JoinedStr(self, n):            # leave f-string literal parts alone
        for v in n.values:
            if isinstance(v, ast.FormattedValue): v.value = self.visit(v.value)
        return n

    def visit_Constant(self, n):
        if isinstance(n.value, str) and n.value:
            enc = base64.b64encode(n.value.encode()).decode()
            return ast.parse(f"__import__('base64').b64decode('{enc}').decode()", mode="eval").body
        return n


def _strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)) and node.body \
                and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant) \
                and isinstance(node.body[0].value.value, str):
            node.body = node.body[1:] or [ast.Pass()]


def obfuscate(source: str, rename=True, strings=True, pack=True, strip=True) -> str:
    tree = ast.parse(source)                 # comments vanish automatically at this step
    if strip: _strip_docstrings(tree)
    if rename:
        c = _Collect(); c.visit(tree)
        targets = sorted(n for n in c.names if n not in BUILTINS and n not in c.protected and n != "self")
        mapping = {n: "_0x" + format(abs(hash(n)) % 0xFFFFFF, "06x") + str(i) for i, n in enumerate(targets)}
        tree = _Rename(mapping).visit(tree)
    if strings: tree = _Strings().visit(tree)
    ast.fix_missing_locations(tree)
    out = ast.unparse(tree)
    if pack:
        blob = base64.b64encode(zlib.compress(out.encode(), 9)).decode()
        out = f"import zlib,base64\nexec(zlib.decompress(base64.b64decode('{blob}')).decode())"
    return out


def deobfuscate_pack(packed: str) -> str:
    """Shows how trivially the 'pack' layer is undone – obfuscation is NOT encryption."""
    import re
    blob = re.search(r"b64decode\('([^']+)'\)", packed).group(1)
    return zlib.decompress(base64.b64decode(blob)).decode()

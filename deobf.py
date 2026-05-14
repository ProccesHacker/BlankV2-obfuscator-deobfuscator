import ast
import base64
import binascii
import operator
import zlib
import re


def banner():
    print(f"""\033[31m
             %                                                    %
              %%                                                %%
               %%%                                            %%%
                 %%%%                                      %%%%
                   %%%%%                                %%%%%
                     %%%%%%%                        %%%%%%%
                       %%%%%%%%:                :%%%%%%%%
                         %%%%%%%%%%          %%%%%%%%%%
                           :%%%%%%%%        %%%%%%%%:
                              %%%%%%        %%%%%%
                               %%%%.         %%%%
                               %%%%          %%%%
                              :%%%%%        %%%%%:
                              %%%%%%%%%  %%%%%%%%%
                                %%%%%%%%%%%%%%%%
                                  %%%%%%%%%%%%
                                    #%%%%%%#
                                       %%

                        Деобфускатор создавал ProcHacker.""")


class Err(ValueError):
    pass


def read(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


bops = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
    ast.Pow: operator.pow, ast.BitXor: operator.xor,
}
uops = {
    ast.UAdd: operator.pos, ast.USub: operator.neg,
    ast.Invert: operator.invert,
}


def ev(n):
    if isinstance(n, ast.Expression):
        return ev(n.body)
    if isinstance(n, ast.Constant):
        return n.value
    if isinstance(n, ast.List):
        return [ev(x) for x in n.elts]
    if isinstance(n, ast.Tuple):
        return tuple(ev(x) for x in n.elts)
    if isinstance(n, ast.UnaryOp) and type(n.op) in uops:
        return uops[type(n.op)](ev(n.operand))
    if isinstance(n, ast.BinOp) and type(n.op) in bops:
        return bops[type(n.op)](ev(n.left), ev(n.right))
    if isinstance(n, ast.Subscript):
        v = ev(n.value)
        i = slc(n.slice)
        return v[i]
    if isinstance(n, ast.Call):
        return evcall(n)
    raise ValueError


def slc(n):
    if isinstance(n, ast.Slice):
        lo = ev(n.lower) if n.lower is not None else None
        hi = ev(n.upper) if n.upper is not None else None
        st = ev(n.step) if n.step is not None else None
        return slice(lo, hi, st)
    return ev(n)


def evcall(n):
    if isinstance(n.func, ast.Name):
        nm = n.func.id
        a = [ev(x) for x in n.args]
        if nm == "bytes": return bytes(a[0])
        if nm == "list": return list(a[0])
        if nm == "int": return int(a[0])
        if nm == "str": return str(a[0])
        if nm == "range": return range(*a)
    if isinstance(n.func, ast.Attribute):
        v = ev(n.func.value)
        a = [ev(x) for x in n.args]
        if n.func.attr == "decode" and isinstance(v, bytes):
            return v.decode(*a)
        if n.func.attr == "split" and isinstance(v, str):
            return v.split(*a)
    raise ValueError


def lit(n):
    try:
        return ev(n)
    except Exception:
        return None


def asint(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def asstr(v):
    return v if isinstance(v, str) else None


def asintlist(v):
    if isinstance(v, list) and all(isinstance(x, int) for x in v):
        return v
    return None


def asstrlist(v):
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    return None


def decomp(data):
    try:
        return zlib.decompress(data).decode("utf-8")
    except (zlib.error, UnicodeDecodeError):
        return None


def layer1(tree):
    parts = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            v = asstr(lit(n.value))
            if v is not None and len(v) > 8:
                parts.append(v)
    if len(parts) < 4:
        return None

    for s in range(0, len(parts) - 3):
        joined = "".join(parts[s : s + 4])
        try:
            raw = base64.b64decode(joined, validate=True)
        except binascii.Error:
            continue
        d = decomp(raw)
        if d is not None:
            return d
    return None


def layer2(tree):
    enc = None
    for n in ast.walk(tree):
        if isinstance(n, ast.List):
            v = asintlist(lit(n))
            if v and len(v) > 20:
                enc = v
                break
    if enc is None:
        return None

    locs = getlocs(tree)
    if locs is not None:
        left, right = locs
        for key in range(1, 101):
            if not (0 <= left < right < len(enc)):
                continue
            if enc[left] ^ key != enc[right]:
                continue
            pay = enc[:left] + enc[left + 1 : right] + enc[right + 1 :]
            raw = bytes(x ^ key for x in pay)
            d = decomp(raw)
            if d is not None:
                return d

    pos = {}
    for i, v in enumerate(enc):
        pos.setdefault(v, []).append(i)

    for key in range(1, 101):
        for left, v in enumerate(enc):
            for right in pos.get(v ^ key, []):
                if right <= left:
                    continue
                pay = enc[:left] + enc[left + 1 : right] + enc[right + 1 :]
                raw = bytes(x ^ key for x in pay)
                d = decomp(raw)
                if d is not None:
                    return d
    return None


def getlocs(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.If):
            continue
        t = n.test
        if not isinstance(t, ast.Compare) or len(t.ops) != 1 or len(t.comparators) != 1:
            continue
        if not isinstance(t.ops[0], ast.Eq):
            continue
        le = t.left
        re_ = t.comparators[0]
        if not isinstance(le, ast.BinOp) or not isinstance(le.op, ast.BitXor):
            continue
        l = subidx(le.left)
        r = subidx(re_)
        if l is None or r is None:
            continue
        return (l, r) if l < r else (r, l)
    return None


def subidx(n):
    if not isinstance(n, ast.Subscript):
        return None
    return asint(lit(n.slice))


def isip(v):
    p = v.split(".")
    if not 1 <= len(p) <= 4:
        return False
    try:
        return all(0 <= int(x) <= 255 for x in p)
    except ValueError:
        return False


def layer3(tree):
    cands = []
    for n in ast.walk(tree):
        if isinstance(n, ast.List):
            v = asstrlist(lit(n))
            if v and all(isip(x) for x in v):
                cands.append(v)

    for c in cands:
        octets = []
        for x in c:
            octets.extend(int(p) for p in x.split("."))
        try:
            raw = base64.b64decode(bytes(octets), validate=True)
        except (binascii.Error, ValueError):
            continue
        d = decomp(raw)
        if d is not None:
            return d
    return None


def once(src):
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        raise Err("не удалось распарсить файл") from e

    for fn in (layer1, layer2, layer3):
        d = fn(tree)
        if d is not None:
            return d
    return None


def fmt(src):
    try:
        return ast.unparse(ast.parse(src)) + "\n"
    except SyntaxError:
        return src


def deobf(src, mx=50):
    cur = src
    for _ in range(mx):
        d = once(cur)
        if d is None:
            return fmt(cur)
        cur = d
    raise Err("слишком много слоёв BlankOBF.")


def proc(p, o=None):
    src = read(p)
    d = deobf(src)
    if o is None:
        o = re.sub(r"\.py$", "", p) + "_deobf.py"
    write(o, d)
    return o


def main():
    banner()
    p = ""
    while not p:
        p = input("Введите путь к файлу: ").strip().strip('"')
    r = proc(p)
    print(f"Deobfuscated file written to: {r}")


if __name__ == "__main__":
    main()

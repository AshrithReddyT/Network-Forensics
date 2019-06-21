"""Useful routines and utilities which simplify code writing"""
from scapy import all as scapy_all


def hexdump(data, columns=16, indentlvl=""):
    """Return the hexadecimal representation of the data"""

    def do_line(line):
        return (
            indentlvl +
            " ".join("{:02x}".format(ord(b)) for b in line) +
            "   " * (columns - len(line)) +
            "  " +
            "".join(b if 32 <= ord(b) < 127 else "." for b in line))

    return "\n".join(do_line(data[i:i + columns]) for i in range(0, len(data), columns))


class LEShortLenField(scapy_all.FieldLenField):
    """A len field in a 2-byte integer"""

    def __init__(self, name, default, count_of=None, length_of=None):
        scapy_all.FieldLenField.__init__(self, name, default, fmt="<H",
                                         count_of=count_of, length_of=length_of)


class XBitEnumField(scapy_all.BitEnumField):
    """A BitEnumField with hexadecimal representation"""

    def __init__(self, name, default, size, enum):
        scapy_all.BitEnumField.__init__(self, name, default, size, enum)

    def i2repr_one(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return scapy_all.lhex(x)

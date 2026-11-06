"""
字节与 BER-TLV 基础层（纯函数，零业务依赖）。

职责
----
只做「十六进制字符串 <-> bytes」和 BER-TLV 的编码/解码；不认识 eUICC、不发起 IO、
不依赖 bleak / textual / HTTP。所有其它层都依赖本模块，本模块不依赖任何内部模块。

对外能力
--------
  h2b / b2h              十六进制字符串 <-> bytes
  swap_nibbles           ICCID 在卡上按半字节交换存放（官方 JS 的 R/D 辅助函数）
  der_len / tlv          构造 BER-TLV（多字节 tag、长式长度）
  parse_tlv              递归解析为 [{tag, length, value}] 树
  find_tag / _find_one   按 tag 路径深度优先查找（官方 JS 的 be/ye）
  serialize_tlv          把解析节点还原为十六进制字符串（用于 pendingNotification）
  _child / _tlv_to_debug / _tlv_response_complete / _int_bytes  辅助函数

重要约定（维护者 / AI 请先读）
------------------------------
* APDU 响应状态字 SW1SW2 在**末尾**；本模块不剥离 SW，剥离由 beesim_euicc 负责。
* parse_tlv 严格校验长度，不足时抛 ValueError("Truncated TLV value: ...") 并附带
  tag / 所需长度 / 剩余长度 / 数据前缀。官方 JS 的 K() 会静默吞掉截断数据，
  这里刻意更严格，以便暴露链路问题。
* constructed 判定按 BER 规则：tag 首字节 bit6 (0x20) 置位即递归解析其 value。
* 无类、无状态、无全局可变数据，可并发安全使用。
"""

from __future__ import annotations

from typing import Optional

def h2b(hexstr: str) -> bytes:
    return bytes.fromhex("".join(hexstr.split()))


def b2h(data: bytes) -> str:
    return data.hex().upper()


def swap_nibbles(hexstr: str) -> str:
    """ICCID <-> on-card nibble-swapped form (JS `R`). Pads odd length with 'F'."""
    if len(hexstr) % 2:
        hexstr += "F"
    return "".join(hexstr[i + 1] + hexstr[i] for i in range(0, len(hexstr), 2))


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def tlv(tag, *children: bytes) -> bytes:
    """Build a BER-TLV (port of JS `H`): tag + length + concatenated children.

    `tag` may be an int (single byte) or a bytes/list of tag bytes.
    """
    if isinstance(tag, int):
        tag = bytes([tag])
    else:
        tag = bytes(tag)
    value = b"".join(children)
    return tag + der_len(len(value)) + value


def parse_tlv(data: bytes, start: int = 0, end: Optional[int] = None) -> list:
    """Recursive BER-TLV parser (port of JS `K`). Returns a list of nodes:
    {tag: 'HEX', length: int, value: bytes|list}. Constructed tags nest a list."""
    if end is None:
        end = len(data)
    if not 0 <= start <= end <= len(data):
        raise ValueError("Invalid TLV bounds")
    out = []
    i = start
    while i < end:
        tag_start = i
        constructed = (data[i] & 0x20) != 0
        if (data[i] & 0x1F) == 0x1F:  # multi-byte tag
            i += 1
            while i < end and (data[i] & 0x80):
                i += 1
            if i >= end:
                raise ValueError("Truncated TLV tag")
            i += 1
        else:
            i += 1
        tag = data[tag_start:i].hex().upper()
        # length
        if i >= end:
            raise ValueError("Missing TLV length")
        if data[i] & 0x80:
            nlen = data[i] & 0x7F
            i += 1
            if not nlen or i + nlen > end:
                raise ValueError("Invalid TLV length")
            length = 0
            for _ in range(nlen):
                length = (length << 8) | data[i]
                i += 1
        else:
            length = data[i]
            i += 1
        if i + length > end:
            raise ValueError(
                f"Truncated TLV value: tag {tag} needs {length} bytes, "
                f"only {end - i} remain at offset {i} "
                f"(data {data[start:start + 16].hex().upper()}...)")
        value_bytes = data[i:i + length]
        # A node's value is a list for constructed tags, bytes for primitive ones.
        value: bytes | list
        if constructed:
            value = parse_tlv(data, i, i + length)
        else:
            value = value_bytes
        out.append({"tag": tag, "length": length, "value": value})
        i += length
    return out


def _tlv_response_complete(data: bytes) -> bool:
    """True when a card response contains whole top-level BER-TLV objects.

    A BeeSIM card occasionally ends a chained GET RESPONSE early (the Web
    bundle tolerates this silently; the strict parser here does not). Read-only
    ES10 commands can be replayed to recover the full response.
    """
    if not data:
        return False
    try:
        parse_tlv(data)
        return True
    except ValueError:
        return False


def find_tag(nodes: list, *tags: str):
    """Depth-first search through parsed TLV for a tag path (port of `be`/`ye`).
    Returns the matching node's value (bytes for primitive, list for constructed)."""
    current = nodes
    node = None
    for want in tags:
        node = _find_one(current, want)
        if node is None:
            return None
        current = node["value"] if isinstance(node["value"], list) else []
    if node is None:
        return None
    return node["value"]


def _find_one(nodes: list, want: str):
    nested = []
    for n in nodes:
        if n["tag"] == want:
            return n
        if isinstance(n["value"], list):
            nested.append(n)
    for n in nested:
        found = _find_one(n["value"], want)
        if found:
            return found
    return None


def serialize_tlv(node: dict) -> str:
    """Serialize a parsed node back to hex (port of JS `Ce`)."""
    if isinstance(node["value"], str):  # already-hex primitive (unused here)
        v = node["value"]
    elif isinstance(node["value"], bytes):
        v = node["value"].hex().upper()
    else:  # constructed
        v = "".join(serialize_tlv(c) for c in node["value"])
    tag = node["tag"]
    return tag + der_len(len(v) // 2).hex().upper() + v


# --------------------------------------------------------------------------- #


def _child(node: dict, tag: str):
    if isinstance(node["value"], list):
        for c in node["value"]:
            if c["tag"] == tag:
                return c["value"]
    return None



def _int_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _tlv_to_debug(nodes: list) -> dict:
    def conv(n):
        if isinstance(n["value"], list):
            return {n["tag"]: [conv(c) for c in n["value"]]}
        return {n["tag"]: b2h(n["value"])}
    return {"tlv": [conv(n) for n in nodes]}


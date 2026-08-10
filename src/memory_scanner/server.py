"""
Memory Scanner MCP Server
基于 pymem 的内存扫描与修改 MCP 服务器
支持进程附加、内存扫描、值修改、地址监控等功能
"""

import re
import struct
import ctypes
import ctypes.wintypes
from typing import Optional
from enum import Enum

import pymem
import pymem.process
import pymem.memory
import pymem.pattern
import psutil
from fastmcp import FastMCP

# 创建 MCP 服务器实例
mcp = FastMCP("MemoryScanner")


# 全局状态管理
class ScanState:
    """管理扫描会话状态"""

    def __init__(self):
        self.pm: Optional[pymem.Pymem] = None
        self.process_name: Optional[str] = None
        self.process_id: Optional[int] = None
        self.scan_results: list[int] = []
        self.scan_type: str = "int32"
        self.frozen_addresses: dict[int, tuple[str, bytes]] = {}


state = ScanState()


# Windows API 常量
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

READABLE_PROTECTIONS = (
    PAGE_READWRITE,
    PAGE_READONLY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
)


# 模块级 MEMORY_BASIC_INFORMATION 定义（避免重复创建）
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


MBI_SIZE = ctypes.sizeof(MEMORY_BASIC_INFORMATION())


def _iter_readable_regions(handle, start=0x10000, end=0x7FFFFFFFFFFF):
    """迭代进程中所有可读的已提交内存区域

    Yields:
        (base_address, region_size) tuples
    """
    mbi = MEMORY_BASIC_INFORMATION()
    address = start

    while address < end:
        result = ctypes.windll.kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            MBI_SIZE,
        )
        if result == 0:
            break

        region_size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE_PROTECTIONS:
            yield (address, region_size)

        address += region_size


class ValueType(str, Enum):
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    FLOAT = "float"
    DOUBLE = "double"
    STRING = "string"
    BYTES = "bytes"


TYPE_FORMAT = {
    "int8": ("b", 1),
    "int16": ("<h", 2),
    "int32": ("<i", 4),
    "int64": ("<q", 8),
    "uint8": ("B", 1),
    "uint16": ("<H", 2),
    "uint32": ("<I", 4),
    "uint64": ("<Q", 8),
    "float": ("<f", 4),
    "double": ("<d", 8),
}


def _encode_value(value_type: str, value) -> bytes:
    """将值编码为字节"""
    if value_type == "string":
        return value.encode("utf-8") + b"\x00"
    if value_type == "bytes":
        return bytes.fromhex(value)
    fmt, _ = TYPE_FORMAT[value_type]
    return struct.pack(fmt, value)


def _decode_value(value_type: str, data: bytes):
    """将字节解码为值"""
    if value_type == "string":
        return data.split(b"\x00")[0].decode("utf-8", errors="replace")
    if value_type == "bytes":
        return data.hex()
    fmt, _ = TYPE_FORMAT[value_type]
    return struct.unpack(fmt, data)[0]


def _get_value_size(value_type: str) -> int:
    """获取值类型的字节大小"""
    if value_type in TYPE_FORMAT:
        return TYPE_FORMAT[value_type][1]
    return 0


# ==================== MCP Tools ====================


@mcp.tool()
def list_processes(name_filter: str = "") -> str:
    """列出当前运行的进程

    Args:
        name_filter: 可选的进程名过滤关键字（不区分大小写）

    Returns:
        匹配的进程列表，包含 PID 和进程名
    """
    processes = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            info = proc.info
            if name_filter and name_filter.lower() not in info["name"].lower():
                continue
            processes.append(f"PID: {info['pid']:>8} | {info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not processes:
        return f"未找到匹配 '{name_filter}' 的进程"

    total = len(processes)
    processes = processes[:50]
    result = "\n".join(processes)
    if total > 50:
        result += f"\n\n... 共 {total} 个进程，仅显示前 50 个"
    return result


@mcp.tool()
def attach_process(process_name: str = "", process_id: int = 0) -> str:
    """附加到目标进程（通过进程名或PID）

    Args:
        process_name: 进程名称（如 "notepad.exe"），与 process_id 二选一
        process_id: 进程PID，与 process_name 二选一

    Returns:
        附加结果信息
    """
    if not process_name and not process_id:
        return "错误: 必须提供 process_name 或 process_id"

    # 关闭已有连接
    if state.pm:
        try:
            state.pm.close_process()
        except Exception:
            pass
        state.pm = None

    try:
        if process_id:
            state.pm = pymem.Pymem()
            state.pm.open_process_from_id(process_id)
            state.process_id = process_id
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["pid"] == process_id:
                    state.process_name = proc.info["name"]
                    break
        else:
            state.pm = pymem.Pymem(process_name)
            state.process_name = process_name
            state.process_id = state.pm.process_id
    except pymem.exception.ProcessNotFound:
        return f"错误: 未找到进程 '{process_name}'"
    except pymem.exception.CouldNotOpenProcess:
        return f"错误: 无法打开进程（权限不足，请以管理员身份运行）"
    except Exception as e:
        return f"错误: 附加进程失败 - {e}"

    state.scan_results = []
    state.frozen_addresses = {}

    base = state.pm.process_base.lpBaseOfDll if state.pm.process_base else 0
    return (
        f"成功附加到进程:\n"
        f"  进程名: {state.process_name}\n"
        f"  PID: {state.process_id}\n"
        f"  基址: 0x{base:X}"
    )


@mcp.tool()
def detach_process() -> str:
    """断开与当前进程的连接"""
    if not state.pm:
        return "当前未附加任何进程"

    name = state.process_name
    try:
        state.pm.close_process()
    except Exception:
        pass

    state.pm = None
    state.process_name = None
    state.process_id = None
    state.scan_results = []
    state.frozen_addresses = {}
    return f"已断开与进程 '{name}' 的连接"


@mcp.tool()
def get_process_info() -> str:
    """获取当前附加进程的详细信息"""
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        proc = psutil.Process(state.process_id)
        mem_info = proc.memory_info()

        modules = []
        for module in state.pm.list_modules():
            modules.append(
                f"  0x{module.lpBaseOfDll:016X} | "
                f"{module.SizeOfImage:>10} bytes | {module.name}"
            )

        module_list = "\n".join(modules[:20])
        if len(modules) > 20:
            module_list += f"\n  ... 共 {len(modules)} 个模块"

        return (
            f"进程信息:\n"
            f"  名称: {state.process_name}\n"
            f"  PID: {state.process_id}\n"
            f"  内存使用: {mem_info.rss / 1024 / 1024:.1f} MB\n"
            f"  虚拟内存: {mem_info.vms / 1024 / 1024:.1f} MB\n"
            f"\n已加载模块:\n{module_list}"
        )
    except Exception as e:
        return f"错误: 获取进程信息失败 - {e}"


@mcp.tool()
def read_memory(address: str, value_type: str = "int32", length: int = 0) -> str:
    """读取指定地址的内存值

    Args:
        address: 内存地址（支持十六进制如 "0x12345678" 或十进制）
        value_type: 值类型 (int8/int16/int32/int64/uint8/uint16/uint32/uint64/float/double/string/bytes)
        length: 当类型为 string 或 bytes 时，读取的字节数（默认 string=256, bytes=64）

    Returns:
        读取到的值
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
    except ValueError:
        return f"错误: 无效的地址格式 '{address}'"

    try:
        if value_type == "string":
            read_len = length if length > 0 else 256
            data = state.pm.read_bytes(addr, read_len)
            value = data.split(b"\x00")[0].decode("utf-8", errors="replace")
            return f"地址 0x{addr:X} 的值 (string): \"{value}\""
        elif value_type == "bytes":
            read_len = length if length > 0 else 64
            data = state.pm.read_bytes(addr, read_len)
            hex_str = " ".join(f"{b:02X}" for b in data)
            return f"地址 0x{addr:X} 的值 (bytes, {read_len}字节):\n{hex_str}"
        else:
            fmt, size = TYPE_FORMAT[value_type]
            data = state.pm.read_bytes(addr, size)
            value = struct.unpack(fmt, data)[0]
            if isinstance(value, float):
                return f"地址 0x{addr:X} 的值 ({value_type}): {value:.6f}"
            return f"地址 0x{addr:X} 的值 ({value_type}): {value}"
    except Exception as e:
        return f"错误: 读取地址 0x{addr:X} 失败 - {e}"


@mcp.tool()
def write_memory(address: str, value: str, value_type: str = "int32") -> str:
    """写入值到指定内存地址

    Args:
        address: 内存地址（支持十六进制如 "0x12345678" 或十进制）
        value: 要写入的值（数值类型传数字，bytes类型传十六进制字符串如 "FF00AB"）
        value_type: 值类型 (int8/int16/int32/int64/uint8/uint16/uint32/uint64/float/double/string/bytes)

    Returns:
        写入结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
    except ValueError:
        return f"错误: 无效的地址格式 '{address}'"

    try:
        if value_type == "string":
            data = value.encode("utf-8") + b"\x00"
        elif value_type == "bytes":
            data = bytes.fromhex(value.replace(" ", ""))
        elif value_type in ("float", "double"):
            data = _encode_value(value_type, float(value))
        else:
            data = _encode_value(value_type, int(value))

        state.pm.write_bytes(addr, data, len(data))

        # 回读验证
        verify = state.pm.read_bytes(addr, len(data))
        if verify == data:
            return f"成功写入地址 0x{addr:X} ({value_type}): {value}"
        else:
            return f"写入地址 0x{addr:X}，但验证不一致（可能被保护）"
    except Exception as e:
        return f"错误: 写入地址 0x{addr:X} 失败 - {e}"


@mcp.tool()
def batch_read_memory(
    addresses: str,
    value_type: str = "int32",
    length: int = 0,
) -> str:
    """批量读取多个地址的内存值

    Args:
        addresses: 多个内存地址，逗号分隔（支持十六进制如 "0x12345678,0x12345680,0x12345688"）
        value_type: 值类型 (int8/int16/int32/int64/uint8/uint16/uint32/uint64/float/double/string/bytes)
        length: 当类型为 string 或 bytes 时，读取的字节数（默认 string=256, bytes=64）

    Returns:
        每个地址的读取结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    addr_list = []
    for addr_str in addresses.split(","):
        addr_str = addr_str.strip()
        if not addr_str:
            continue
        try:
            addr_list.append(
                int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            )
        except ValueError:
            return f"错误: 无效的地址格式 '{addr_str}'"

    if not addr_list:
        return "错误: 未提供有效地址"

    lines = [f"批量读取 ({value_type}), 共 {len(addr_list)} 个地址:\n"]
    success = 0
    failed = 0

    for addr in addr_list:
        try:
            if value_type == "string":
                read_len = length if length > 0 else 256
                data = state.pm.read_bytes(addr, read_len)
                val = data.split(b"\x00")[0].decode("utf-8", errors="replace")
                lines.append(f"  0x{addr:X} = \"{val}\"")
            elif value_type == "bytes":
                read_len = length if length > 0 else 64
                data = state.pm.read_bytes(addr, read_len)
                hex_str = " ".join(f"{b:02X}" for b in data[:32])
                if read_len > 32:
                    hex_str += " ..."
                lines.append(f"  0x{addr:X} = {hex_str}")
            else:
                fmt, size = TYPE_FORMAT[value_type]
                data = state.pm.read_bytes(addr, size)
                val = struct.unpack(fmt, data)[0]
                if isinstance(val, float):
                    lines.append(f"  0x{addr:X} = {val:.6f}")
                else:
                    lines.append(f"  0x{addr:X} = {val}")
            success += 1
        except Exception as e:
            lines.append(f"  0x{addr:X} = <读取失败: {e}>")
            failed += 1

    lines.append(f"\n成功: {success}, 失败: {failed}")
    return "\n".join(lines)


@mcp.tool()
def batch_write_memory(
    addresses: str,
    values: str,
    value_type: str = "int32",
) -> str:
    """批量写入多个地址的内存值

    Args:
        addresses: 多个内存地址，逗号分隔（支持十六进制如 "0x12345678,0x12345680"）
        values: 对应的写入值，逗号分隔。若只提供一个值，则所有地址写入相同值
        value_type: 值类型 (int8/int16/int32/int64/uint8/uint16/uint32/uint64/float/double/string/bytes)

    Returns:
        每个地址的写入结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    # 解析地址列表
    addr_list = []
    for addr_str in addresses.split(","):
        addr_str = addr_str.strip()
        if not addr_str:
            continue
        try:
            addr_list.append(
                int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            )
        except ValueError:
            return f"错误: 无效的地址格式 '{addr_str}'"

    if not addr_list:
        return "错误: 未提供有效地址"

    # 解析值列表
    value_list = [v.strip() for v in values.split(",") if v.strip()]
    if not value_list:
        return "错误: 未提供有效值"

    # 如果只有一个值，扩展到和地址数量一样
    if len(value_list) == 1:
        value_list = value_list * len(addr_list)
    elif len(value_list) != len(addr_list):
        return (
            f"错误: 地址数量 ({len(addr_list)}) 与值数量 ({len(value_list)}) 不匹配\n"
            f"提示: 提供与地址相同数量的值，或仅提供一个值（将写入所有地址）"
        )

    lines = [f"批量写入 ({value_type}), 共 {len(addr_list)} 个地址:\n"]
    success = 0
    failed = 0

    for addr, val in zip(addr_list, value_list):
        try:
            if value_type == "string":
                data = val.encode("utf-8") + b"\x00"
            elif value_type == "bytes":
                data = bytes.fromhex(val.replace(" ", ""))
            elif value_type in ("float", "double"):
                data = _encode_value(value_type, float(val))
            else:
                data = _encode_value(value_type, int(val))

            state.pm.write_bytes(addr, data, len(data))

            # 回读验证
            verify = state.pm.read_bytes(addr, len(data))
            if verify == data:
                lines.append(f"  0x{addr:X} <- {val} ✓")
                success += 1
            else:
                lines.append(f"  0x{addr:X} <- {val} (验证不一致)")
                failed += 1
        except Exception as e:
            lines.append(f"  0x{addr:X} <- {val} ✗ ({e})")
            failed += 1

    lines.append(f"\n成功: {success}, 失败: {failed}")
    return "\n".join(lines)


@mcp.tool()
def scan_memory_first(
    value: str,
    value_type: str = "int32",
    start_address: str = "",
    end_address: str = "",
) -> str:
    """首次扫描 - 在进程内存中搜索指定值

    Args:
        value: 要搜索的值
        value_type: 值类型 (int8/int16/int32/int64/uint8/uint16/uint32/uint64/float/double/string/bytes)
        start_address: 搜索起始地址（可选，默认从 0x10000 开始）
        end_address: 搜索结束地址（可选，默认到 0x7FFFFFFFFFFF）

    Returns:
        扫描结果摘要
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        start = int(start_address, 16) if start_address else 0x10000
        end = int(end_address, 16) if end_address else 0x7FFFFFFFFFFF
    except ValueError:
        return "错误: 无效的地址格式"

    # 准备搜索值
    try:
        if value_type == "string":
            search_bytes = value.encode("utf-8")
            value_size = len(search_bytes)
        elif value_type == "bytes":
            search_bytes = bytes.fromhex(value.replace(" ", ""))
            value_size = len(search_bytes)
        elif value_type in ("float", "double"):
            search_bytes = _encode_value(value_type, float(value))
            value_size = len(search_bytes)
        else:
            search_bytes = _encode_value(value_type, int(value))
            value_size = len(search_bytes)
    except (ValueError, struct.error) as e:
        return f"错误: 无法编码值 '{value}' 为 {value_type} - {e}"

    state.scan_type = value_type
    state.scan_results = []

    # 确定对齐（数值类型按自然对齐搜索，string/bytes 逐字节）
    alignment = 1
    if value_type in TYPE_FORMAT:
        alignment = TYPE_FORMAT[value_type][1]  # 自然对齐: int32->4, int16->2, etc.

    handle = state.pm.process_handle
    max_results = 10000

    for region_base, region_size in _iter_readable_regions(handle, start, end):
        if len(state.scan_results) >= max_results:
            break
        try:
            data = state.pm.read_bytes(region_base, region_size)
            if alignment > 1:
                # 对齐扫描：利用 struct 直接遍历对齐位置
                # 计算区域起始的对齐偏移
                align_offset = (alignment - (region_base % alignment)) % alignment
                for offset in range(align_offset, len(data) - value_size + 1, alignment):
                    if data[offset : offset + value_size] == search_bytes:
                        state.scan_results.append(region_base + offset)
                        if len(state.scan_results) >= max_results:
                            break
            else:
                # 字符串/字节: 使用 bytes.find (C 实现，高效)
                offset = 0
                while offset <= len(data) - value_size:
                    pos = data.find(search_bytes, offset)
                    if pos == -1:
                        break
                    state.scan_results.append(region_base + pos)
                    offset = pos + 1
                    if len(state.scan_results) >= max_results:
                        break
        except Exception:
            pass

    count = len(state.scan_results)
    if count == 0:
        return f"首次扫描完成，未找到值 '{value}' ({value_type})"

    preview = []
    for addr in state.scan_results[:10]:
        preview.append(f"  0x{addr:X}")

    result_text = "\n".join(preview)
    extra = f"\n  ... 共 {count} 个结果" if count > 10 else ""

    return (
        f"首次扫描完成，找到 {count} 个匹配地址:\n"
        f"{result_text}{extra}\n\n"
        f"提示: 等待目标值变化后，使用 scan_memory_next 进行缩小范围"
    )


@mcp.tool()
def scan_memory_next(value: str, scan_type_override: str = "") -> str:
    """再次扫描 - 在上次扫描结果中筛选新值（缩小范围）

    Args:
        value: 新的搜索值（变化后的值）
        scan_type_override: 覆盖值类型（可选，默认使用首次扫描的类型）

    Returns:
        筛选后的结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    if not state.scan_results:
        return "错误: 没有上次扫描结果，请先使用 scan_memory_first"

    vtype = scan_type_override if scan_type_override else state.scan_type

    try:
        if vtype == "string":
            search_bytes = value.encode("utf-8")
            value_size = len(search_bytes)
        elif vtype == "bytes":
            search_bytes = bytes.fromhex(value.replace(" ", ""))
            value_size = len(search_bytes)
        elif vtype in ("float", "double"):
            search_bytes = _encode_value(vtype, float(value))
            value_size = len(search_bytes)
        else:
            search_bytes = _encode_value(vtype, int(value))
            value_size = len(search_bytes)
    except (ValueError, struct.error) as e:
        return f"错误: 无法编码值 '{value}' 为 {vtype} - {e}"

    # 优化：将相邻地址分组，合并为批量读取以减少系统调用
    new_results = []
    BATCH_THRESHOLD = 4096  # 地址间距小于此值时合并读取

    i = 0
    sorted_results = sorted(state.scan_results)

    while i < len(sorted_results):
        # 找到一组相邻地址
        group_start = sorted_results[i]
        group_end = sorted_results[i] + value_size
        j = i + 1
        while j < len(sorted_results):
            if sorted_results[j] - group_start < BATCH_THRESHOLD:
                group_end = sorted_results[j] + value_size
                j += 1
            else:
                break

        # 批量读取整个区域
        read_size = group_end - group_start
        try:
            data = state.pm.read_bytes(group_start, read_size)
            for k in range(i, j):
                offset = sorted_results[k] - group_start
                if data[offset : offset + value_size] == search_bytes:
                    new_results.append(sorted_results[k])
        except Exception:
            # 回退到逐个读取
            for k in range(i, j):
                try:
                    d = state.pm.read_bytes(sorted_results[k], value_size)
                    if d == search_bytes:
                        new_results.append(sorted_results[k])
                except Exception:
                    continue

        i = j

    old_count = len(state.scan_results)
    state.scan_results = new_results
    count = len(new_results)

    if count == 0:
        return f"再次扫描完成，从 {old_count} 个地址中未找到值 '{value}'"

    preview = [f"  0x{addr:X}" for addr in new_results[:20]]
    result_text = "\n".join(preview)
    extra = f"\n  ... 共 {count} 个结果" if count > 20 else ""

    return (
        f"再次扫描完成: {old_count} -> {count} 个匹配地址:\n"
        f"{result_text}{extra}"
    )


@mcp.tool()
def scan_memory_filter(
    condition: str = "changed",
    value: str = "",
) -> str:
    """条件过滤 - 根据值变化条件筛选扫描结果

    Args:
        condition: 过滤条件 (changed/unchanged/increased/decreased/greater_than/less_than)
        value: 对于 greater_than/less_than 条件，需要提供比较值

    Returns:
        过滤后的结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    if not state.scan_results:
        return "错误: 没有扫描结果，请先使用 scan_memory_first"

    vtype = state.scan_type
    if vtype in ("string", "bytes"):
        return "错误: 条件过滤不支持 string/bytes 类型"

    fmt, size = TYPE_FORMAT[vtype]
    new_results = []

    for addr in state.scan_results:
        try:
            data = state.pm.read_bytes(addr, size)
            current = struct.unpack(fmt, data)[0]

            if condition == "greater_than":
                threshold = float(value) if vtype in ("float", "double") else int(value)
                if current > threshold:
                    new_results.append(addr)
            elif condition == "less_than":
                threshold = float(value) if vtype in ("float", "double") else int(value)
                if current < threshold:
                    new_results.append(addr)
            else:
                new_results.append(addr)
        except Exception:
            continue

    old_count = len(state.scan_results)
    state.scan_results = new_results
    count = len(new_results)

    preview = [f"  0x{addr:X}" for addr in new_results[:20]]
    result_text = "\n".join(preview)
    extra = f"\n  ... 共 {count} 个结果" if count > 20 else ""

    return (
        f"条件过滤 ({condition}) 完成: {old_count} -> {count}\n"
        f"{result_text}{extra}"
    )


@mcp.tool()
def write_scan_results(value: str, max_write: int = 10) -> str:
    """将值写入所有（或部分）扫描结果地址

    Args:
        value: 要写入的值
        max_write: 最多写入的地址数量（安全限制，默认10）

    Returns:
        写入结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    if not state.scan_results:
        return "错误: 没有扫描结果"

    vtype = state.scan_type
    try:
        if vtype == "string":
            data = value.encode("utf-8") + b"\x00"
        elif vtype == "bytes":
            data = bytes.fromhex(value.replace(" ", ""))
        elif vtype in ("float", "double"):
            data = _encode_value(vtype, float(value))
        else:
            data = _encode_value(vtype, int(value))
    except (ValueError, struct.error) as e:
        return f"错误: 无法编码值 - {e}"

    targets = state.scan_results[:max_write]
    success = 0
    failed = 0

    for addr in targets:
        try:
            state.pm.write_bytes(addr, data, len(data))
            success += 1
        except Exception:
            failed += 1

    return (
        f"批量写入完成:\n"
        f"  目标地址数: {len(targets)}\n"
        f"  成功: {success}\n"
        f"  失败: {failed}\n"
        f"  写入值: {value} ({vtype})"
    )


@mcp.tool()
def scan_pattern(
    pattern: str,
    module_name: str = "",
) -> str:
    """AOB/特征码扫描 - 使用字节模式搜索内存

    Args:
        pattern: 字节模式，用空格分隔，?? 表示通配符（如 "48 8B ?? ?? 89 05 ?? ?? ?? ??"）
        module_name: 限定搜索的模块名（可选，如 "target.exe"）

    Returns:
        匹配的地址列表
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    # 将用户友好的模式转换为 pymem 所需的 regex bytes pattern
    parts = pattern.strip().split()
    regex_parts = []

    for part in parts:
        if part in ("??", "?", "**"):
            regex_parts.append(b".")
        else:
            try:
                byte_val = int(part, 16)
                regex_parts.append(re.escape(bytes([byte_val])))
            except ValueError:
                return f"错误: 无效的模式字节 '{part}'"

    if not regex_parts:
        return "错误: 模式为空"

    regex_pattern = b"".join(regex_parts)

    try:
        if module_name:
            module = pymem.process.module_from_name(
                state.pm.process_handle, module_name
            )
            if not module:
                return f"错误: 未找到模块 '{module_name}'"

            results = pymem.pattern.pattern_scan_module(
                state.pm.process_handle,
                module,
                regex_pattern,
                return_multiple=True,
            )
        else:
            results = pymem.pattern.pattern_scan_all(
                state.pm.process_handle,
                regex_pattern,
                return_multiple=True,
            )
    except Exception as e:
        return f"错误: 扫描失败 - {e}"

    if not results:
        return "特征码扫描完成，未找到匹配模式"

    # 限制结果数量
    results = results[:100]

    preview = [f"  0x{addr:X}" for addr in results[:20]]
    result_text = "\n".join(preview)
    extra = f"\n  ... 共 {len(results)} 个结果" if len(results) > 20 else ""

    return f"特征码扫描完成，找到 {len(results)} 个匹配:\n{result_text}{extra}"


@mcp.tool()
def get_module_base(module_name: str) -> str:
    """获取指定模块的基地址

    Args:
        module_name: 模块名称（如 "target.exe", "example.dll"）

    Returns:
        模块基地址和大小
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        module = pymem.process.module_from_name(
            state.pm.process_handle, module_name
        )
        if not module:
            return f"错误: 未找到模块 '{module_name}'"

        return (
            f"模块: {module_name}\n"
            f"  基地址: 0x{module.lpBaseOfDll:X}\n"
            f"  大小: {module.SizeOfImage} bytes ({module.SizeOfImage / 1024:.1f} KB)"
        )
    except Exception as e:
        return f"错误: 获取模块信息失败 - {e}"


@mcp.tool()
def read_pointer_chain(
    base_address: str,
    offsets: str,
    value_type: str = "int32",
) -> str:
    """读取多级指针链的值

    Args:
        base_address: 基地址（支持十六进制）
        offsets: 偏移量列表，逗号分隔的十六进制值（如 "0x10,0x28,0x44"）
        value_type: 最终地址的值类型

    Returns:
        指针链解析过程和最终值
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        addr = int(base_address, 16) if base_address.startswith("0x") else int(base_address)
    except ValueError:
        return f"错误: 无效的基地址 '{base_address}'"

    offset_list = []
    for off_str in offsets.split(","):
        off_str = off_str.strip()
        try:
            offset_list.append(
                int(off_str, 16) if off_str.startswith("0x") else int(off_str)
            )
        except ValueError:
            return f"错误: 无效的偏移量 '{off_str}'"

    chain_log = [f"基地址: 0x{addr:X}"]
    current = addr

    try:
        for i, offset in enumerate(offset_list):
            if i < len(offset_list) - 1:
                ptr = state.pm.read_longlong(current)
                current = ptr + offset
                chain_log.append(f"  [0x{ptr:X}] + 0x{offset:X} = 0x{current:X}")
            else:
                current = current + offset
                chain_log.append(f"  + 0x{offset:X} = 0x{current:X} (最终地址)")

        if value_type == "string":
            data = state.pm.read_bytes(current, 256)
            value = data.split(b"\x00")[0].decode("utf-8", errors="replace")
            chain_log.append(f"  值: \"{value}\"")
        elif value_type == "bytes":
            data = state.pm.read_bytes(current, 64)
            chain_log.append(f"  值: {data.hex()}")
        else:
            fmt, size = TYPE_FORMAT[value_type]
            data = state.pm.read_bytes(current, size)
            value = struct.unpack(fmt, data)[0]
            chain_log.append(f"  值 ({value_type}): {value}")

        return "指针链解析:\n" + "\n".join(chain_log)
    except Exception as e:
        return "指针链解析失败:\n" + "\n".join(chain_log) + f"\n  错误: {e}"


@mcp.tool()
def write_pointer_chain(
    base_address: str,
    offsets: str,
    value: str,
    value_type: str = "int32",
) -> str:
    """通过多级指针链写入值

    Args:
        base_address: 基地址
        offsets: 偏移量列表，逗号分隔（如 "0x10,0x28,0x44"）
        value: 要写入的值
        value_type: 值类型

    Returns:
        写入结果
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        addr = int(base_address, 16) if base_address.startswith("0x") else int(base_address)
    except ValueError:
        return "错误: 无效的基地址"

    offset_list = []
    for off_str in offsets.split(","):
        off_str = off_str.strip()
        try:
            offset_list.append(
                int(off_str, 16) if off_str.startswith("0x") else int(off_str)
            )
        except ValueError:
            return f"错误: 无效的偏移量 '{off_str}'"

    try:
        current = addr
        for i, offset in enumerate(offset_list):
            if i < len(offset_list) - 1:
                ptr = state.pm.read_longlong(current)
                current = ptr + offset
            else:
                current = current + offset

        if value_type == "string":
            data = value.encode("utf-8") + b"\x00"
        elif value_type == "bytes":
            data = bytes.fromhex(value.replace(" ", ""))
        elif value_type in ("float", "double"):
            data = _encode_value(value_type, float(value))
        else:
            data = _encode_value(value_type, int(value))

        state.pm.write_bytes(current, data, len(data))
        return f"成功通过指针链写入 0x{current:X}: {value} ({value_type})"
    except Exception as e:
        return f"错误: 指针链写入失败 - {e}"


@mcp.tool()
def dump_memory(address: str, size: int = 256, columns: int = 16) -> str:
    """内存转储 - 以十六进制+ASCII格式显示内存区域

    Args:
        address: 起始地址
        size: 转储字节数（默认256，最大4096）
        columns: 每行显示的字节数（默认16）

    Returns:
        格式化的内存转储
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
    except ValueError:
        return "错误: 无效的地址"

    size = min(size, 4096)

    try:
        data = state.pm.read_bytes(addr, size)
    except Exception as e:
        return f"错误: 读取内存失败 - {e}"

    lines = []
    for i in range(0, len(data), columns):
        chunk = data[i : i + columns]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"0x{addr + i:08X}  {hex_part:<{columns * 3}}  {ascii_part}")

    return "\n".join(lines)


@mcp.tool()
def batch_dump_memory(
    addresses: str,
    size: int = 64,
    columns: int = 16,
) -> str:
    """批量内存转储 - 同时转储多个地址的内存内容

    Args:
        addresses: 多个内存地址，逗号分隔（支持十六进制如 "0x12345678,0x12345780"）
        size: 每个地址转储的字节数（默认64，最大1024）
        columns: 每行显示的字节数（默认16）

    Returns:
        所有地址的格式化内存转储
    """
    if not state.pm:
        return "错误: 未附加任何进程，请先使用 attach_process"

    addr_list = []
    for addr_str in addresses.split(","):
        addr_str = addr_str.strip()
        if not addr_str:
            continue
        try:
            addr_list.append(
                int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
            )
        except ValueError:
            return f"错误: 无效的地址格式 '{addr_str}'"

    if not addr_list:
        return "错误: 未提供有效地址"

    size = min(size, 1024)
    sections = []

    for addr in addr_list:
        section_lines = [f"━━━ 0x{addr:X} ({size} bytes) ━━━"]
        try:
            data = state.pm.read_bytes(addr, size)
            for i in range(0, len(data), columns):
                chunk = data[i : i + columns]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in chunk
                )
                section_lines.append(
                    f"0x{addr + i:08X}  {hex_part:<{columns * 3}}  {ascii_part}"
                )
        except Exception as e:
            section_lines.append(f"  <读取失败: {e}>")
        sections.append("\n".join(section_lines))

    return "\n\n".join(sections)


@mcp.tool()
def get_scan_results(start: int = 0, count: int = 20) -> str:
    """获取当前扫描结果列表

    Args:
        start: 起始索引
        count: 返回数量（最大100）

    Returns:
        扫描结果地址列表及当前值
    """
    if not state.pm:
        return "错误: 未附加任何进程"

    if not state.scan_results:
        return "当前没有扫描结果"

    count = min(count, 100)
    total = len(state.scan_results)
    subset = state.scan_results[start : start + count]

    vtype = state.scan_type
    lines = [f"扫描结果 (共 {total} 个, 显示 {start}-{start + len(subset) - 1}):"]
    lines.append(f"类型: {vtype}\n")

    for i, addr in enumerate(subset):
        try:
            if vtype in TYPE_FORMAT:
                fmt, size = TYPE_FORMAT[vtype]
                data = state.pm.read_bytes(addr, size)
                val = struct.unpack(fmt, data)[0]
                if isinstance(val, float):
                    lines.append(f"  [{start + i:>4}] 0x{addr:X} = {val:.4f}")
                else:
                    lines.append(f"  [{start + i:>4}] 0x{addr:X} = {val}")
            else:
                lines.append(f"  [{start + i:>4}] 0x{addr:X}")
        except Exception:
            lines.append(f"  [{start + i:>4}] 0x{addr:X} = <读取失败>")

    return "\n".join(lines)


@mcp.tool()
def freeze_address(address: str, value: str, value_type: str = "int32") -> str:
    """冻结地址 - 将地址添加到冻结列表（需要配合外部循环写入）

    注意：MCP 服务器本身无法持续写入，此工具记录冻结信息供客户端轮询使用

    Args:
        address: 要冻结的地址
        value: 冻结的值
        value_type: 值类型

    Returns:
        冻结状态
    """
    if not state.pm:
        return "错误: 未附加任何进程"

    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
    except ValueError:
        return "错误: 无效的地址"

    try:
        if value_type == "string":
            data = value.encode("utf-8") + b"\x00"
        elif value_type == "bytes":
            data = bytes.fromhex(value.replace(" ", ""))
        elif value_type in ("float", "double"):
            data = _encode_value(value_type, float(value))
        else:
            data = _encode_value(value_type, int(value))
    except (ValueError, struct.error) as e:
        return f"错误: 值编码失败 - {e}"

    state.frozen_addresses[addr] = (value_type, data)

    try:
        state.pm.write_bytes(addr, data, len(data))
    except Exception as e:
        return f"警告: 冻结地址已记录，但首次写入失败 - {e}"

    return (
        f"已冻结地址 0x{addr:X} = {value} ({value_type})\n"
        f"当前冻结列表共 {len(state.frozen_addresses)} 个地址\n"
        f"提示: 调用 apply_frozen 来执行一次冻结写入"
    )


@mcp.tool()
def unfreeze_address(address: str) -> str:
    """解除地址冻结

    Args:
        address: 要解冻的地址
    """
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
    except ValueError:
        return "错误: 无效的地址"

    if addr in state.frozen_addresses:
        del state.frozen_addresses[addr]
        return f"已解冻地址 0x{addr:X}，剩余 {len(state.frozen_addresses)} 个冻结地址"

    return f"地址 0x{addr:X} 不在冻结列表中"


@mcp.tool()
def apply_frozen() -> str:
    """执行一次冻结写入 - 将所有冻结地址的值重新写入

    Returns:
        写入结果
    """
    if not state.pm:
        return "错误: 未附加任何进程"

    if not state.frozen_addresses:
        return "冻结列表为空"

    success = 0
    failed = 0

    for addr, (vtype, data) in state.frozen_addresses.items():
        try:
            state.pm.write_bytes(addr, data, len(data))
            success += 1
        except Exception:
            failed += 1

    return f"冻结写入完成: 成功 {success}, 失败 {failed}"


@mcp.tool()
def list_frozen() -> str:
    """列出所有冻结的地址"""
    if not state.frozen_addresses:
        return "冻结列表为空"

    lines = [f"冻结地址列表 (共 {len(state.frozen_addresses)} 个):"]
    for addr, (vtype, data) in state.frozen_addresses.items():
        if vtype in TYPE_FORMAT:
            fmt, _ = TYPE_FORMAT[vtype]
            val = struct.unpack(fmt, data)[0]
            lines.append(f"  0x{addr:X} = {val} ({vtype})")
        else:
            lines.append(f"  0x{addr:X} = {data.hex()} ({vtype})")

    return "\n".join(lines)


@mcp.tool()
def invalidate_window(process_name: str = "", process_id: int = 0) -> str:
    """触发目标进程窗口重绘（InvalidateRect）

    通过向目标进程的所有顶层窗口发送重绘请求，强制刷新显示内容。
    修改内存后调用此工具可立即看到效果。

    Args:
        process_name: 进程名（可选，默认使用当前附加的进程）
        process_id: 进程PID（可选，默认使用当前附加的进程）

    Returns:
        重绘结果
    """
    # 确定目标 PID
    target_pid = 0
    if process_id:
        target_pid = process_id
    elif process_name:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"].lower() == process_name.lower():
                    target_pid = proc.info["pid"]
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not target_pid:
            return f"错误: 未找到进程 '{process_name}'"
    elif state.process_id:
        target_pid = state.process_id
    else:
        return "错误: 未指定目标进程，也未附加任何进程"

    # Windows API 定义
    user32 = ctypes.windll.user32

    # EnumWindows 回调类型
    WNDENUMPROC = ctypes.WINFUNCTYPE(
        ctypes.wintypes.BOOL,
        ctypes.wintypes.HWND,
        ctypes.wintypes.LPARAM,
    )

    # 收集目标进程的窗口句柄
    hwnd_list = []

    def enum_callback(hwnd, lparam):
        pid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == target_pid:
            if user32.IsWindowVisible(hwnd):
                hwnd_list.append(hwnd)
        return True

    user32.EnumWindows(WNDENUMPROC(enum_callback), 0)

    if not hwnd_list:
        return f"未找到进程 PID={target_pid} 的可见窗口"

    # 对每个窗口调用 InvalidateRect + UpdateWindow
    RDW_INVALIDATE = 0x0001
    RDW_UPDATENOW = 0x0100
    RDW_ALLCHILDREN = 0x0080

    success = 0
    for hwnd in hwnd_list:
        # RedrawWindow 比 InvalidateRect 更强力
        result = user32.RedrawWindow(
            hwnd,
            None,
            None,
            RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN,
        )
        if result:
            success += 1

    return (
        f"窗口重绘完成:\n"
        f"  目标进程 PID: {target_pid}\n"
        f"  找到窗口数: {len(hwnd_list)}\n"
        f"  成功重绘: {success}"
    )


@mcp.tool()
def encode_string(
    text: str,
    encoding: str = "utf-8",
) -> str:
    """字符串编码器 - 将文本编码为十六进制字符串

    用于将字符串转换为可直接用于内存写入的十六进制格式。
    支持 Python 所有内置编码。

    Args:
        text: 要编码的文本字符串
        encoding: 编码格式，支持 Python 所有内置编码（默认 utf-16le）

    Returns:
        十六进制字符串
    """
    try:
        encoded = text.encode(encoding)
    except LookupError:
        return f"错误: 未知编码 '{encoding}'，请使用 Python 支持的编码名称"
    except UnicodeEncodeError as e:
        return f"错误: 文本无法用 {encoding} 编码 - {e}"

    return encoded.hex().upper()


@mcp.tool()
def calc_address(expression: str) -> str:
    """地址计算器 - 计算地址表达式

    支持十六进制和十进制的加减乘运算，避免手动计算错误。

    Args:
        expression: 地址计算表达式，支持 +, -, *, 括号, 十六进制(0x前缀)
                    例如: "0x7FF6C76D0000 + 0x1A4", "0x12345678 - 0x100", "0x1000 * 4"

    Returns:
        计算结果（十六进制和十进制）
    """
    expr = expression.strip()
    if not expr:
        return "错误: 表达式为空"

    # 将 0x 十六进制数转换为 Python 可 eval 的格式（0x 已原生支持）
    # 安全检查：只允许数字、十六进制字符、运算符和括号
    allowed = set("0123456789abcdefABCDEFxX+-*()/ \t")
    if not all(c in allowed for c in expr):
        return f"错误: 表达式包含不允许的字符，仅支持: 数字, 0x十六进制, +, -, *, /, ()"

    try:
        result = int(eval(expr))  # noqa: S307
    except Exception as e:
        return f"错误: 计算失败 - {e}"

    return f"0x{result:X} ({result})"

"""Draws Warden's icon (packaging/warden.ico): the app's teal shield with a check mark.

Plain Python only (no image library): each pixel is tested against the shape, with
4x4 sub-samples for smooth edges, and saved as PNG images inside a Windows .ico file.
Run:  python packaging/make_icon.py
"""

import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent / "warden.ico"
BACKGROUND = (11, 46, 43)     # #0b2e2b, the dark Warden bar
SHIELD = (45, 212, 191)       # #2dd4bf, Warden teal
SIZES = (256, 64, 48, 32, 16)

# The shield outline in a 24x24 grid (same shape as the app's SVG icon).
SHIELD_POINTS = [(12, 2), (20, 5), (20, 12), (19.4, 15.2), (17.6, 18.1), (15.0, 20.4), (12, 22),
                 (9.0, 20.4), (6.4, 18.1), (4.6, 15.2), (4, 12), (4, 5)]
CHECK = [(8.6, 12.2), (11, 14.6), (15.6, 9.8)]
CHECK_WIDTH = 2.0


def inside(x: float, y: float, poly: list[tuple[float, float]]) -> bool:
    """Ray casting: is (x, y) inside the polygon?"""
    result = False
    j = len(poly) - 1
    for i, (xi, yi) in enumerate(poly):
        xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            result = not result
        j = i
    return result


def near_line(x: float, y: float, a: tuple, b: tuple, width: float) -> bool:
    (ax, ay), (bx, by) = a, b
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    px, py = ax + t * dx, ay + t * dy
    return (x - px) ** 2 + (y - py) ** 2 <= (width / 2) ** 2


def in_rounded_square(x: float, y: float, radius: float = 5.0) -> bool:
    cx, cy = min(max(x, radius), 24 - radius), min(max(y, radius), 24 - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2


def colour_at(x: float, y: float) -> tuple[int, int, int, int]:
    if not in_rounded_square(x, y):
        return (0, 0, 0, 0)
    if any(near_line(x, y, CHECK[i], CHECK[i + 1], CHECK_WIDTH) for i in range(len(CHECK) - 1)):
        return (*BACKGROUND, 255)
    if inside(x, y, SHIELD_POINTS):
        return (*SHIELD, 255)
    return (*BACKGROUND, 255)


def render(size: int) -> bytes:
    """RGBA rows for a PNG (each row starts with filter byte 0)."""
    sub = 4
    rows = bytearray()
    for py in range(size):
        rows.append(0)
        for px in range(size):
            total = [0, 0, 0, 0]
            for sy in range(sub):
                for sx in range(sub):
                    x = (px + (sx + 0.5) / sub) * 24 / size
                    y = (py + (sy + 0.5) / sub) * 24 / size
                    r, g, b, a = colour_at(x, y)
                    total[0] += r * a
                    total[1] += g * a
                    total[2] += b * a
                    total[3] += a
            alpha = total[3] / (sub * sub)
            if total[3]:
                rows += bytes((round(total[0] / total[3]), round(total[1] / total[3]),
                               round(total[2] / total[3]), round(alpha)))
            else:
                rows += bytes(4)
    return bytes(rows)


def png(size: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)       # 8-bit RGBA
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"IDAT", zlib.compress(render(size), 9)) + chunk(b"IEND", b""))


def main() -> None:
    images = [png(s) for s in SIZES]
    directory = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for size, data in zip(SIZES, images):
        side = 0 if size >= 256 else size                              # 0 means 256 in .ico
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    OUT.write_bytes(directory + entries + b"".join(images))
    (OUT.parent / "warden-256.png").write_bytes(images[0])            # a preview you can open
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()

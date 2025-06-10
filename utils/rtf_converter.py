import logging
import re

logger = logging.getLogger(__name__)

try:
    from striprtf.striprtf import rtf_to_text as striprtf_to_text
except Exception:  # pragma: no cover - optional dependency
    striprtf_to_text = None


PRE_BUF = b""  # Placeholder, algorithm works without it


def _decompress_lzfu(data: bytes) -> bytes:
    """Decompress MAPI LZFu compressed RTF data."""
    if len(data) < 16 or data[:4] != b"LZFu":
        return data

    pos = 16  # Skip header
    window = bytearray(b" " * 4096)
    win_pos = 0x0fef
    output = bytearray()

    while pos < len(data):
        flags = data[pos]
        pos += 1
        for bit in range(8):
            if flags & (1 << bit):
                if pos >= len(data):
                    break
                c = data[pos]
                pos += 1
                output.append(c)
                window[win_pos] = c
                win_pos = (win_pos + 1) & 0xFFF
            else:
                if pos + 1 >= len(data):
                    break
                b1 = data[pos]
                b2 = data[pos + 1]
                pos += 2
                offset = ((b2 & 0xF0) << 4) | b1
                length = (b2 & 0x0F) + 2
                for _ in range(length):
                    c = window[(offset + _) & 0xFFF]
                    output.append(c)
                    window[win_pos] = c
                    win_pos = (win_pos + 1) & 0xFFF
    return bytes(output)


def rtf_to_text(data: bytes) -> str:
    """Convert RTF bytes to plain text."""
    try:
        decompressed = _decompress_lzfu(data)
    except Exception as e:  # pragma: no cover - decompress failure
        logger.warning("RTF decompression failed: %s", e)
        decompressed = data

    text = decompressed.decode("latin1", errors="ignore")

    if striprtf_to_text:
        try:
            return striprtf_to_text(text)
        except Exception as e:  # pragma: no cover - optional dependency
            logger.warning("striprtf conversion failed: %s", e)

    # Fallback: naive stripping of RTF control words
    text = re.sub(r"\\'..", "", text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", text)
    text = text.replace("\\par", "\n")
    text = re.sub(r"[{}]", "", text)
    return text.strip()

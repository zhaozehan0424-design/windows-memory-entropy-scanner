import ctypes
import time

HEX_MARKER = b"00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F"

buffer = ctypes.create_string_buffer(HEX_MARKER + b"\0")
print(f"pid={ctypes.windll.kernel32.GetCurrentProcessId()} marker={HEX_MARKER.decode()}", flush=True)

while True:
    # Keep the ctypes allocation alive for the scanner.
    _ = buffer.raw[0]
    time.sleep(1)

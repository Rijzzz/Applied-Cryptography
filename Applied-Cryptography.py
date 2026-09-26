import os
import sys
import time
import struct
import argparse
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

class Sender:
    def __init__(self, key: bytes, algo: str = "AES_GCM"):
        if len(key) != KEY_SIZE:
            raise ValueError(f"key must be exactly {KEY_SIZE} bytes")
        self.key = key
        self.algo = algo
        self.seq = 0
        self._cipher = AESGCM(key) if algo == "AES_GCM" else ChaCha20Poly1305(key)

    def protect(self, pt: bytes, aad: bytes = b"") -> dict:
        # 64-bit counter + 4 zero bytes = 96-bit nonce (standard for GCM/Poly1305)
        nonce = struct.pack(">Q", self.seq) + b"\x00\x00\x00\x00"
        full_aad = struct.pack(">Q", self.seq) + aad
        self.seq += 1

        raw = self._cipher.encrypt(nonce, pt, full_aad)
        ct, tag = raw[:-TAG_SIZE], raw[-TAG_SIZE:]

        return {
            "nonce": nonce,
            "aad": full_aad,
            "ct": ct,
            "tag": tag
        }

class Receiver:
    def __init__(self, key: bytes, algo: str = "AES_GCM"):
        if len(key) != KEY_SIZE:
            raise ValueError(f"key must be exactly {KEY_SIZE} bytes")
        self.key = key
        self.algo = algo
        # TODO: replace with sliding window if this runs in long sessions
        self.seen = set()
        self._cipher = AESGCM(key) if algo == "AES_GCM" else ChaCha20Poly1305(key)

    def open(self, record: dict):
        nonce = record["nonce"]
        aad = record["aad"]
        ct = record["ct"]
        tag = record["tag"]

        if len(aad) < 8:
            return None

        seq = struct.unpack(">Q", aad[:8])[0]
        if seq in self.seen:
            return None

        try:
            pt = self._cipher.decrypt(nonce, ct + tag, aad)
            self.seen.add(seq)
            return pt
        except InvalidTag:
            return None

# File format: [1B algo_id] [12B nonce] [16B tag] [4B aad_len] [aad] [ciphertext]
def encrypt_file(in_path: str, out_path: str, key: bytes, algo: str = "AES_GCM") -> bool:
    with open(in_path, "rb") as f:
        data = f.read()

    sender = Sender(key, algo)
    meta = os.path.basename(in_path).encode("utf-8")
    rec = sender.protect(data, meta)

    algo_id = 0 if algo == "AES_GCM" else 1
    hdr = struct.pack(">B12s16sI", algo_id, rec["nonce"], rec["tag"], len(rec["aad"]))

    with open(out_path, "wb") as f:
        f.write(hdr + rec["aad"] + rec["ct"])
    return True

def decrypt_file(in_path: str, out_path: str, key: bytes) -> bool:
    with open(in_path, "rb") as f:
        raw = f.read()

    if len(raw) < 33:
        return False

    algo_id, nonce, tag, aad_len = struct.unpack(">B12s16sI", raw[:33])
    algo = "AES_GCM" if algo_id == 0 else "ChaCha20_Poly1305"
    aad = raw[33:33 + aad_len]
    ct = raw[33 + aad_len:]

    receiver = Receiver(key, algo)
    pt = receiver.open({"nonce": nonce, "aad": aad, "ct": ct, "tag": tag})
    if pt is None:
        return False

    with open(out_path, "wb") as f:
        f.write(pt)
    return True

def run_tests():
    print("running tests...")
    for algo in ["AES_GCM", "ChaCha20_Poly1305"]:
        key = os.urandom(32)
        s = Sender(key, algo)
        r = Receiver(key, algo)
        msg = b"Confidential record content"

        rec = s.protect(msg, b"hdr_v1")
        assert r.open(rec) == msg
        print(f"[{algo}] decrypt: PASS")

        bad = dict(rec)
        bad["ct"] = bytes([bad["ct"][0] ^ 0x01]) + bad["ct"][1:]
        assert r.open(bad) is None
        print(f"[{algo}] tampered ct: PASS")

        bad = dict(rec)
        bad["tag"] = bytes([bad["tag"][0] ^ 0xFF]) + bad["tag"][1:]
        assert r.open(bad) is None
        print(f"[{algo}] tampered tag: PASS")

        bad = dict(rec)
        bad["aad"] = bad["aad"][:-1] + b"X"
        assert r.open(bad) is None
        print(f"[{algo}] tampered aad: PASS")

        assert r.open(rec) is None
        print(f"[{algo}] replay blocked: PASS")

        r_bad = Receiver(os.urandom(32), algo)
        fresh = s.protect(b"Another message", b"hdr")
        assert r_bad.open(fresh) is None
        print(f"[{algo}] wrong key: PASS")

    # nonce collision check, 10k is overkill but it runs in under a second
    for algo in ["AES_GCM", "ChaCha20_Poly1305"]:
        s = Sender(os.urandom(32), algo)
        seen = set()
        for _ in range(10000):
            rec = s.protect(b"ping", b"h")
            seen.add(rec["nonce"])
        assert len(seen) == 10000
        print(f"[{algo}] 10k nonces, 0 collisions: PASS")
    print()

def run_benchmark():
    print(f"{'Algorithm':<18} | {'Payload':<10} | {'Enc Time':<10} | {'Dec Time':<10} | {'Speed':<12}")

    for algo in ["AES_GCM", "ChaCha20_Poly1305"]:
        key = os.urandom(32)
        s = Sender(key, algo)
        r = Receiver(key, algo)

        for size in [64, 1024, 65536]:
            payload = os.urandom(size)

            t0 = time.time()
            packets = [s.protect(payload, b"meta") for _ in range(200)]
            enc_t = time.time() - t0

            t1 = time.time()
            for p in packets:
                r.open(p)
            dec_t = time.time() - t1

            total_mb = (size * 200) / (1024 * 1024)
            mb_s = total_mb / (enc_t + dec_t)
            print(f"{algo:<18} | {size:>5} bytes | {enc_t:>8.4f}s | {dec_t:>8.4f}s | {mb_s:>8.2f} MB/s")
    print()

def main():
    parser = argparse.ArgumentParser(description="AEAD encryption utility & test runner")
    parser.add_argument("--algo", choices=["AES_GCM", "ChaCha20_Poly1305"], default="AES_GCM")
    parser.add_argument("--encrypt-text", type=str, help="Encrypt a plaintext string")
    parser.add_argument("--encrypt-file", nargs=2, metavar=("IN", "OUT"), help="Encrypt a file")
    parser.add_argument("--decrypt-file", nargs=2, metavar=("IN", "OUT"), help="Decrypt a file")
    parser.add_argument("--key", type=str, help="32-byte hex key")
    parser.add_argument("--test", action="store_true", help="Run security test suite")
    parser.add_argument("--benchmark", action="store_true", help="Run speed benchmark")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        run_tests()
        run_benchmark()
        return

    key = bytes.fromhex(args.key) if args.key else os.urandom(32)

    if args.encrypt_text:
        s = Sender(key, args.algo)
        rec = s.protect(args.encrypt_text.encode("utf-8"), b"cli")
        print(f"Algo:  {args.algo}")
        print(f"Key:   {key.hex()}")
        print(f"Nonce: {rec['nonce'].hex()}")
        print(f"Tag:   {rec['tag'].hex()}")
        print(f"CT:    {rec['ct'].hex()}")

    elif args.encrypt_file:
        src, dst = args.encrypt_file
        encrypt_file(src, dst, key, args.algo)
        print(f"Encrypted {src} -> {dst}")
        print(f"Key (hex): {key.hex()}")

    elif args.decrypt_file:
        src, dst = args.decrypt_file
        if not args.key:
            print("Error: --key required to decrypt")
            sys.exit(1)
        if decrypt_file(src, dst, key):
            print(f"Decrypted {src} -> {dst}")
        else:
            print("Decryption failed: corrupted data or wrong key")
            sys.exit(1)

    elif args.test:
        run_tests()

    elif args.benchmark:
        run_benchmark()

if __name__ == "__main__":
    main()

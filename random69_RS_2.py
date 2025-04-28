import hashlib
import base58
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import random
import sys

TARGET_ADDRESSES = {"19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"}

def private_key_to_compressed_address(private_key_hex):
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        public_key_bytes = prefix + x.to_bytes(32, 'big')
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hashed_public_key = ripemd160.digest()
        network_byte = b"\x00" + hashed_public_key
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        binary_address = network_byte + checksum
        bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
        return bitcoin_address
    except Exception:
        return None

def hybrid_brute_force_process(start, end, total_tests_per_process, process_id):
    base_key = random.randint(start, end)
    for i in range(total_tests_per_process):
        if i % 1_000_000 == 0:
            base_key = random.randint(start, end)
        private_key_int = base_key + (i % 1_000_000)
        if private_key_int > end:
            private_key_int = start + (private_key_int - end - 1)
        private_key_hex = f"{private_key_int:064x}"
        bitcoin_address = private_key_to_compressed_address(private_key_hex)
        if i % 50_000 == 0:
            progress = (i + 1) / total_tests_per_process * 100
            print(f"\rProcess {process_id}: Progress: {progress:.2f}% | Testing private key: {private_key_hex}", end="", flush=True)
        if bitcoin_address in TARGET_ADDRESSES:
            print(f"\nPrivate key found: {private_key_hex}")
            print(f"Bitcoin address: {bitcoin_address}")
            return private_key_hex
    print(f"\nProcess {process_id} completed. Private key not found.")
    return None

if __name__ == "__main__":
    START_KEY = 0x100000000000000000
    END_KEY = 0x1fffffffffffffffff
    TOTAL_TESTS = 10_000_000  # Untuk HP, jangan terlalu besar
    NUM_PROCESSES = 1  # 1 proses agar progress jelas di Termux
    TESTS_PER_PROCESS = TOTAL_TESTS // NUM_PROCESSES

    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        futures = []
        for process_id in range(NUM_PROCESSES):
            future = executor.submit(hybrid_brute_force_process, START_KEY, END_KEY, TESTS_PER_PROCESS, process_id)
            futures.append(future)
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)
    print("Search completed. Private key not found.")

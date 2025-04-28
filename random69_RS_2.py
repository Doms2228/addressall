import hashlib
import base58
import secp256k1
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import random
import sys

# Target address (gunakan set untuk lookup cepat)
TARGET_ADDRESSES = {"19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"}

def private_key_to_compressed_address(private_key_hex):
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        privkey = secp256k1.PrivateKey(private_key_bytes, raw=True)
        public_key = privkey.pubkey.serialize(compressed=True)
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hashed_public_key = ripemd160.digest()
        network_byte = b"\x00" + hashed_public_key
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        binary_address = network_byte + checksum
        bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
        return bitcoin_address
    except Exception as e:
        # Hindari spam error
        return None

def hybrid_brute_force_process(start, end, total_tests_per_process, process_id):
    base_key = random.randint(start, end)
    for i in range(total_tests_per_process):
        # Ganti base key setiap 1 juta iterasi
        if i % 1_000_000 == 0:
            base_key = random.randint(start, end)
        private_key_int = base_key + (i % 1_000_000)
        if private_key_int > end:
            private_key_int = start + (private_key_int - end - 1)
        private_key_hex = f"{private_key_int:064x}"
        bitcoin_address = private_key_to_compressed_address(private_key_hex)
        # Output progress setiap 200.000 iterasi saja
        if i % 200_000 == 0:
            progress = (i + 1) / total_tests_per_process * 100
            print(f"\rProcess {process_id}: {progress:.2f}% | Key: {private_key_hex[:12]}...", end="")
            sys.stdout.flush()
        if bitcoin_address in TARGET_ADDRESSES:
            print(f"\n[FOUND] Process {process_id}: Private key: {private_key_hex}")
            print(f"Address: {bitcoin_address}")
            return private_key_hex
    print(f"\nProcess {process_id} selesai. Private key tidak ditemukan.")
    return None

if __name__ == "__main__":
    START_KEY = 0x100000000000000000
    END_KEY = 0x1fffffffffffffffff
    TOTAL_TESTS = 10_000_000  # Untuk HP, cukup 10 juta dulu, bisa dinaikkan jika kuat
    NUM_PROCESSES = min(2, multiprocessing.cpu_count())  # Maksimal 2 proses di HP
    TESTS_PER_PROCESS = TOTAL_TESTS // NUM_PROCESSES

    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        futures = []
        for process_id in range(NUM_PROCESSES):
            future = executor.submit(
                hybrid_brute_force_process,
                START_KEY, END_KEY, TESTS_PER_PROCESS, process_id
            )
            futures.append(future)
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)
    print("\nSearch completed. Private key not found.")

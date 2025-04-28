import hashlib
import base58
import secp256k1
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import random
import sys

# Define the target Bitcoin addresses as a set
TARGET_ADDRESSES = {"19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"}

# Function to derive a compressed Bitcoin address from a private key
def private_key_to_compressed_address(private_key_hex):
    try:
        # Convert the private key from hex string to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Generate the public key using secp256k1
        privkey = secp256k1.PrivateKey(private_key_bytes, raw=True)
        public_key = privkey.pubkey.serialize(compressed=True)  # Compressed public key
        
        # Hash the public key to generate the Bitcoin address
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hashed_public_key = ripemd160.digest()
        
        # Add network byte (0x00 for mainnet Bitcoin)
        network_byte = b"\x00" + hashed_public_key
        
        # Compute checksum (first 4 bytes of double SHA-256 hash)
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        
        # Encode in Base58 to get the Bitcoin address
        binary_address = network_byte + checksum
        bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
        
        return bitcoin_address
    except Exception as e:
        print(f"Error generating compressed address: {e}")
        return None

# Function to perform randomized and sequential brute-force search in a single process
def hybrid_brute_force_process(start, end, total_tests_per_process, process_id):
    used_keys = set()  # Track used private keys to avoid duplicates
    base_key = random.randint(start, end)  # Initial random base key
    
    for i in range(total_tests_per_process):
        # Change base key every 1,000,000 iterations
        if i % 1_000_000 == 0:
            base_key = random.randint(start, end)
        
        # Sequentially increment from the base key
        private_key_int = base_key + (i % 1_000_000)
        if private_key_int > end:
            private_key_int = start + (private_key_int - end - 1)  # Wrap around if out of range
        
        private_key_hex = f"{private_key_int:064x}"  # Convert to 64-character hex string
        
        # Check if the private key has already been used
        if private_key_hex not in used_keys:
            used_keys.add(private_key_hex)  # Mark the private key as used
        else:
            continue  # Skip duplicate keys
        
        # Derive the Bitcoin address from the private key
        bitcoin_address = private_key_to_compressed_address(private_key_hex)
        
        # Update progress dynamically (every 50,000 iterations)
        if i % 50_000 == 0:
            progress = (i + 1) / total_tests_per_process * 100
            sys.stdout.write(f"\rProcess {process_id}: Progress: {progress:.2f}% | Testing private key: {private_key_hex}")
            sys.stdout.flush()
        
        # Check if the derived Bitcoin address matches any of the target addresses
        if bitcoin_address in TARGET_ADDRESSES:
            print(f"\nPrivate key found: {private_key_hex}")
            print(f"Bitcoin address: {bitcoin_address}")
            return private_key_hex
    
    print(f"\nProcess {process_id} completed. Private key not found.")
    return None

# Main function to execute the brute-force search with multiple processes
if __name__ == "__main__":
    # Define the range of private keys to search (for Puzzle #69)
    START_KEY = 0x100000000000000000  # Start of the range for Puzzle #69
    END_KEY = 0x1fffffffffffffffff    # End of the range for Puzzle #69
    
    # Total number of tests across all processes
    TOTAL_TESTS = 100_000_000  # Reduced to 100 million tests
    
    # Number of processes
    NUM_PROCESSES = multiprocessing.cpu_count()  # Use all available CPU cores
    
    # Divide the total tests among the processes
    TESTS_PER_PROCESS = TOTAL_TESTS // NUM_PROCESSES
    
    # Perform the hybrid brute-force search using multiple processes
    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        futures = []
        for process_id in range(NUM_PROCESSES):
            future = executor.submit(hybrid_brute_force_process, START_KEY, END_KEY, TESTS_PER_PROCESS, process_id)
            futures.append(future)
        
        # Wait for all processes to complete and check results
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)  # Exit early if a private key is found
    
    print("Search completed. Private key not found.")
import sys
from datetime import datetime
from hashlib import sha256
import json

MAGIC_NUMBER = b'\xf9\xbe\xb4\xd9'

def main():
    file_path = sys.argv[1]

    try:
        #open the file in 'read binary' mode
        with open(file_path, 'rb') as file:
            block_count = 0
            previous_block_header_hash = None #initialize with none for the first block
            previous_block_timestamp = None #initalize with none for the first block
            blocks_data = [] #dictionary for JSON output

            while True: #loop until the end of the file
                #read the preamble
                magic_number_bytes = file.read(4)

                if not magic_number_bytes: #check for EOF
                    break

                #validate magic number
                if not validate_magic_number(magic_number_bytes, block_count):
                    sys.exit(1)

                block_size_bytes = file.read(4)
                #read the block header
                header_bytes = file.read(80)  # Version (4) + Previous Hash (32) + Merkle Root (32) + Time (4) + nBits (4) + Nonce (4)
                version_bytes, prev_header_hash_bytes, merkle_root_hash_bytes, time_bytes, nBits_bytes, nonce_bytes = \
                    header_bytes[:4], header_bytes[4:36], header_bytes[36:68], header_bytes[68:72], header_bytes[72:76], header_bytes[76:80]

                #validate header version
                if not validate_header_version(version_bytes, block_count):
                    sys.exit(1)

                current_block_header_hash = calculate_block_header_hash(header_bytes)

                # Validate previous header hash (skip for the first block)
                if block_count > 0:
                    if previous_block_header_hash != prev_header_hash_bytes.hex():
                        print(f"error 3 block {block_count}")
                        sys.exit(1)

                # validate the timestamp
                if not validate_timestamp(time_bytes, previous_block_timestamp, block_count):
                    sys.exit(1)

                #read the transaction count
                txn_count = read_compact_size(file)

                transactions = []
                transaction_hashes = []
                for _ in range(txn_count):
                    transaction_start_pos = file.tell() #get the start position of the transaction
                    transaction_version = file.read(4)
                    validate_transaction_version(int.from_bytes(transaction_version, byteorder='little'), block_count)
                    txn_in_count = read_compact_size(file)
                    txn_inputs = [read_transaction_inputs(file) for _ in range(txn_in_count)]
                    txn_out_count = read_compact_size(file)
                    txn_outputs = [read_transaction_outputs(file) for _ in range(txn_out_count)]
                    lock_time = file.read(4)
                    transaction_end_pos = file.tell() #get the end position of the transaction

                    #read the entire binary data of the transaction
                    file.seek(transaction_start_pos)
                    transaction_binary_data = file.read(transaction_end_pos - transaction_start_pos)

                    #compute the double SHA-256 hash of the transaction binary data
                    transaction_double_hash = sha256(sha256(transaction_binary_data).digest()).digest()
                    transaction_hashes.append(transaction_double_hash.hex()) #store the transaction hash

                    transaction = {
                        "version": int.from_bytes(transaction_version,byteorder='little'),
                        "txn_in_count": txn_in_count,
                        "txn_inputs": txn_inputs,
                        "txn_out_count": txn_out_count,
                        "txn_outputs": txn_outputs,
                        "lock_time": int.from_bytes(lock_time, byteorder='little')
                    }
                    transactions.append(transaction)

                    file.seek(transaction_end_pos) #reset the file pointer to the end of the transaction

                computed_merkle_root = compute_merkle_root(transaction_hashes)
                block_header_merkle_root = merkle_root_hash_bytes.hex()

                if computed_merkle_root != block_header_merkle_root: #validate merkle root hash
                    print(f"error 6 block {block_count}")
                    sys.exit(1)

                #construct a dictionary of the block
                block_info = {
                    "height": block_count,
                    "version": int.from_bytes(version_bytes, 'little'),
                    "previous_hash": prev_header_hash_bytes[::-1].hex(),
                    "merkle_hash": merkle_root_hash_bytes[::-1].hex(),
                    "timestamp": int.from_bytes(time_bytes, 'little'),
                    "timestamp_readable": datetime.utcfromtimestamp(int.from_bytes(time_bytes, 'little')).strftime(
                        '%Y-%m-%d %H:%M:%S'),
                    "nbits": nBits_bytes[::-1].hex(),
                    "nonce": int.from_bytes(nonce_bytes, 'little'),
                    "txn_count": txn_count,
                    "transactions": transactions
                }
                blocks_data.append(block_info)

                previous_block_header_hash = current_block_header_hash
                previous_block_timestamp = int.from_bytes(time_bytes, 'little') #update the previous block timestamp
                block_count += 1

        #serialize and write JSON data to file
        output_filename = file_path + ".json"
        # Before the json.dump call
        with open(output_filename, 'w') as json_file:
            json.dump({"blocks": blocks_data, "height": block_count}, json_file, indent=4)

        print(f"no errors {block_count} blocks")
    except IOError as e:
        print(f"Error opening or reading the file: {e}")

def read_compact_size(f):
    """Reads a compactSize unsigned integer from file f."""
    size = int.from_bytes(f.read(1), byteorder='little')
    if size < 0xfd:
        return size
    elif size == 0xfd:
        # Read the next 2 bytes
        return int.from_bytes(f.read(2), byteorder='little')
    elif size == 0xfe:
        # Read the next 4 bytes
        return int.from_bytes(f.read(4), byteorder='little')
    elif size == 0xff:
        # Read the next 8 bytes
        return int.from_bytes(f.read(8), byteorder='little')
    else:
        raise ValueError("Invalid size for compactSize unsigned integer")

def read_transaction_inputs(file):
    tx_id = file.read(32)
    output_index = file.read(4)
    in_script_size = read_compact_size(file)
    in_script = file.read(in_script_size)
    sequence = file.read(4)

    return {
        "txn_hash": tx_id[::-1].hex(),
        "index": int.from_bytes(output_index, byteorder='little'),
        "input_script_size": in_script_size,
        "input_script_bytes": in_script.hex(),
        "sequence": int.from_bytes(sequence, byteorder='little')
    }

def read_transaction_outputs(file):
    value_bytes = file.read(8)
    output_script_size = read_compact_size(file)
    pubkey_script = file.read(output_script_size)

    return {
        "satoshis": int.from_bytes(value_bytes, byteorder='little'),
        "output_script_size": output_script_size,
        "output_script_bytes": pubkey_script.hex()
    }


def validate_magic_number(magic_number_bytes, block_count):
    #validates blocks magic number
    if magic_number_bytes != MAGIC_NUMBER:
        print(f"error 1 block {block_count}")
        return False
    return True

def validate_header_version(version_bytes, block_count):
    #validates header version
    version = int.from_bytes(version_bytes, 'little')
    if version != 1:
        print(f"error 2 block {block_count}")
        return False
    return True

def validate_timestamp(time_bytes, previous_block_timestamp, block_count):
    #validates previous timestamp (ensuring it is no more than 2 hours before the previous block, skipping the first block)
    #convert current block's timestamp from bytes to integer
    current_block_timestamp = int.from_bytes(time_bytes, 'little')

    #skip first block
    if block_count == 0:
        return True

    #calculate the difference in hours between the current and previous block's timestamps
    time_difference_hours = (current_block_timestamp - previous_block_timestamp) / 3600

    if time_difference_hours < -2: #check if current block timestamp is earlier than 2 hours before previous block
        print(f"error 4 block {block_count}")
        return False
    return True

def validate_transaction_version(transaction_version, block_count):
    if transaction_version != 1:
        print(f"error 5 block {block_count}")
        sys.exit(1)

def calculate_block_header_hash(header_bytes):
    return sha256(sha256(header_bytes).digest()).digest().hex()

def compute_merkle_root(tx_hashes):
    #if there's only one hash, its the root
    if len(tx_hashes) == 1:
        return tx_hashes[0]

    #ensure even number of hashes by duplicating the last one if necessary
    if len(tx_hashes) % 2 == 1:
        tx_hashes.append(tx_hashes[-1])

    #compute the parent level of the hashes
    parent_hashes = []
    for i in range(0, len(tx_hashes), 2):
        hash_pair = tx_hashes[i] + tx_hashes[i + 1]
        parent_hash = sha256(sha256(bytes.fromhex(hash_pair)).digest()).hexdigest()
        parent_hashes.append(parent_hash)

    #recursively compute the root
    return compute_merkle_root(parent_hashes)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Bitcoin Mining Pool Stratum Protocol Investigator
Connects to mining pools via Stratum protocol to retrieve mining jobs and extract payout addresses
"""

import socket
import ssl
import json
import hashlib
import struct
from typing import Dict, Any, Optional, List, Tuple
from io import BytesIO


class BitcoinAddressDecoder:
    """Decode Bitcoin addresses from scriptPubKey"""
    
    BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    
    @staticmethod
    def decode_varint(data: BytesIO) -> int:
        """Decode Bitcoin variable length integer"""
        first_byte = data.read(1)
        if not first_byte:
            return 0
        n = first_byte[0]
        if n < 0xfd:
            return n
        elif n == 0xfd:
            return struct.unpack('<H', data.read(2))[0]
        elif n == 0xfe:
            return struct.unpack('<I', data.read(4))[0]
        else:
            return struct.unpack('<Q', data.read(8))[0]
    
    @staticmethod
    def bech32_polymod(values: List[int]) -> int:
        """Bech32 polymod calculation"""
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((top >> i) & 1) else 0
        return chk
    
    @staticmethod
    def bech32_hrp_expand(hrp: str) -> List[int]:
        """Expand HRP for Bech32"""
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    
    @staticmethod
    def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
        """Create Bech32 checksum"""
        values = BitcoinAddressDecoder.bech32_hrp_expand(hrp) + data
        polymod = BitcoinAddressDecoder.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    
    @staticmethod
    def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
        """Convert between bit sizes"""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret
    
    @staticmethod
    def encode_bech32(hrp: str, witver: int, witprog: bytes) -> str:
        """Encode to Bech32/Bech32m address"""
        data = [witver] + BitcoinAddressDecoder.convertbits(witprog, 8, 5)
        checksum = BitcoinAddressDecoder.bech32_create_checksum(hrp, data)
        return hrp + "1" + ''.join([BitcoinAddressDecoder.BECH32_CHARSET[d] for d in data + checksum])
    
    @staticmethod
    def base58_encode(data: bytes) -> str:
        """Encode bytes to Base58Check"""
        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        data_with_checksum = data + checksum
        
        # Convert to integer
        n = int.from_bytes(data_with_checksum, 'big')
        
        # Convert to base58
        result = ''
        while n > 0:
            n, remainder = divmod(n, 58)
            result = ALPHABET[remainder] + result
        
        # Add leading zeros
        for byte in data_with_checksum:
            if byte == 0:
                result = '1' + result
            else:
                break
        
        return result
    
    @classmethod
    def script_to_address(cls, script_hex: str, mainnet: bool = True) -> Optional[str]:
        """Convert scriptPubKey hex to Bitcoin address"""
        try:
            script = bytes.fromhex(script_hex)
            
            # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
            # 76 a9 14 <20 bytes> 88 ac
            if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac:
                pubkey_hash = script[3:23]
                prefix = b'\x00' if mainnet else b'\x6f'
                return cls.base58_encode(prefix + pubkey_hash)
            
            # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
            # a9 14 <20 bytes> 87
            if len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
                script_hash = script[2:22]
                prefix = b'\x05' if mainnet else b'\xc4'
                return cls.base58_encode(prefix + script_hash)
            
            # P2WPKH: OP_0 <20 bytes>
            # 00 14 <20 bytes>
            if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
                witprog = script[2:22]
                hrp = "bc" if mainnet else "tb"
                return cls.encode_bech32(hrp, 0, witprog)
            
            # P2WSH: OP_0 <32 bytes>
            # 00 20 <32 bytes>
            if len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
                witprog = script[2:34]
                hrp = "bc" if mainnet else "tb"
                return cls.encode_bech32(hrp, 0, witprog)
            
            # P2TR (Taproot): OP_1 <32 bytes>
            # 51 20 <32 bytes>
            if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
                witprog = script[2:34]
                hrp = "bc" if mainnet else "tb"
                # For taproot, witness version is 1
                return cls.encode_bech32(hrp, 1, witprog)
            
            # OP_RETURN (null data / unspendable)
            if script[0] == 0x6a:
                return f"OP_RETURN:{script[1:].hex()}"
            
            return f"UNKNOWN_SCRIPT:{script_hex}"
            
        except Exception as e:
            return f"DECODE_ERROR:{str(e)}"


class CoinbaseParser:
    """Parse coinbase transaction to extract outputs and payout addresses"""
    
    @staticmethod
    def parse_coinbase_tx(coinbase_hex: str) -> Dict[str, Any]:
        """Parse a coinbase transaction from hex"""
        try:
            data = BytesIO(bytes.fromhex(coinbase_hex))
            
            # Version (4 bytes, little endian)
            version = struct.unpack('<I', data.read(4))[0]
            
            # Check for segwit marker
            marker = data.read(1)
            flag = None
            if marker == b'\x00':
                flag = data.read(1)
                if flag != b'\x01':
                    return {'error': 'Invalid segwit flag'}
            else:
                # Not segwit, put marker back
                data.seek(data.tell() - 1)
            
            # Input count
            input_count = BitcoinAddressDecoder.decode_varint(data)
            
            inputs = []
            for _ in range(input_count):
                # Previous tx hash (32 bytes)
                prev_tx = data.read(32)[::-1].hex()
                # Previous output index (4 bytes)
                prev_index = struct.unpack('<I', data.read(4))[0]
                # Script length
                script_len = BitcoinAddressDecoder.decode_varint(data)
                # Script (coinbase data)
                script = data.read(script_len).hex()
                # Sequence (4 bytes)
                sequence = struct.unpack('<I', data.read(4))[0]
                
                inputs.append({
                    'prev_tx': prev_tx,
                    'prev_index': prev_index,
                    'coinbase_script': script,
                    'sequence': sequence
                })
            
            # Output count
            output_count = BitcoinAddressDecoder.decode_varint(data)
            
            outputs = []
            total_value = 0
            for i in range(output_count):
                # Value (8 bytes, little endian, in satoshis)
                value = struct.unpack('<Q', data.read(8))[0]
                total_value += value
                # Script length
                script_len = BitcoinAddressDecoder.decode_varint(data)
                # ScriptPubKey
                script_pubkey = data.read(script_len).hex()
                
                # Decode address
                address = BitcoinAddressDecoder.script_to_address(script_pubkey)
                
                outputs.append({
                    'index': i,
                    'value_satoshis': value,
                    'value_btc': value / 100_000_000,
                    'script_pubkey': script_pubkey,
                    'address': address
                })
            
            # Skip witness data if segwit
            if flag == b'\x01':
                for _ in range(input_count):
                    witness_count = BitcoinAddressDecoder.decode_varint(data)
                    for _ in range(witness_count):
                        witness_len = BitcoinAddressDecoder.decode_varint(data)
                        data.read(witness_len)
            
            # Locktime (4 bytes)
            locktime = struct.unpack('<I', data.read(4))[0]
            
            return {
                'version': version,
                'is_segwit': flag == b'\x01',
                'input_count': input_count,
                'inputs': inputs,
                'output_count': output_count,
                'outputs': outputs,
                'total_output_satoshis': total_value,
                'total_output_btc': total_value / 100_000_000,
                'locktime': locktime
            }
            
        except Exception as e:
            return {'error': f'Parse error: {str(e)}'}


class StratumClient:
    """Stratum protocol client with SSL support and proper message handling"""
    
    def __init__(self, host: str, port: int, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.socket = None
        self.buffer = ""
        self.request_id = 1
        self.extranonce1 = None
        self.extranonce2_size = None
        self.subscription_details = None
        self.pending_notifications = []  # Store notifications received during other requests
    
    def connect(self) -> bool:
        """Connect to the Stratum server"""
        try:
            print(f"\n[*] Connecting to {self.host}:{self.port} ({'SSL' if self.use_ssl else 'TCP'})...")
            
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(15)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.socket = context.wrap_socket(raw_socket, server_hostname=self.host)
            else:
                self.socket = raw_socket
            
            self.socket.connect((self.host, self.port))
            print(f"[✓] Connected successfully!")
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")
            return False
    
    def _read_messages(self, timeout: float = 5.0) -> List[Dict]:
        """Read and parse newline-delimited JSON messages"""
        messages = []
        self.socket.settimeout(timeout)
        
        try:
            while True:
                try:
                    data = self.socket.recv(4096).decode('utf-8')
                    if not data:
                        break
                    self.buffer += data
                    
                    # Process complete messages (newline-delimited)
                    while '\n' in self.buffer:
                        line, self.buffer = self.buffer.split('\n', 1)
                        line = line.strip()
                        if line:
                            try:
                                msg = json.loads(line)
                                messages.append(msg)
                            except json.JSONDecodeError:
                                print(f"[!] Invalid JSON: {line[:100]}")
                    
                    # If we got messages, short timeout for any remaining
                    if messages:
                        self.socket.settimeout(0.5)
                        
                except socket.timeout:
                    break
                    
        except Exception as e:
            print(f"[!] Read error: {str(e)}")
        
        return messages
    
    def send_request(self, method: str, params: list) -> Tuple[Optional[Dict], List[Dict]]:
        """Send request and return (response, notifications)"""
        current_id = self.request_id
        self.request_id += 1
        
        request = {
            "id": current_id,
            "method": method,
            "params": params
        }
        
        try:
            message = json.dumps(request) + "\n"
            print(f"[→] Sending: {method} (id={current_id})")
            print(f"    Request: {message.strip()}")
            self.socket.sendall(message.encode('utf-8'))
            
            # Read response and any notifications
            messages = self._read_messages()
            
            print(f"[←] Received {len(messages)} message(s)")
            
            response = None
            notifications = []
            
            for msg in messages:
                print(f"    Raw: {json.dumps(msg)}")
                if 'id' in msg and msg['id'] == current_id:
                    response = msg
                    print(f"[←] Response matched id={current_id}")
                elif 'method' in msg:
                    notifications.append(msg)
                    print(f"[←] Notification: {msg.get('method')}")
                else:
                    # Could be a response with different id or error
                    if response is None and 'result' in msg:
                        response = msg
                        print(f"[←] Using as response (no id match)")
            
            return response, notifications
            
        except Exception as e:
            print(f"[-] Request error: {str(e)}")
            return None, []
    
    def subscribe(self) -> bool:
        """Subscribe to mining notifications"""
        print(f"\n[*] Subscribing to mining pool...")
        response, notifications = self.send_request("mining.subscribe", ["PoolInvestigator/1.0"])
        
        if response and 'result' in response and response['result']:
            result = response['result']
            if isinstance(result, list) and len(result) >= 3:
                self.subscription_details = result[0]
                self.extranonce1 = result[1]
                self.extranonce2_size = result[2]
                print(f"[✓] Subscribed!")
                print(f"    Extranonce1: {self.extranonce1}")
                print(f"    Extranonce2 size: {self.extranonce2_size}")
                return True
        
        if response and 'error' in response and response['error']:
            print(f"[-] Subscribe error: {response['error']}")
        
        return False
    
    def authorize(self, username: str, password: str = "x") -> bool:
        """Authorize with the pool"""
        print(f"\n[*] Authorizing as: {username}")
        response, notifications = self.send_request("mining.authorize", [username, password])
        
        # Store any notifications we received (including mining.notify jobs!)
        self.pending_notifications.extend(notifications)
        
        if response and 'result' in response and response['result']:
            print(f"[✓] Authorized!")
            return True
        
        if response and 'error' in response and response['error']:
            print(f"[-] Auth error: {response['error']}")
        
        return False
    
    def get_job(self, timeout: float = 10.0) -> Optional[Dict]:
        """Get mining.notify job from pending notifications or wait for one"""
        print(f"\n[*] Looking for mining job...")
        
        # First check if we already have a job from previous notifications
        all_messages = self.pending_notifications.copy()
        self.pending_notifications.clear()
        
        # Also try to read any additional messages
        additional = self._read_messages(timeout=1.0)
        all_messages.extend(additional)
        
        # If no messages yet, wait longer
        if not any(msg.get('method') == 'mining.notify' for msg in all_messages):
            print(f"[*] Waiting for mining job (timeout={timeout}s)...")
            more = self._read_messages(timeout=timeout)
            all_messages.extend(more)
        
        for msg in all_messages:
            if msg.get('method') == 'mining.notify':
                params = msg.get('params', [])
                print(f"[✓] Found mining.notify job!")
                if len(params) >= 9:
                    return {
                        'job_id': params[0],
                        'prevhash': params[1],
                        'coinbase1': params[2],
                        'coinbase2': params[3],
                        'merkle_branches': params[4],
                        'version': params[5],
                        'nbits': params[6],
                        'ntime': params[7],
                        'clean_jobs': params[8]
                    }
        
        print(f"[-] No mining job found in {len(all_messages)} messages")
        return None
    
    def close(self):
        """Close connection"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            print(f"[*] Connection closed")


class PoolInvestigator:
    """Main investigator class"""
    
    def __init__(self, pool_url: str, worker: str):
        self.pool_url = pool_url
        self.worker = worker
        self.host, self.port, self.use_ssl = self._parse_pool_url(pool_url)
    
    @staticmethod
    def _parse_pool_url(url: str) -> Tuple[str, int, bool]:
        """Parse pool URL and extract host, port, and SSL flag"""
        use_ssl = False
        
        # Handle protocol prefixes
        if url.startswith('stratum+ssl://'):
            use_ssl = True
            url = url[14:]  # Remove 'stratum+ssl://'
        elif url.startswith('stratum+tcp://'):
            url = url[14:]  # Remove 'stratum+tcp://'
        elif url.startswith('stratum://'):
            url = url[10:]  # Remove 'stratum://'
        elif url.startswith('ssl://'):
            use_ssl = True
            url = url[6:]
        elif url.startswith('tcp://'):
            url = url[6:]
        
        # Parse host:port
        if ':' in url:
            parts = url.rsplit(':', 1)
            host = parts[0]
            port = int(parts[1])
        else:
            host = url
            port = 3333  # Default Stratum port
        
        return host, port, use_ssl
    
    def investigate(self) -> Dict[str, Any]:
        """Run the investigation"""
        print(f"\n{'='*70}")
        print(f"  Mining Pool Investigator")
        print(f"{'='*70}")
        print(f"  Pool URL: {self.pool_url}")
        print(f"  Host: {self.host}")
        print(f"  Port: {self.port}")
        print(f"  SSL: {self.use_ssl}")
        print(f"  Worker: {self.worker}")
        print(f"{'='*70}")
        
        results = {
            'pool_url': self.pool_url,
            'host': self.host,
            'port': self.port,
            'ssl': self.use_ssl,
            'worker': self.worker,
            'connected': False,
            'subscribed': False,
            'authorized': False,
            'extranonce1': None,
            'extranonce2_size': None,
            'mining_job': None,
            'coinbase_analysis': None,
            'payout_addresses': []
        }
        
        client = StratumClient(self.host, self.port, self.use_ssl)
        
        try:
            # Connect
            if not client.connect():
                return results
            results['connected'] = True
            
            # Subscribe
            if not client.subscribe():
                return results
            results['subscribed'] = True
            results['extranonce1'] = client.extranonce1
            results['extranonce2_size'] = client.extranonce2_size
            
            # Authorize
            if not client.authorize(self.worker):
                # Some pools don't require auth, continue anyway
                print(f"[!] Authorization not required or failed, continuing...")
            else:
                results['authorized'] = True
            
            # Get mining job (from pending notifications or wait for new one)
            job = client.get_job()
            if job:
                results['mining_job'] = job
                print(f"\n[✓] Received mining job: {job['job_id']}")
                
                # Reconstruct and parse coinbase transaction
                if client.extranonce1 and job['coinbase1'] and job['coinbase2']:
                    # Create dummy extranonce2 (zeros)
                    extranonce2 = '00' * client.extranonce2_size
                    
                    # Full coinbase transaction
                    coinbase_hex = job['coinbase1'] + client.extranonce1 + extranonce2 + job['coinbase2']
                    
                    print(f"\n[*] Analyzing coinbase transaction...")
                    print(f"    Coinbase1: {job['coinbase1'][:60]}...")
                    print(f"    Extranonce1: {client.extranonce1}")
                    print(f"    Extranonce2: {extranonce2}")
                    print(f"    Coinbase2: {job['coinbase2'][:60]}...")
                    
                    # Parse the coinbase transaction
                    parsed = CoinbaseParser.parse_coinbase_tx(coinbase_hex)
                    results['coinbase_analysis'] = parsed
                    
                    if 'error' not in parsed:
                        print(f"\n[✓] Coinbase transaction parsed successfully!")
                        print(f"    Version: {parsed['version']}")
                        print(f"    Segwit: {parsed['is_segwit']}")
                        print(f"    Outputs: {parsed['output_count']}")
                        print(f"    Total value: {parsed['total_output_btc']:.8f} BTC")
                        
                        # Extract payout addresses
                        print(f"\n{'='*70}")
                        print(f"  PAYOUT ADDRESSES")
                        print(f"{'='*70}")
                        
                        for output in parsed['outputs']:
                            addr = output['address']
                            value = output['value_btc']
                            pct = (output['value_satoshis'] / parsed['total_output_satoshis'] * 100) if parsed['total_output_satoshis'] > 0 else 0
                            
                            results['payout_addresses'].append({
                                'address': addr,
                                'value_btc': value,
                                'percentage': round(pct, 2)
                            })
                            
                            print(f"  [{output['index']}] {addr}")
                            print(f"      Value: {value:.8f} BTC ({pct:.2f}%)")
                            print()
                    else:
                        print(f"[-] Coinbase parse error: {parsed['error']}")
            else:
                print(f"[-] No mining job received")
            
        finally:
            client.close()
        
        return results


def main():
    print(f"\n{'='*70}")
    print(f"  Bitcoin Mining Pool Investigator")
    print(f"  Extracts payout addresses from pool block templates")
    print(f"{'='*70}\n")
    
    # Get pool host
    print("Enter pool host/URL (supports stratum+tcp://, stratum+ssl://, or just hostname)")
    print("Examples:")
    print("  - stratum+tcp://pool.example.com")
    print("  - stratum+ssl://pool.example.com")
    print("  - pool.example.com")
    print("  - pool.example.com:3333 (with port)")
    print()
    
    pool_url = input("Pool Host: ").strip()
    if not pool_url:
        print("[-] Pool host is required")
        return
    
    # Check if port is already in URL
    has_port = False
    temp_url = pool_url
    for prefix in ['stratum+ssl://', 'stratum+tcp://', 'stratum://', 'ssl://', 'tcp://']:
        if temp_url.startswith(prefix):
            temp_url = temp_url[len(prefix):]
            break
    if ':' in temp_url:
        has_port = True
    
    # Get port if not already specified
    if not has_port:
        print("\nEnter pool port (default: 3333)")
        port_input = input("Port [3333]: ").strip()
        if port_input:
            try:
                port = int(port_input)
                # Append port to URL
                if '://' in pool_url:
                    pool_url = pool_url + f":{port}"
                else:
                    pool_url = pool_url + f":{port}"
            except ValueError:
                print("[-] Invalid port, using default 3333")
    
    # Get worker name (usually BTC address for anonymous pools)
    print("\nEnter worker name (usually your BTC address for anonymous mining pools)")
    worker = input("Worker: ").strip()
    if not worker:
        worker = "bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Dummy address
        print(f"[*] Using default worker: {worker}")
    
    try:
        investigator = PoolInvestigator(pool_url, worker)
        results = investigator.investigate()
        
        # Summary
        print(f"\n{'='*70}")
        print(f"  INVESTIGATION SUMMARY")
        print(f"{'='*70}")
        print(f"  Pool: {results['pool_url']}")
        print(f"  Connected: {'✓' if results['connected'] else '✗'}")
        print(f"  Subscribed: {'✓' if results['subscribed'] else '✗'}")
        print(f"  Authorized: {'✓' if results['authorized'] else '✗'}")
        print(f"  Job received: {'✓' if results['mining_job'] else '✗'}")
        
        if results['payout_addresses']:
            print(f"\n  Payout addresses found: {len(results['payout_addresses'])}")
            for payout in results['payout_addresses']:
                if not payout['address'].startswith('OP_RETURN'):
                    print(f"    • {payout['address']} ({payout['value_btc']:.8f} BTC)")
        
        # Save results
        output_file = 'pool_investigation.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[✓] Full results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\n\n[-] Investigation cancelled")
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
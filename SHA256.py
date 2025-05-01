def Preprocessing(password):
    bin_repr = ''.join(format(ord(char), '08b') for char in password)
    bin_repr += '1'
    
    while (len(bin_repr) + 64) % 512 != 0:
        bin_repr += '0'
    bin_repr += format(len(password) * 8, '064b')
    
    return bin_repr

def create_chunks(padded):
    chunks = [padded[i:i+512] for i in range(0, len(padded), 512)]
    nested_chunks = [[chunk[j:j+32] for j in range(0, len(chunk), 32)] for chunk in chunks]
    return nested_chunks


def generate_prime(limit):
    primes = []
    n = 2
    while len(primes) < limit:
        is_prime = all(n % i != 0 for i in range(2, int(n**0.5) + 1))
        if is_prime:
            primes.append(n)
        n += 1
    return primes

def fractional_to_binary(fractional_part, precision=32):
    binary_fraction = []
    while fractional_part and len(binary_fraction) < precision:
        fractional_part *= 2
        bit = int(fractional_part)
        binary_fraction.append(str(bit))
        fractional_part -= bit
    return "".join(binary_fraction).ljust(precision, '0')  


def create_h():
    primes = generate_prime(8)
    return [int(fractional_to_binary(i**0.5 - int(i**0.5)), 2) for i in primes]

def create_k():
    primes = generate_prime(64)
    return [int(fractional_to_binary(i**(1/3) - int(i**(1/3))), 2) for i in primes]


def rotate_right(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

def shift_right(value, bits):
    return value >> bits

def sigma0(w):
    if isinstance(w, str):
        w = int(w, 2)
    return rotate_right(w, 7) ^ rotate_right(w, 18) ^ shift_right(w, 3)

def sigma1(w):
    if isinstance(w, str):
        w = int(w, 2)
    return rotate_right(w, 17) ^ rotate_right(w, 19) ^ shift_right(w, 10)

def create_message(nested_chunks):
    final_w = []
    for chunk in nested_chunks:
        w = [chunk[i] if i < 16 else '0' * 32 for i in range(64)]  
        for i in range(16, 64):
            w_i_16 = int(w[i-16], 2) if isinstance(w[i-16], str) else w[i-16]
            w_i_15 = int(w[i-15], 2) if isinstance(w[i-15], str) else w[i-15]
            w_i_7 = int(w[i-7], 2) if isinstance(w[i-7], str) else w[i-7]
            w_i_2 = int(w[i-2], 2) if isinstance(w[i-2], str) else w[i-2]
            
            ans = (w_i_16 + sigma0(w_i_15) + w_i_7 + sigma1(w_i_2)) & 0xFFFFFFFF
            w[i] = format(ans, '032b')
        
        final_w.append(w)
    
    return final_w

def formula(w):
    h_values = create_h()
    k = create_k()
    w_int = [int(word, 2) if isinstance(word, str) else word for word in w]
    h = h_values.copy()
    
    for i in range(64):
        E1 = rotate_right(h[4], 6) ^ rotate_right(h[4], 11) ^ rotate_right(h[4], 25)
        ch = (h[4] & h[5]) ^ (~h[4] & h[6])
        T1 = (h[7] + E1 + ch + k[i] + w_int[i]) & 0xFFFFFFFF
        E0 = rotate_right(h[0], 2) ^ rotate_right(h[0], 13) ^ rotate_right(h[0], 22)
        maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2])
        T2 = (E0 + maj) & 0xFFFFFFFF
        
        h = [(T1 + T2) & 0xFFFFFFFF, h[0], h[1], h[2], 
             (h[3] + T1) & 0xFFFFFFFF, h[4], h[5], h[6]]
    
    return h

# Hash generation function
def create_hash(final_w):
    final_hash = ""
    
    for j in range(len(final_w)):
        h_initial = create_h()
        h_result = formula(final_w[j])
        
        for i in range(len(h_initial)):
            h_initial[i] = (h_initial[i] + h_result[i]) & 0xFFFFFFFF
        
        # Convert to hexadecimal string
        chunk_hash = ''.join(format(h_val, '08x') for h_val in h_initial)
        final_hash = chunk_hash  # Overwriting each chunk hash; could be improved for multi-chunk input
    
    return final_hash

# Main SHA-256 function
def sha256(password):
    preprocessed = Preprocessing(password)
    nested_chunks = create_chunks(preprocessed)
    w = create_message(nested_chunks)
    hash_result = create_hash(w)
    return hash_result
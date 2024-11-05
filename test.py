import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt

class RealisticAESTraceGenerator:
    def __init__(self, samples_per_cycle=50, noise_level=0.05):
        self.samples_per_cycle = samples_per_cycle
        self.noise_level = noise_level
        self.key = get_random_bytes(16)
        self.sbox = self._generate_aes_sbox()
        
    def _generate_aes_sbox(self):
        """Generate AES S-box lookup table"""
        # Pre-computed AES S-box
        sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        return np.array(sbox, dtype=np.uint8)

    def _add_round_key(self, state, round_key):
        """Simulate AddRoundKey operation based on bitwise transitions"""
        power_trace = []
        for i in range(16):
            xor_result = state[i] ^ round_key[i]
            bit_transitions = [int(b) for b in f"{xor_result:08b}"]  # Bitwise transitions
            power_trace.extend(self._generate_operation_samples(bit_transitions))
        return power_trace, bytes([state[i] ^ round_key[i] for i in range(16)])
        
    def _sub_bytes(self, state):
        """Simulate SubBytes operation based on bitwise transitions"""
        power_trace = []
        result = bytearray(16)
        for i in range(16):
            result[i] = self.sbox[state[i]]
            bit_transitions = [int(b) for b in f"{result[i]:08b}"]  # Bitwise representation
            power_trace.extend(self._generate_operation_samples(bit_transitions, amplitude=1.2))
        return power_trace, result

    def _shift_rows(self, state):
    
        # ShiftRows transformation
        shifted_state = bytearray(16)
        # Row 0 (no shift)
        shifted_state[0] = state[0]
        shifted_state[4] = state[4]
        shifted_state[8] = state[8]
        shifted_state[12] = state[12]
        # Row 1 (left shift by 1)
        shifted_state[1] = state[5]
        shifted_state[5] = state[9]
        shifted_state[9] = state[13]
        shifted_state[13] = state[1]
        # Row 2 (left shift by 2)
        shifted_state[2] = state[10]
        shifted_state[6] = state[14]
        shifted_state[10] = state[2]
        shifted_state[14] = state[6]
        # Row 3 (left shift by 3)
        shifted_state[3] = state[15]
        shifted_state[7] = state[3]
        shifted_state[11] = state[7]
        shifted_state[15] = state[11]
        
        return shifted_state

    def _mix_columns(self, state):
        """Simulate MixColumns operation"""
        def xtime(x):
            return ((x << 1) ^ 0x1B) & 0xFF if (x & 0x80) else (x << 1) & 0xFF

        mixed_state = bytearray(16)
        for col in range(4):
            a = state[col * 4: col * 4 + 4]
            b = [xtime(a[i]) for i in range(4)]
            
            mixed_state[col * 4 + 0] = (b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]) & 0xFF
            mixed_state[col * 4 + 1] = (b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]) & 0xFF
            mixed_state[col * 4 + 2] = (b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]) & 0xFF
            mixed_state[col * 4 + 3] = (b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]) & 0xFF

        return mixed_state


    def _generate_operation_samples(self, bit_transitions, amplitude=1.0, num_samples=None):
        """Generate samples based on bitwise transitions"""
        if num_samples is None:
            num_samples = self.samples_per_cycle
        
        # Bell curve to model power consumption
        x = np.linspace(-2, 2, num_samples)
        base_curve = np.exp(-x**2)

        # Apply bit-specific amplitudes and add noise
        power_curve = sum(amplitude * b * base_curve for b in bit_transitions)
        clock = 0.2 * np.sin(2 * np.pi * x)
        noise = np.random.normal(0, self.noise_level, num_samples)
        return power_curve + clock + noise
        
    def generate_trace(self, plaintext):
        """Generate a complete power trace for AES encryption"""
        full_trace = []
        state = plaintext

        # Initial AddRoundKey
        trace, state = self._add_round_key(state, self.key)
        full_trace.extend(trace)

        # 9 main rounds
        for round_num in range(9):
            trace, state = self._sub_bytes(state)
            full_trace.extend(trace)

            state = self._shift_rows(state)
            state = self._mix_columns(state)

            round_key = self.key  # Placeholder for actual round key
            trace, state = self._add_round_key(state, round_key)
            full_trace.extend(trace)

        # Final round (no MixColumns)
        trace, state = self._sub_bytes(state)
        full_trace.extend(trace)
        
        state = self._shift_rows(state)
        trace, state = self._add_round_key(state, self.key)  # Final key
        full_trace.extend(trace)

        return np.array(full_trace), state

# Sample usage
if __name__ == "__main__":
    generator = RealisticAESTraceGenerator(samples_per_cycle=1)
    plaintext = get_random_bytes(16)
    trace, _ = generator.generate_trace(plaintext)

    # Plot the generated trace
    plt.figure(figsize=(15, 5))
    plt.plot(trace)
    plt.title("Generated AES Trace with Bitwise Model for DoA")
    plt.xlabel("Sample Points")
    plt.ylabel("Power Consumption")
    plt.grid(True)
    plt.show()

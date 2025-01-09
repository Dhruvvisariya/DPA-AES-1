import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import os

class RealisticAESTraceGenerator:
    def __init__(self, samples_per_cycle=50, noise_level=0.05, amplitude_scale=1.0):
        self.samples_per_cycle = samples_per_cycle
        self.noise_level = noise_level
        self.amplitude_scale = amplitude_scale
        self.key = get_random_bytes(16)
        self.sbox = self._generate_aes_sbox()

    def _generate_aes_sbox(self):
        """Generate AES S-box lookup table"""
        # Pre-computed AES S-box
        sbox = np.array([
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
        ], dtype=np.uint8)
        return sbox

    def _add_round_key(self, state, round_key):
        """Simulate AddRoundKey operation and power consumption"""
        power_trace = []
        for i in range(16):
            # Power consumption from XOR operation
            xor_result = state[i] ^ round_key[i]
            # Model switching activity
            hamming_distance = bin(state[i] ^ xor_result).count('1')
            # Generate multiple sample points per operation
            power_trace.extend(self._generate_operation_samples(hamming_distance))
        return power_trace, bytes([state[i] ^ round_key[i] for i in range(16)])

    def _sub_bytes(self, state):
        """Simulate SubBytes operation and power consumption"""
        power_trace = []
        result = bytearray(16)
        for i in range(16):
            # Power from S-box lookup
            result[i] = self.sbox[state[i]]
            # Model memory access and data movement
            hamming_weight = bin(result[i]).count('1')
            power_trace.extend(self._generate_operation_samples(hamming_weight, amplitude=1.2 * self.amplitude_scale))
        return power_trace, result

    def _shift_rows(self, state):
        """Simulate ShiftRows operation and power consumption"""
        power_trace = []
        # Convert to matrix for shifting
        matrix = np.array(state).reshape(4, 4)
        for i in range(1, 4):
            matrix[i:] = np.roll(matrix[i:], -i, axis=1)
            # Model data movement power
            power_trace.extend(self._generate_operation_samples(0.5 * self.amplitude_scale))
        return power_trace, matrix.flatten()

    def _mix_columns(self, state):
        """Simulate MixColumns operation and power consumption"""
        power_trace = []
        result = bytearray(16)
        # Galois field multiplication lookup tables
        mul2 = lambda x: ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF
        mul3 = lambda x: mul2(x) ^ x

        for col in range(4):
            # Process each column
            c = state[4*col:4*(col+1)]
            result[4*col] = mul2(c[0]) ^ mul3(c[1]) ^ c[2] ^ c[3]
            result[4*col+1] = c[0] ^ mul2(c[1]) ^ mul3(c[2]) ^ c[3]
            result[4*col+2] = c[0] ^ c[1] ^ mul2(c[2]) ^ mul3(c[3])
            result[4*col+3] = mul3(c[0]) ^ c[1] ^ c[2] ^ mul2(c[3])

            # Model column mixing power consumption
            hamming_distance = sum(bin(x ^ y).count('1') for x, y in zip(c, result[4*col:4*(col+1)]))
            power_trace.extend(self._generate_operation_samples(hamming_distance, amplitude=1.5 * self.amplitude_scale))

        return power_trace, result

    def _generate_operation_samples(self, base_power, amplitude=1.0, num_samples=None):
        """Generate multiple samples for a single operation with realistic power profile."""
        if num_samples is None:
            num_samples = self.samples_per_cycle

        # Ensure consistent size for all arrays
        sample_count = num_samples * 2  # Double the samples for charging and discharging
        time = np.linspace(0, 1, num_samples)  # Normalized time within one clock cycle

        # Charging and discharging effects for capacitive load
        charging = base_power * (1 - np.exp(-5 * time))  # Exponential charging curve
        discharging = base_power * np.exp(-5 * time[::-1])  # Exponential discharging curve
        power_cycle = np.concatenate((charging, discharging))

        # Ensure `power_cycle` matches `sample_count`
        power_cycle = np.resize(power_cycle, sample_count)

        # Clock signal
        clock_amplitude = 0.2 * base_power
        clock = clock_amplitude * (np.sign(np.sin(2 * np.pi * 10 * np.linspace(0, 1, sample_count))) + 1)

        # Switching noise
        switching_frequency = 5 * num_samples
        switching_noise = 0.1 * base_power * np.sin(2 * np.pi * switching_frequency * np.linspace(0, 1, sample_count))

        # Random glitches
        glitch_probability = 0.1
        glitches = np.random.choice([0, 0.05 * base_power], size=sample_count, p=[1 - glitch_probability, glitch_probability])

        # Gaussian noise
        noise = np.random.normal(0, self.noise_level, sample_count)

        # Combine all components
        return power_cycle + clock + switching_noise + glitches + noise



    def generate_trace(self, plaintext):
        """Generate a complete power trace for AES encryption"""
        full_trace = []
        state = plaintext

        # Initial AddRoundKey
        trace, state = self._add_round_key(state, self.key)
        full_trace.extend(trace)

        # 10 main rounds
        for round_num in range(10):
            # SubBytes
            trace, state = self._sub_bytes(state)
            full_trace.extend(trace)

            # ShiftRows
            trace, state = self._shift_rows(state)
            full_trace.extend(trace)

            if round_num < 9:
                # MixColumns
                trace, state = self._mix_columns(state)
                full_trace.extend(trace)

            # AddRoundKey (with round key)
            round_key = self.key  # Simplified: should derive actual round key
            trace, state = self._add_round_key(state, round_key)
            full_trace.extend(trace)

        return np.array(full_trace), state

    def generate_traces(self, num_traces=100):
        """Generate multiple traces"""
        traces = []
        plaintexts = []
        ciphertexts = []

        for _ in range(num_traces):
            plaintext = get_random_bytes(16)
            trace, ciphertext = self.generate_trace(plaintext)
            traces.append(trace)
            plaintexts.append(plaintext)
            ciphertexts.append(ciphertext)

        return np.array(traces), np.array(plaintexts), np.array(ciphertexts)

def save_traces(traces, plaintexts, ciphertexts, key, base_filename):
    """Save traces in CSV format"""
    # Save traces
    trace_df = pd.DataFrame(traces)
    trace_df.to_csv(f'{base_filename}_traces300.csv', index=False)

    # Save metadata with hex values
    metadata = {
        'trace_id': range(len(traces)),
        'plaintext': [p.hex() for p in plaintexts],
        'ciphertext': [c.hex() for c in ciphertexts],
        'key': [key.hex()] * len(traces)
    }
    metadata_df = pd.DataFrame(metadata)
    metadata_df.to_csv(f'{base_filename}_metadata300.csv', index=False)

def visualize_trace(trace, title="Power Trace"):
    plt.figure(figsize=(15, 5))
    plt.plot(trace)
    plt.title(title)
    plt.xlabel('Sample Points')
    plt.ylabel('Power Consumption')
    plt.grid(True)
    plt.show()

def main():
    # Parameters
    num_traces = 1
    samples_per_cycle = 1
    noise_level = 0.05
    amplitude_scale = 2.0  

    # Create output directory
    if not os.path.exists('tracesasbook'):
        os.makedirs('tracesasbook')

    # Generate traces
    print("Generating realistic AES power traces...")
    generator = RealisticAESTraceGenerator(samples_per_cycle=samples_per_cycle, noise_level=noise_level, amplitude_scale=amplitude_scale)
    traces, plaintexts, ciphertexts = generator.generate_traces(num_traces)

    # Calculate total sample points
    points_per_trace = len(traces[0])
    print(f"\nTrace details:")
    print(f"Number of traces: {num_traces}")
    print(f"Sample points per trace: {points_per_trace}")
    print(f"Key used (hex): {generator.key.hex()}")

    # Save traces
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f'tracesasbook/aes_traces_{timestamp}'
    save_traces(traces, plaintexts, ciphertexts, generator.key, base_filename)

    # Visualize a single trace
    visualize_trace(traces[0], "Single AES Encryption Power Trace")

    print("\nFiles saved:")
    print(f"- Traces: {base_filename}_traces.csv")
    print(f"- Metadata: {base_filename}_metadata.csv")

if __name__ == "__main__":
    main()
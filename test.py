import numpy as np
import matplotlib.pyplot as plt
import csv
from Crypto.Random import get_random_bytes

# AES S-box for SubBytes step
S_BOX = [
    # Full S-box array, 256 entries
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

class AESPowerTraceGenerator:
    def __init__(self, key, num_rounds=10, samples_per_operation=10, noise_level=0.5):
        self.key = key
        self.num_rounds = num_rounds
        self.samples_per_operation = samples_per_operation
        self.noise_level = noise_level

    def _hamming_weight(self, byte):
        """Calculates the Hamming weight of a byte."""
        return bin(byte).count("1")

    def _generate_power_samples(self, hamming_value):
        """Generates power consumption samples for a given Hamming value."""
        base_power = np.ones(self.samples_per_operation) * hamming_value
        noise = np.random.normal(0, self.noise_level, self.samples_per_operation)
        return base_power + noise

    def _sub_bytes(self, state):
        """Simulates the SubBytes step using AES S-box."""
        transformed_state = np.copy(state)
        trace = []
        for i in range(len(state)):
            transformed_byte = S_BOX[state[i]]
            hamming_value = self._hamming_weight(transformed_byte)
            trace.extend(self._generate_power_samples(hamming_value))
            transformed_state[i] = transformed_byte
        return trace, transformed_state

    def _shift_rows(self, state):
        """Performs the ShiftRows step by shifting each row of the state array."""
        transformed_state = np.copy(state)
        trace = []

        # Shift rows (AES standard)
        transformed_state[1], transformed_state[5], transformed_state[9], transformed_state[13] = \
            transformed_state[5], transformed_state[9], transformed_state[13], transformed_state[1]
        transformed_state[2], transformed_state[6], transformed_state[10], transformed_state[14] = \
            transformed_state[10], transformed_state[14], transformed_state[2], transformed_state[6]
        transformed_state[3], transformed_state[7], transformed_state[11], transformed_state[15] = \
            transformed_state[15], transformed_state[3], transformed_state[7], transformed_state[11]

        # Add power consumption for ShiftRows
        for byte in transformed_state:
            hamming_value = self._hamming_weight(byte)
            trace.extend(self._generate_power_samples(hamming_value))

        return trace, transformed_state

    def _mix_columns(self, state):
        """Simulates the MixColumns transformation."""
        trace = []
        transformed_state = np.copy(state)

        # Simplified MixColumns without full GF(2^8) multiplication for realistic trace modeling
        for i in range(0, 16, 4):
            col = state[i:i+4]
            transformed_state[i] = col[0] ^ col[1]
            transformed_state[i+1] = col[1] ^ col[2]
            transformed_state[i+2] = col[2] ^ col[3]
            transformed_state[i+3] = col[3] ^ col[0]

            # Add power consumption for each mixed column byte
            for byte in transformed_state[i:i+4]:
                hamming_value = self._hamming_weight(byte)
                trace.extend(self._generate_power_samples(hamming_value))

        return trace, transformed_state

    def _add_round_key(self, state, round_key):
        """Simulates AddRoundKey."""
        trace = []
        for i in range(len(state)):
            hamming_value = self._hamming_weight(state[i] ^ round_key[i % len(round_key)])
            trace.extend(self._generate_power_samples(hamming_value))
        return trace

    def generate_trace(self, plaintext):
        """Generates a complete power trace for AES encryption."""
        state = np.frombuffer(plaintext, dtype=np.uint8)[:16]
        trace = []

        # Initial round: AddRoundKey
        trace.extend(self._add_round_key(state, self.key))

        # Main rounds with all steps
        for round_num in range(self.num_rounds - 1):
            sub_trace, state = self._sub_bytes(state)
            trace.extend(sub_trace)
            shift_trace, state = self._shift_rows(state)
            trace.extend(shift_trace)
            mix_trace, state = self._mix_columns(state)
            trace.extend(mix_trace)
            trace.extend(self._add_round_key(state, self.key))

        # Final round: SubBytes, ShiftRows, AddRoundKey
        sub_trace, state = self._sub_bytes(state)
        trace.extend(sub_trace)
        shift_trace, state = self._shift_rows(state)
        trace.extend(shift_trace)
        trace.extend(self._add_round_key(state, self.key))

        return np.array(trace)

    def generate_traces(self, num_traces):
        """Generates multiple traces with random plaintexts."""
        traces = []
        for _ in range(num_traces):
            plaintext = get_random_bytes(16)
            trace = self.generate_trace(plaintext)
            traces.append(trace)
        return np.array(traces)

    def save_traces_to_csv(self, traces, filename="power_traces.csv"):
        """Saves traces to a CSV file."""
        with open(filename, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerows(traces)

    def plot_trace(self, trace, title="AES Power Trace"):
        """Plots a single power trace."""
        plt.figure(figsize=(12, 6))
        plt.plot(trace, color='blue', linewidth=0.5)
        plt.title(title)
        plt.xlabel("Sample Index")
        plt.ylabel("Power Consumption")
        plt.show()

# Example usage
key = np.random.randint(0, 256, size=16, dtype=np.uint8)
trace_generator = AESPowerTraceGenerator(key, num_rounds=10, samples_per_operation=100, noise_level=0.5)

# Generate traces and save to CSV
num_traces = 1
traces = trace_generator.generate_traces(num_traces)
trace_generator.save_traces_to_csv(traces, filename="aes_power_traces.csv")

# Plot a sample trace
trace_generator.plot_trace(traces[0], title="Sample AES Power Trace with S-Box, ShiftRows, and MixColumns")

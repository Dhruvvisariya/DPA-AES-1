import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt

class RealisticAESTraceGenerator:
    def __init__(self, samples_per_cycle=100, noise_level=0.02):
        self.samples_per_cycle = samples_per_cycle
        self.noise_level = noise_level
        self.key = get_random_bytes(16)
        self.round_keys = self._expand_key(self.key)

    @staticmethod
    def _expand_key(key):
        """Expand the AES key into round keys for all rounds."""
        return [key] * 11  # Placeholder for round keys

    def _generate_clock_waveform(self, power_level, num_cycles):
        """Generate a clock-based waveform with oscillations around zero."""
        trace = []
        for _ in range(num_cycles):
            # Create a centered sinusoidal waveform to oscillate around zero
            x = np.linspace(0, 2 * np.pi, self.samples_per_cycle)
            baseline = np.random.normal(0, self.noise_level)  # Small random baseline offset
            base_wave = power_level * np.sin(x) + baseline  # Oscillate around zero
            noise = np.random.normal(0, self.noise_level, self.samples_per_cycle)
            trace.extend(base_wave + noise)
        return trace

    def _add_round_key(self, state, round_key):
        """Simulate AddRoundKey operation with small power variations per byte."""
        trace = []
        for byte in state:
            power_level = 1.0 + 0.05 * np.random.randn()  # Small random variation
            trace.extend(self._generate_clock_waveform(power_level, 1))
        return trace

    def _sub_bytes(self, state):
        """Simulate SubBytes operation with small power variations per byte."""
        trace = []
        for byte in state:
            power_level = 1.2 + 0.05 * np.random.randn()
            trace.extend(self._generate_clock_waveform(power_level, 1))
        return trace

    def _shift_rows(self, state):
        """Simulate ShiftRows operation with small power variations per byte."""
        trace = []
        for byte in state:
            power_level = 1.1 + 0.05 * np.random.randn()
            trace.extend(self._generate_clock_waveform(power_level, 1))
        return trace

    def _mix_columns(self, state):
        """Simulate MixColumns operation with small power variations per byte."""
        trace = []
        for byte in state:
            power_level = 1.3 + 0.05 * np.random.randn()
            trace.extend(self._generate_clock_waveform(power_level, 1))
        return trace

    def generate_trace(self, plaintext):
        """Generate a complete power trace for an AES encryption process with realistic cycles."""
        trace = []
        state = bytearray(plaintext)

        # Initial round: AddRoundKey
        trace.extend(self._add_round_key(state, self.round_keys[0]))

        # Main rounds: 9 rounds with all four operations
        for round_num in range(1, 10):
            trace.extend(self._sub_bytes(state))
            trace.extend(self._shift_rows(state))
            trace.extend(self._mix_columns(state))
            trace.extend(self._add_round_key(state, self.round_keys[round_num]))

        # Final round: SubBytes, ShiftRows, AddRoundKey
        trace.extend(self._sub_bytes(state))
        trace.extend(self._shift_rows(state))
        trace.extend(self._add_round_key(state, self.round_keys[10]))

        return np.array(trace)

# Sample usage
if __name__ == "__main__":
    generator = RealisticAESTraceGenerator(samples_per_cycle=4)
    plaintext = get_random_bytes(16)
    trace = generator.generate_trace(plaintext)

    plt.figure(figsize=(15, 5))
    plt.plot(trace)
    plt.title("Realistic AES Power Trace with Centered Oscillations")
    plt.xlabel("Sample Points")
    plt.ylabel("Power Consumption (Arbitrary Units)")
    plt.grid(True)
    plt.show()

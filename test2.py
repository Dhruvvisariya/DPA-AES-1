import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

@dataclass
class TraceMetadata:
    """Stores metadata for each power trace"""
    plaintext: bytes
    key: bytes
    timestamp: float
    trace_length: int

class EnhancedAESPowerTraceGenerator:
    """Enhanced power trace generator with realistic modeling for DPA"""
    
    NUM_BYTES = 16
    STATE_SIZE = 4
    SBOX = np.array([
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
    
    def __init__(
        self,
        key: bytes,
        num_rounds: int = 10,
        samples_per_operation: int = 1000,  # Increased for better resolution
        noise_level: float = 0.3,
        include_transitions: bool = True,
        jitter_range: float = 0.1
    ):
        if len(key) != self.NUM_BYTES:
            raise ValueError(f"Key must be {self.NUM_BYTES} bytes long")
            
        self.key = np.frombuffer(key, dtype=np.uint8)
        self.num_rounds = num_rounds
        self.samples_per_operation = samples_per_operation
        self.noise_level = noise_level
        self.include_transitions = include_transitions
        self.jitter_range = jitter_range
        self.cipher = AES.new(key, AES.MODE_ECB)
        
    def _hamming_distance(self, state1: np.ndarray, state2: np.ndarray) -> np.ndarray:
        """Calculate Hamming distance between two states"""
        xor_result = np.bitwise_xor(state1, state2)
        return np.array([bin(x).count("1") for x in xor_result])
    
    def _add_jitter(self, samples: np.ndarray) -> np.ndarray:
        """Add timing jitter to samples"""
        jitter = np.random.uniform(-self.jitter_range, self.jitter_range, len(samples))
        return samples + jitter
    
    def _generate_power_samples(self, current_state: np.ndarray, previous_state: np.ndarray) -> np.ndarray:
        """Generate enhanced power samples including state transitions"""
        # Static power based on Hamming weight
        hw_current = np.array([bin(x).count("1") for x in current_state])
        static_power = np.mean(hw_current)
        
        # Dynamic power based on Hamming distance
        if self.include_transitions and previous_state is not None:
            hd = self._hamming_distance(current_state, previous_state)
            dynamic_power = np.mean(hd)
        else:
            dynamic_power = 0
            
        # Combined power model
        base_power = static_power + (2 * dynamic_power)  # Dynamic power typically has more impact
        
        # Generate samples with noise and jitter
        samples = np.random.normal(base_power, self.noise_level, self.samples_per_operation)
        samples = self._add_jitter(samples)
        
        return samples
    
    def generate_trace(self, plaintext: bytes) -> Tuple[np.ndarray, TraceMetadata]:
        """Generate a complete power trace for single encryption"""
        if len(plaintext) != self.NUM_BYTES:
            raise ValueError(f"Plaintext must be {self.NUM_BYTES} bytes long")
        
        state = np.frombuffer(plaintext, dtype=np.uint8)
        previous_state = None
        trace = []
        
        # Generate trace for first round (focus area for DPA)
        # Add round key
        state = np.bitwise_xor(state, self.key)
        trace.extend(self._generate_power_samples(state, previous_state))
        previous_state = state.copy()
        
        # SubBytes - main target for DPA
        state = self.SBOX[state]
        trace.extend(self._generate_power_samples(state, previous_state))
        
        # Complete the encryption (simplified for DPA focus)
        # In real DPA we mainly care about the first round
        remaining_trace = self._generate_power_samples(state, previous_state)
        trace.extend(remaining_trace)
        
        trace_array = np.array(trace)
        metadata = TraceMetadata(
            plaintext=plaintext,
            key=self.key.tobytes(),
            timestamp=np.datetime64('now').astype(float),
            trace_length=len(trace_array)
        )
        
        return trace_array, metadata

    def generate_traces(
        self,
        num_traces: int,
        save_path: Optional[Path] = None
    ) -> Tuple[np.ndarray, List[TraceMetadata]]:
        """Generate multiple traces with random plaintexts"""
        traces = []
        metadata_list = []
        
        print(f"Generating {num_traces} traces...")
        for i in range(num_traces):
            if i % 100 == 0:  # Print progress every 100 traces
                print(f"Progress: {i}/{num_traces}")
            plaintext = get_random_bytes(self.NUM_BYTES)
            trace, metadata = self.generate_trace(plaintext)
            traces.append(trace)
            metadata_list.append(metadata)
        
        traces_array = np.array(traces)
        
        if save_path:
            self._save_data(traces_array, metadata_list, save_path)
            
        return traces_array, metadata_list

class DPAAttack:
    """Implements Differential Power Analysis attack"""
    
    def __init__(self, traces: np.ndarray, plaintexts: List[bytes], target_byte: int = 0):
        self.traces = traces
        self.plaintexts = [np.frombuffer(p, dtype=np.uint8) for p in plaintexts]
        self.target_byte = target_byte
        self.num_traces = len(traces)
        
    def _selection_function(self, plaintext_byte: int, key_guess: int) -> int:
        """Selection function targeting first round SBox output"""
        return bin(EnhancedAESPowerTraceGenerator.SBOX[plaintext_byte ^ key_guess]).count("1")
    
    def attack_byte(self) -> Tuple[int, np.ndarray]:
        """Perform DPA attack on target byte"""
        max_difference = -1
        best_key_guess = -1
        differences = np.zeros(256)
        
        print("Starting DPA attack...")
        for key_guess in range(256):
            if key_guess % 32 == 0:  # Print progress every 32 guesses
                print(f"Testing key guesses: {key_guess}/256")
                
            # Split traces based on selection function
            group_0 = []
            group_1 = []
            
            for i in range(self.num_traces):
                plaintext_byte = self.plaintexts[i][self.target_byte]
                if self._selection_function(plaintext_byte, key_guess) > 4:  # Threshold at middle of Hamming weight
                    group_1.append(self.traces[i])
                else:
                    group_0.append(self.traces[i])
            
            # Calculate difference of means
            mean_0 = np.mean(group_0, axis=0) if group_0 else np.zeros_like(self.traces[0])
            mean_1 = np.mean(group_1, axis=0) if group_1 else np.zeros_like(self.traces[0])
            difference = np.max(np.abs(mean_1 - mean_0))
            
            differences[key_guess] = difference
            if difference > max_difference:
                max_difference = difference
                best_key_guess = key_guess
        
        return best_key_guess, differences

def run_dpa_example():
    """Run complete DPA attack example"""
    # Generate traces
    print("Initializing DPA attack example...")
    key = get_random_bytes(16)
    generator = EnhancedAESPowerTraceGenerator(
        key=key,
        samples_per_operation=1000,
        noise_level=0.3,
        include_transitions=True
    )
    
    # Generate 1000 traces for the attack
    print("Generating power traces...")
    traces, metadata = generator.generate_traces(1000)
    plaintexts = [meta.plaintext for meta in metadata]
    
    # Perform DPA attack
    print("Performing DPA attack...")
    dpa = DPAAttack(traces, plaintexts, target_byte=0)
    recovered_byte, differences = dpa.attack_byte()
    
    # Plot results
    plt.figure(figsize=(12, 6))
    plt.plot(differences)
    plt.title("DPA Results - Difference of Means")
    plt.xlabel("Key Guess")
    plt.ylabel("Maximum Difference")
    plt.grid(True)
    
    print(f"Actual key byte: {key[0]}")
    print(f"Recovered key byte: {recovered_byte}")
    print(f"Attack {'successful' if key[0] == recovered_byte else 'failed'}")
    
    plt.show()

if __name__ == "__main__":
    run_dpa_example()
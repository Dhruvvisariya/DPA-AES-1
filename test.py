import numpy as np
import matplotlib.pyplot as plt
import csv
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass
from Crypto.Random import get_random_bytes

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

@dataclass
class TraceMetadata:
    """Stores metadata for each power trace"""
    plaintext: bytes
    key: bytes
    timestamp: float
    trace_length: int

class AESPowerTraceGenerator:
    """Generates power consumption traces for AES encryption operations"""
    
    # Class-level constants
    NUM_BYTES = 16
    STATE_SIZE = 4
    
    def __init__(
        self, 
        key: bytes,
        num_rounds: int = 10,
        samples_per_operation: int = 10,
        noise_level: float = 0.5
    ):
        """
        Initialize the AES Power Trace Generator
        
        Args:
            key: 16-byte encryption key
            num_rounds: Number of AES rounds
            samples_per_operation: Number of samples per operation
            noise_level: Standard deviation of Gaussian noise
        
        Raises:
            ValueError: If key length is not 16 bytes or parameters are invalid
        """
        if len(key) != self.NUM_BYTES:
            raise ValueError(f"Key must be {self.NUM_BYTES} bytes long")
        if num_rounds < 1:
            raise ValueError("Number of rounds must be positive")
        if samples_per_operation < 1:
            raise ValueError("Samples per operation must be positive")
        if noise_level < 0:
            raise ValueError("Noise level must be non-negative")
            
        self.key = np.frombuffer(key, dtype=np.uint8)
        self.num_rounds = num_rounds
        self.samples_per_operation = samples_per_operation
        self.noise_level = noise_level
        self._initialize_sbox()

    def _initialize_sbox(self) -> None:
        """Initialize S-box as numpy array for better performance"""
        self.s_box = np.array(S_BOX, dtype=np.uint8)

    @staticmethod
    def _hamming_weight(byte: int) -> int:
        """
        Calculate the Hamming weight (number of 1s) in a byte
        
        Args:
            byte: Input byte
        Returns:
            Number of 1s in binary representation
        """
        return bin(byte).count("1")

    def _generate_power_samples(self, hamming_value: int) -> np.ndarray:
        """
        Generate power consumption samples for a given Hamming weight
        
        Args:
            hamming_value: Hamming weight of the byte
        Returns:
            Array of power samples with noise
        """
        base_power = np.full(self.samples_per_operation, hamming_value, dtype=np.float32)
        noise = np.random.normal(0, self.noise_level, self.samples_per_operation)
        return base_power + noise

    def _sub_bytes(self, state: np.ndarray) -> Tuple[List[float], np.ndarray]:
        """
        Perform SubBytes transformation using vectorized operations
        
        Args:
            state: Current state array
        Returns:
            Tuple of (power trace, transformed state)
        """
        transformed_state = self.s_box[state]
        hamming_values = np.array([self._hamming_weight(byte) for byte in transformed_state])
        trace = []
        for hw in hamming_values:
            trace.extend(self._generate_power_samples(hw))
        return trace, transformed_state

    def _shift_rows(self, state: np.ndarray) -> Tuple[List[float], np.ndarray]:
        """
        Perform ShiftRows transformation using matrix operations
        
        Args:
            state: Current state array
        Returns:
            Tuple of (power trace, transformed state)
        """
        # Reshape to 4x4 matrix for easier shifting
        matrix = state.reshape(self.STATE_SIZE, self.STATE_SIZE)
        
        # Perform row shifts
        for i in range(1, self.STATE_SIZE):
            matrix[i] = np.roll(matrix[i], -i)
            
        transformed_state = matrix.flatten()
        
        # Generate power traces
        trace = []
        for byte in transformed_state:
            trace.extend(self._generate_power_samples(self._hamming_weight(byte)))
            
        return trace, transformed_state

    def _mix_columns(self, state: np.ndarray) -> Tuple[List[float], np.ndarray]:
        """
        Perform MixColumns transformation with improved matrix operations
        
        Args:
            state: Current state array
        Returns:
            Tuple of (power trace, transformed state)
        """
        transformed_state = np.copy(state)
        trace = []
        
        # Process each column
        for i in range(0, self.NUM_BYTES, self.STATE_SIZE):
            col = state[i:i + self.STATE_SIZE]
            # Improved mixing using circular XOR
            transformed_state[i:i + self.STATE_SIZE] = np.roll(col, 1) ^ col
            
            for byte in transformed_state[i:i + self.STATE_SIZE]:
                trace.extend(self._generate_power_samples(self._hamming_weight(byte)))
                
        return trace, transformed_state

    def generate_trace(self, plaintext: bytes) -> Tuple[np.ndarray, TraceMetadata]:
        """
        Generate a complete power trace for AES encryption
        
        Args:
            plaintext: 16-byte plaintext
        Returns:
            Tuple of (power trace array, trace metadata)
        
        Raises:
            ValueError: If plaintext length is invalid
        """
        if len(plaintext) != self.NUM_BYTES:
            raise ValueError(f"Plaintext must be {self.NUM_BYTES} bytes long")
            
        state = np.frombuffer(plaintext, dtype=np.uint8)
        trace = []
        
        # Initial round
        trace.extend(self._add_round_key(state, self.key))
        
        # Main rounds
        for _ in range(self.num_rounds - 1):
            sub_trace, state = self._sub_bytes(state)
            trace.extend(sub_trace)
            shift_trace, state = self._shift_rows(state)
            trace.extend(shift_trace)
            mix_trace, state = self._mix_columns(state)
            trace.extend(mix_trace)
            trace.extend(self._add_round_key(state, self.key))
            
        # Final round
        sub_trace, state = self._sub_bytes(state)
        trace.extend(sub_trace)
        shift_trace, state = self._shift_rows(state)
        trace.extend(shift_trace)
        trace.extend(self._add_round_key(state, self.key))
        
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
        """
        Generate multiple traces with random plaintexts
        
        Args:
            num_traces: Number of traces to generate
            save_path: Optional path to save traces
        Returns:
            Tuple of (traces array, list of metadata)
        """
        traces = []
        metadata_list = []
        
        for _ in range(num_traces):
            plaintext = get_random_bytes(self.NUM_BYTES)
            trace, metadata = self.generate_trace(plaintext)
            traces.append(trace)
            metadata_list.append(metadata)
            
        traces_array = np.array(traces)
        
        if save_path:
            self.save_traces(traces_array, metadata_list, save_path)
            
        return traces_array, metadata_list

    def save_traces(
        self,
        traces: np.ndarray,
        metadata: List[TraceMetadata],
        save_path: Path
    ) -> None:
        """
        Save traces and metadata to files
        
        Args:
            traces: Array of power traces
            metadata: List of trace metadata
            save_path: Path to save directory
        """
        save_path = Path(save_path)
        save_path.mkdir(parents=True, exist_ok=True)
        
        # Save traces
        np.save(save_path / "traces.npy", traces)
        
        # Save metadata
        with open(save_path / "metadata.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["plaintext", "key", "timestamp", "trace_length"])
            for meta in metadata:
                writer.writerow([
                    meta.plaintext.hex(),
                    meta.key.hex(),
                    meta.timestamp,
                    meta.trace_length
                ])

    def plot_trace(
        self,
        trace: np.ndarray,
        title: str = "AES Power Trace",
        save_path: Optional[Path] = None
    ) -> None:
        """
        Plot a single power trace
        
        Args:
            trace: Power trace array
            title: Plot title
            save_path: Optional path to save plot
        """
        plt.figure(figsize=(12, 6))
        plt.plot(trace, color='blue', linewidth=0.5)
        plt.title(title)
        plt.xlabel("Sample Index")
        plt.ylabel("Power Consumption (normalized)")
        plt.grid(True, alpha=0.3)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()

# Example usage
if __name__ == "__main__":
    # Generate random key
    key = get_random_bytes(16)
    
    # Create generator
    trace_generator = AESPowerTraceGenerator(
        key=key,
        num_rounds=10,
        samples_per_operation=100,
        noise_level=0.5
    )
    
    # Generate and save traces
    save_dir = Path("power_traces")
    traces, metadata = trace_generator.generate_traces(
        num_traces=10,
        save_path=save_dir
    )
    
    # Plot first trace
    trace_generator.plot_trace(
        traces[0],
        title="Sample AES Power Trace",
        save_path=save_dir / "sample_trace.png"
    )
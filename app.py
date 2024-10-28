import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
import h5py
import pandas as pd
from datetime import datetime
import os

class AESTraceGenerator:
    def __init__(self, noise_level=0.1):
        self.noise_level = noise_level
        self.key = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        
    def hamming_weight(self, byte_value):
        """Calculate Hamming weight of a byte"""
        return bin(byte_value).count('1')
    
    def generate_single_trace(self, plaintext):
        """Generate a single power trace"""
        ciphertext = self.cipher.encrypt(plaintext)
        trace = []
        
        # Generate trace points for each operation
        for byte in plaintext + ciphertext:
            power = self.hamming_weight(byte)
            power *= 1.2
            trace.extend([power * 0.8, power, power * 0.9])
            
        trace = np.array(trace)
        noise = np.random.normal(0, self.noise_level, len(trace))
        return trace + noise, ciphertext
    
    def generate_traces(self, num_traces=100):
        """Generate multiple traces with random plaintexts"""
        traces = []
        plaintexts = []
        ciphertexts = []
        
        for _ in range(num_traces):
            plaintext = get_random_bytes(16)
            trace, ciphertext = self.generate_single_trace(plaintext)
            traces.append(trace)
            plaintexts.append(plaintext)
            ciphertexts.append(ciphertext)
            
        return np.array(traces), np.array(plaintexts), np.array(ciphertexts)

def save_traces_all_formats(traces, plaintexts, ciphertexts, key):
    """Save traces in multiple formats: NPZ, HDF5, and CSV"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if not os.path.exists('power_traces'):
        os.makedirs('power_traces')
    
    base_filename = f'power_traces/aes_traces_{timestamp}'
    
    # 1. Save as NPZ (NumPy format)
    np.savez(f'{base_filename}.npz',
             traces=traces,
             plaintexts=plaintexts,
             ciphertexts=ciphertexts,
             key=key)
    print(f"Traces saved in NPZ format: {base_filename}.npz")
    
    # 2. Save as HDF5
    with h5py.File(f'{base_filename}.h5', 'w') as f:
        f.create_dataset('traces', data=traces)
        f.create_dataset('plaintexts', data=plaintexts)
        f.create_dataset('ciphertexts', data=ciphertexts)
        f.create_dataset('key', data=key)
    print(f"Traces saved in HDF5 format: {base_filename}.h5")
    
    # 3. Save as CSV (in multiple files for better organization)
    # 3.1 Save traces
    trace_df = pd.DataFrame(traces)
    trace_df.to_csv(f'{base_filename}_traces.csv', index=False)
    
    # 3.2 Save metadata (plaintexts, ciphertexts, and key)
    metadata = {
        'trace_id': range(len(traces)),
        'plaintext': [p.hex() for p in plaintexts],
        'ciphertext': [c.hex() for c in ciphertexts]
    }
    metadata_df = pd.DataFrame(metadata)
    metadata_df.to_csv(f'{base_filename}_metadata.csv', index=False)
    
    # 3.3 Save key separately
    with open(f'{base_filename}_key.txt', 'w') as f:
        f.write(f"Key (hex): {key.hex()}\n")
    
    print(f"Traces and metadata saved in CSV format:")
    print(f"- Traces: {base_filename}_traces.csv")
    print(f"- Metadata: {base_filename}_metadata.csv")
    print(f"- Key: {base_filename}_key.txt")

def visualize_traces(traces, num_traces_to_plot=5):
    """Visualize power traces"""
    plt.figure(figsize=(15, 10))
    
    # Plot full traces
    plt.subplot(2, 1, 1)
    for i in range(min(num_traces_to_plot, len(traces))):
        plt.plot(traces[i], alpha=0.7, label=f'Trace {i+1}')
    plt.title('Power Consumption Traces')
    plt.xlabel('Sample Point')
    plt.ylabel('Power Consumption')
    plt.legend()
    plt.grid(True)
    
    # Plot zoomed section
    plt.subplot(2, 1, 2)
    for i in range(min(num_traces_to_plot, len(traces))):
        plt.plot(traces[i][:100], alpha=0.7, label=f'Trace {i+1}')
    plt.title('Zoomed First 100 Sample Points')
    plt.xlabel('Sample Point')
    plt.ylabel('Power Consumption')
    plt.grid(True)
    
    plt.tight_layout()
    
    # Save the plot
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plt.savefig(f'power_traces/trace_visualization_{timestamp}.png')
    plt.close()

def main():
    # Set parameters
    num_traces = 100  # You can adjust this
    
    # Generate traces
    print("Generating AES power traces...")
    generator = AESTraceGenerator(noise_level=0.1)
    traces, plaintexts, ciphertexts = generator.generate_traces(num_traces)
    
    # Print information
    print(f"\nGenerated {len(traces)} traces")
    print(f"Each trace has {len(traces[0])} sample points")
    print(f"Key used (hex): {generator.key.hex()}")
    
    # Save in all formats
    save_traces_all_formats(traces, plaintexts, ciphertexts, generator.key)
    
    # Create visualization
    print("\nCreating visualization...")
    visualize_traces(traces)
    print("Visualization saved in power_traces directory")
    
    # Print statistical summary
    print("\nTrace Statistics:")
    print(f"Mean power value: {np.mean(traces):.3f}")
    print(f"Standard deviation: {np.std(traces):.3f}")
    print(f"Min value: {np.min(traces):.3f}")
    print(f"Max value: {np.max(traces):.3f}")

if __name__ == "__main__":
    main()
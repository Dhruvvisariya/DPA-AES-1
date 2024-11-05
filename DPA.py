import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Load data
traces = np.loadtxt('power_traces/aes_traces_20241104_005854_traces.csv', delimiter=',')
metadata = pd.read_csv('power_traces/aes_traces_20241104_005854_metadata.csv')
plaintexts = np.array([bytes.fromhex(pt) for pt in metadata['plaintext']])
# Assuming key is not needed for the analysis since we are guessing
key_byte_guess_range = range(256)  # 0 to 255 for 1-byte key guesses

# Perform DPA using DoA on a single key byte based on AddRoundKey
def dpa_doa_add_round_key(traces, plaintexts, key_byte_index=0):
    num_traces, num_samples = traces.shape
    max_diffs = np.zeros(len(key_byte_guess_range))

    for guess in key_byte_guess_range:
        set_0, set_1 = [], []

        # Divide traces into sets based on the outcome of the AddRoundKey operation
        for trace_idx, plaintext in enumerate(plaintexts):
            # Compute intermediate value: AddRoundKey = plaintext XOR guessed key byte
            intermediate_value = plaintext[key_byte_index] ^ guess
            
            # Debugging: Print intermediate values
            #print(f"Trace {trace_idx}, Plaintext: {plaintext.hex()}, Guess: {guess}, Intermediate: {intermediate_value:02x}")

            # Use the most significant bit (MSB) to categorize traces
            if intermediate_value & 0x80:  # Check the MSB of the intermediate value
                set_1.append(traces[trace_idx])
            else:
                set_0.append(traces[trace_idx])

        # Check if sets are populated
        print(f"Set 0 size: {len(set_0)}, Set 1 size: {len(set_1)}")

        # Compute means and difference of averages
        mean_set_0 = np.mean(set_0, axis=0) if set_0 else np.zeros(num_samples)
        #print(mean_set_0)
        mean_set_1 = np.mean(set_1, axis=0) if set_1 else np.zeros(num_samples)
        #print(mean_set_1)
        max_diffs[guess] = np.max(np.abs(mean_set_1 - mean_set_0))

    # Key byte guess with the highest correlation
    best_guess = np.argmax(max_diffs)
    print(f"Best guess for key byte {key_byte_index}: {best_guess}")

    return best_guess, max_diffs

# Run DPA on the first key byte
best_guess, diffs = dpa_doa_add_round_key(traces, plaintexts, key_byte_index=0)

# Plot difference of averages
plt.plot(diffs)
plt.xlabel("Key Byte Guess")
plt.ylabel("Max Difference of Averages")
plt.title("DPA Difference of Averages for AddRoundKey - Key Byte 0")
plt.grid()
plt.show()

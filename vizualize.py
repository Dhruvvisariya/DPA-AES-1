import pandas as pd
import matplotlib.pyplot as plt

class AESTraceVisualizer:
    def __init__(self, traces_file):
        self.traces_file = traces_file

    def visualize_trace(self, trace_id):
        """Load and visualize a single trace given its trace_id."""
        trace = pd.read_csv(self.traces_file, skiprows=trace_id + 1, nrows=1, header=None)
        plt.figure(figsize=(15, 5))
        plt.plot(trace.values[0])
        plt.title(f"Power Trace {trace_id}")
        plt.xlabel('Sample Points')
        plt.ylabel('Power Consumption')
        plt.grid(True)
        plt.show()

def main():
    # File paths
    traces_file = r'power_traces\aes_traces_20241107_101711_traces.csv' 

    # Create visualizer
    visualizer = AESTraceVisualizer(traces_file)

    # Visualize a specific trace
    trace_id = 100 # Change this to visualize a different trace
    visualizer.visualize_trace(trace_id)

if __name__ == "__main__":
    main()

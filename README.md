### ReadMe for GitHub Repository

# Cryptanalysis Using Differential Power Analysis on AES

## Overview
This repository contains the implementation of Differential Power Analysis (DPA) attacks on the Advanced Encryption Standard (AES). The project demonstrates how side-channel information, specifically power consumption patterns, can be exploited to recover cryptographic keys. This repository is part of a BTech project submitted to the University of Allahabad, focusing on cryptanalysis through Differential Power Analysis.

## Features
- **Synthetic Power Trace Generation**: Implements a model to simulate power traces incorporating factors like noise, clock signal effects, and CMOS switching characteristics.
- **Differential Power Analysis**: Uses statistical methods such as the Difference of Means (DoM) to extract the first byte of the AES encryption key.
- **AES Encryption Model**: Simulates the encryption process to analyze vulnerabilities.
- **Custom Trace Simulation**: Generates realistic traces using a Hamming Distance-based model for cryptographic operations.

## Project Details
- **Author**: Dhruv Visariya
- **Supervisor**: Prof. Rajneesh Kumar Srivastav
- **Institution**: University of Allahabad
- **Timeframe**: July 2024 - December 2024

## Table of Contents
1. [Introduction](#introduction)
2. [Methodology](#methodology)
3. [Setup](#setup)
4. [Usage](#usage)
5. [Experimental Results](#experimental-results)
6. [Future Work](#future-work)
7. [References](#references)

## Introduction
Cryptographic devices ensure secure communication but are susceptible to side-channel attacks. This project focuses on Differential Power Analysis (DPA), a non-invasive technique leveraging power consumption to deduce encryption keys. The target algorithm is AES, one of the most widely used cryptographic standards.

## Methodology
1. **Power Trace Simulation**:
   - Models the power consumption of CMOS circuits during AES encryption.
   - Considers noise, glitches, clock effects, and other physical parameters.
   - Uses Hamming Distance to simulate intermediate state transitions.
2. **DPA Attack**:
   - Applies the DoM method on generated traces to identify key-dependent correlations.
   - Analyzes synthetic power traces to extract the first byte of the AES key.

## Setup
### Requirements
- Python 3.7 or higher
- Libraries: `numpy`, `matplotlib`, `scipy`
- Optional: Hardware setup for real trace collection (oscilloscope, microcontroller, etc.)

### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/dpa-attack-aes.git
   cd dpa-attack-aes
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. **Generate Power Traces**:
   Run the script to generate synthetic power traces:
   ```bash
   python generate_traces.py
   ```
2. **Perform DPA**:
   Execute the DPA attack using the generated traces:
   ```bash
   python dpa_attack.py
   ```
3. **Visualize Results**:
   Use the provided scripts to plot power traces and statistical results.

![asperbook_trace1](https://github.com/user-attachments/assets/156a91ce-5eac-4900-b60a-cabbe993d5d2)

## Experimental Results
- The attack was successful in recovering the first byte of the AES key with 500 traces.
- Key observations:
  - 100 and 300 traces were insufficient due to noise dominance.

### 100: <img width="851" alt="AsperbookDPA100" src="https://github.com/user-attachments/assets/a5c08c69-63bf-47d2-98c5-45f591b70c25" />
### 300: <img width="741" alt="AsperbookDPA300" src="https://github.com/user-attachments/assets/9e817585-7694-44ca-a42d-71e40fd1a042" />
### 500:<img width="853" alt="AsperbookDPA500" src="https://github.com/user-attachments/assets/e5f824af-4666-4d51-8552-0f15d96e0dd6" />

 - Increasing the number of traces averaged out noise and improved statistical precision.

## Future Work
- **Real-World Implementation**: Perform DPA on hardware setups using real power traces.
- **Enhanced Models**: Incorporate temperature variations, clock jitter, and interconnect delays in synthetic trace generation.
- **Countermeasures**:
  - Masking techniques
  - Power equalization
  - Noise injection

## References
1. Mangard, S., Oswald, E., & Popp, T. *Power Analysis Attacks: Revealing the Secrets of Smart Cards*. Springer, 2007.
2. Lo, O., Buchanan, W. J., & Carson, D. *Power analysis attacks on the AES-128 S-box using differential power analysis (DPA)*. *Journal of Cyber Security Technology*, 2016.
3. Standaert, François-Xavier. *Introduction to Side-Channel Attacks*. Springer, 2010.

For detailed methodology and results, refer to the project report.

---

import subprocess
import datetime
import os
import json
import time

# Function to run the benchmark
def run_benchmark(num_variables):
    # Construct the command to run benchmark.rs
    command = ['./target/release/benchmark', '-d', str(num_variables)]
    process = subprocess.Popen(command)
    process.wait()  # Wait for the process to finish

# Function to read the JSON output
def read_benchmark_output():
    with open('outputs/bench_output.json', 'r') as f:
        return json.load(f)

# Function to convert prover time to milliseconds
def convert_prover_time(prover_time):
    secs = prover_time['secs']
    nanos = prover_time['nanos']
    return secs * 1000 + nanos / 1000000

# Main function to execute benchmarks for different variable counts
def main():
    # Define the range of variables to test
    variable_counts = range(10, 29)  # Adjust this list as needed
    results = []

    for count in variable_counts:
        print("Running benchmark for num_variables = ", count)
        # Delete the previous output file if it exists
        if os.path.exists('outputs/bench_output.json'):
            os.remove('outputs/bench_output.json')

        # Run the benchmark
        run_benchmark(count)

        # Check if the output file exists before reading
        if not os.path.exists('outputs/bench_output.json'):
            print(f"Error: outputs/bench_output.json not found after running benchmark for {count} variables.")
            continue

        # Read the output from the JSON file
        output_data = read_benchmark_output()
        proving_time = convert_prover_time(output_data.get('whir_prover_time'))
        verification_hashes = output_data.get('whir_verifier_hashes')
        proof_size = output_data.get('whir_argument_size')

        # Store results
        results.append((count, proving_time, verification_hashes, proof_size))

    # Print results
    print(f"{'Variables':<10} {'Proving Time (ms)':<20} {'Verification Hashes':<40} {'Proof Size':<15}")
    for count, proving_time, verification_hashes, proof_size in results:
        print(f"{count:<10} {proving_time:<20.2f} {verification_hashes:<40} {proof_size:<15}")

if __name__ == '__main__':
    print(f"Benchmark run at: {datetime.datetime.now()}")
    main()
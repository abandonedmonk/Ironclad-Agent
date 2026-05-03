# REQUIRES: 
import math

def read_proc_file(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filename}: {str(e)}")
        return None

def parse_meminfo(meminfo):
    mem_total = 0
    mem_available = 0
    for line in meminfo.split('\n'):
        if line.startswith('MemTotal'):
            mem_total = int(line.split()[1])
        elif line.startswith('MemAvailable'):
            mem_available = int(line.split()[1])
    return mem_total, mem_available

def parse_loadavg(loadavg):
    loadavg_values = loadavg.split()
    return float(loadavg_values[0])

def main():
    meminfo = read_proc_file('/proc/meminfo')
    loadavg = read_proc_file('/proc/loadavg')
    stat = read_proc_file('/proc/stat')

    if meminfo and loadavg and stat:
        mem_total, mem_available = parse_meminfo(meminfo)
        loadavg_value = parse_loadavg(loadavg)

        print(f"Memory Total: {mem_total // 1024} MB")
        print(f"Memory Available: {mem_available // 1024} MB")
        print(f"Load Average: {loadavg_value}")
        print(f"Simulated io_write_kbps: 6859121.8, Anomaly Score: -0.1458, Severity: warning")

        # Analyze pattern
        if mem_total - mem_available < 1024 * 1024:  # 1 GB
            print("Memory usage is low.")
        else:
            print("Memory usage is high.")

        if loadavg_value < 1.0:
            print("System load is low.")
        else:
            print("System load is high.")

        if mem_total - mem_available < 1024 * 1024 and loadavg_value < 1.0:
            print("The simulated anomaly values do not seem to be related to the current system resource usage.")
        else:
            print("The simulated anomaly values might be related to the current system resource usage.")

    else:
        print("Failed to read /proc files.")

if __name__ == "__main__":
    main()
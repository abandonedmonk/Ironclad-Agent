import os
import subprocess

# Check CPU usage
def check_cpu_usage():
    # Attempt to use a different file path
    with open('/proc/stat', 'r') as file:
        # Read the CPU stats
        cpu_stats = file.readline().split()
        # Calculate CPU usage
        cpu_usage = 100 * (float(cpu_stats[1]) + float(cpu_stats[2]) + float(cpu_stats[3])) / float(cpu_stats[4])
        return cpu_usage

# Check memory usage
def check_memory_usage():
    with open('/proc/meminfo', 'r') as file:
        meminfo = file.readlines()
        for line in meminfo:
            if line.startswith('MemTotal:'):
                total_memory = int(line.split()[1])
            elif line.startswith('MemFree:'):
                free_memory = int(line.split()[1])
        return (total_memory - free_memory) / total_memory

# Check open file descriptors
def check_open_fds():
    with open('/proc/sys/fs/file-nr', 'r') as file:
        file_nr = file.readline().split()
        return int(file_nr[0])

# Main function to gather and print system resource usage
def diagnose_system():
    cpu_usage = check_cpu_usage()
    memory_usage = check_memory_usage()
    open_fds = check_open_fds()

    print("System Resource Usage Summary:")
    print(f"CPU Usage: {cpu_usage:.2f}%")
    print(f"Memory Usage: {memory_usage:.2f}%")
    print(f"Open File Descriptors: {open_fds}")

# Call the main function to diagnose the system
diagnose_system()

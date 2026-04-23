import math

# Small but non-trivial CPU work so startup cost still dominates.
value = sum(math.sqrt(i) for i in range(1, 5000))
print(f"workload_ok:{value:.4f}")

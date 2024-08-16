import matplotlib.pyplot as plt

# Data
num_slots = [2, 4, 6, 8, 10]
interval = [1569.008, 778.027, 586.823, 506.258, 455.127]
logarithmic = [1540.87, 1260.98, 1070.678, 930.256, 929.548]
compression = [2040.276, 1354.65, 1207.957, 1090.856, 989.074]

# Plotting
plt.figure(figsize=(10, 6))
plt.plot(num_slots, interval, marker='o', linestyle='-', color='b', label='Interval')
plt.plot(num_slots, logarithmic, marker='s', linestyle='-', color='g', label='Logarithmic')
plt.plot(num_slots, compression, marker='^', linestyle='-', color='r', label='Compression')

# Labels and Title
plt.xlabel('Number of Slots')
plt.ylabel('Key derivation time')
plt.title('Comparison of Interval, Logarithmic, and Compression Storage Methods')
plt.legend()

# Show Plot
plt.grid(True)
plt.show()

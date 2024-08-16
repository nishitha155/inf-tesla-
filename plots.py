import matplotlib.pyplot as plt

disclosure_delay = [1, 2, 3, 4, 5]
det = [128, 256, 384, 512, 640]
prob = [32, 64, 96, 128, 160]

# Plotting the graph
plt.plot(disclosure_delay, det, label='Deterministic mode', marker='o')
plt.plot(disclosure_delay, prob, label='Probabilistic mode', marker='x')

# Set the x-ticks to ensure only integer values are shown
plt.xticks(disclosure_delay)

plt.xlabel('Disclosure delay')
plt.ylabel('Storage overhead (bytes)')
plt.title('Storage overhead vs Disclosure delay')
plt.legend()
plt.grid(True)
plt.show()

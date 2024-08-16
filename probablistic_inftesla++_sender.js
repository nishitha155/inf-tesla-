const crypto = require('crypto');
const net = require('net');
const fs = require('fs');
const { performance } = require('perf_hooks');

// Configuration
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 4000;  // Interval duration in milliseconds (1 second)
const serverPort = 12345;  // Port on which the sender will send data
const lambda = 2;  // Lambda for Poisson distribution (average number of messages per interval)
const bloomFilterSize = 256;  // Size of the Bloom filter bit array
const numHashFunctions = 3;  // Number of hash functions for the Bloom filter
const congestion = true;  // Ensure probabilistic mode is enabled

// Poisson distribution function
const poisson = (lambda) => {
  const L = Math.exp(-lambda);
  let k = 0;
  let p = 1;

  do {
    k++;
    p *= Math.random();
  } while (p > L);

  return k - 1;
};

// Function to apply HMAC with SHA-256
const hmac = (key, data) => {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
};

// Load sender info from file created by the owner
const loadSenderInfo = (id) => {
  const senderInfo = JSON.parse(fs.readFileSync(`${id}.json`));
  return senderInfo;
};

// Bloom filter implementation
class BloomFilter {
  constructor(size, numHashFunctions) {
    this.size = size;
    this.numHashFunctions = numHashFunctions;
    this.bitArray = Array(size).fill(0);
  }

  // Hash functions for Bloom filter
  hashFunctions(data) {
    const hashes = [];
    for (let i = 0; i < this.numHashFunctions; i++) {
      const hash = crypto.createHash('sha256').update(data + i).digest('hex');
      const index = parseInt(hash, 16) % this.size;
      hashes.push(index);
    }
    return hashes;
  }

  // Add data to Bloom filter
  add(data) {
    const indices = this.hashFunctions(data);
    indices.forEach((index) => {
      this.bitArray[index] = 1;
    });
  }

  // Check data against Bloom filter
  check(data) {
    const indices = this.hashFunctions(data);
    return indices.every((index) => this.bitArray[index] === 1);
  }

  // Convert bit array to string for transmission
  toString() {
    return this.bitArray.join('');
  }
}

// Sender server to broadcast HMACs and disclose keys
const createSenderServer = (port) => {
  const start=performance.now()
  const senderInfo = loadSenderInfo('sender1');  // Load sender info based on ID
  const end=performance.now()
  console.log(end-start)
  const keyChain = senderInfo.keyChain;
  let currentInterval = senderInfo.startSlot;

  const server = net.createServer((socket) => {
    let prevMessages = [];
    let keyDisclosed = false;

    // Create initial Bloom filter and send it
    const initialBloomFilter = new BloomFilter(bloomFilterSize, numHashFunctions);
    socket.write(JSON.stringify({ mode: 'initial', bloomFilter: initialBloomFilter.toString() }));

    const intervalId = setInterval(() => {
      if (currentInterval >= senderInfo.expirySlot) {
        clearInterval(intervalId);
        socket.end();
        return;
      }

      const numberOfMessages = poisson(lambda);
      const messages = Array.from({ length: numberOfMessages }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);
      console.log(messages);

      const bloomFilter = new BloomFilter(bloomFilterSize, numHashFunctions);
      messages.forEach((message) => bloomFilter.add(message));

      const bloomFilterData = bloomFilter.toString();

      // Compute and broadcast HMAC of the Bloom filter
      const start = performance.now();
      const hmacValue = hmac(keyChain[currentInterval - senderInfo.startSlot], bloomFilterData);
      socket.write(JSON.stringify({ interval: currentInterval, hmac: hmacValue, mode: 'probabilistic' }));
      const end = performance.now();
      const hmacTime = end - start;
      console.log(`Time to compute HMACs for interval ${currentInterval}: ${hmacTime.toFixed(2)} ms`);

      // Simulate key disclosure with messages after the delay
      if (currentInterval >= senderInfo.startSlot + disclosureDelay) {
        const disclosedMessages = prevMessages[currentInterval - senderInfo.startSlot - disclosureDelay].map((message, index) => {
          if (!keyDisclosed) {
            keyDisclosed = true;
            return {
              interval: currentInterval - disclosureDelay,
              message,
              key: keyChain[currentInterval - senderInfo.startSlot - disclosureDelay],
              bloomFilter: bloomFilterData,
              index,
            };
          } else {
            return { interval: currentInterval - disclosureDelay, message, index };
          }
        });
        console.log(`Disclosing messages for interval ${currentInterval - disclosureDelay}:`, disclosedMessages);
        socket.write(JSON.stringify(disclosedMessages));
      }
      keyDisclosed = false;
      prevMessages[currentInterval - senderInfo.startSlot] = messages;
      currentInterval++;
    }, intervalDuration);
  });

  server.listen(port, () => {
    console.log(`Sender server listening on port ${port}`);
  });
};

// Start the sender server
createSenderServer(serverPort);

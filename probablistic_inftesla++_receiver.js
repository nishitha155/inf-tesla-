const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const serverPorts = [12345]; // List of server ports
const serverHost = '127.0.0.1';

// Load sender info from file
const senderInfo = JSON.parse(fs.readFileSync('sender1.json', 'utf8'));

// Function to apply HMAC with SHA-256
const hmac = (key, data) => {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
};

let prev={}
const verifyKey = (temp, interval, keyChain, startSlot) => {
  console.log('prev', prev);
  console.log(interval);
  const start = performance.now();
  let hashedKey;
  let inter;

  // Check if 'prev' is initialized with key and interval
  if (prev.key === undefined || prev.interval === undefined) {
    // First-time computation
    hashedKey = keyChain[0];
    inter = interval - startSlot;
    console.log('Using start key from keyChain');
  } else {
    // Use the previously stored key and interval
    hashedKey = prev.key;
    inter = interval - prev.interval;
    console.log('Using previous key');
  }

  console.log('Initial hashed key:', hashedKey);
  console.log('Interval difference:', inter);

  // Perform the hashing based on the computed interval difference
  for (let i = 0; i < inter; i++) {
    temp = hash(temp);
  }

  const end = performance.now();
  prev.interval = interval;
  prev.key = temp;

  console.log('Final computed key:', temp);

  return { result: hashedKey === temp, time: end - start };
};

// Function to store HMACs temporarily
const storeHmacs = (hmacs, state) => {
  hmacs.forEach(({ interval, hmac }) => {
    if (!state.storedHmacs[interval]) {
      state.storedHmacs[interval] = [];
    }
    state.storedHmacs[interval].push(hmac);

    // Track storage usage
    state.totalHmacStorage += hmac.length * 2; // Hex string, hence 2 bytes per char
  });
};

const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Bloom filter implementation for receiver
class BloomFilter {
  constructor(size, numHashFunctions, bitArray) {
    this.size = size;
    this.numHashFunctions = numHashFunctions;
    this.bitArray = bitArray;

    // Track storage usage
    state.totalBloomFilterStorage += bitArray.length / 8; // Convert bits to bytes
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

  // Check data against Bloom filter
  check(data) {
    const indices = this.hashFunctions(data);
    return indices.every((index) => this.bitArray[index] === '1');
  }
}
let bloom;

const updateKnownKeys = (disclosures, state) => {
  console.log('Disclosures:', disclosures);

  disclosures.forEach(({ interval, message, key, bloomFilter, index }) => {
    let totalAuthTime = 0; // Initialize total authentication time

    if (key) {
      state.knownKeys[interval] = key;

      // Track storage usage
      state.totalKeyStorage += key.length * 2; // Hex string, hence 2 bytes per char
    } else {
      key = state.knownKeys[interval];
    }

    const storedMacs = state.storedHmacs[interval];

    if (index == 0 && storedMacs && storedMacs.length > 0) {
      const bloomFilterData = bloomFilter.toString();
      
      // Compute HMAC
      const startHmac = performance.now();
      const hmacValue = hmac(key, bloomFilterData);
      const endHmac = performance.now();
      const hmacTime = endHmac - startHmac;
      state.totalHmacComputationTime += hmacTime;
      totalAuthTime += hmacTime; // Add HMAC computation time to total authentication time

      if (hmacValue === state.storedHmacs[interval]) {
        console.log('MAC verified');
      }

      // Verify key
      const { result: keyVerified, time: keyVerificationTime } = verifyKey(key, interval, senderInfo.keyChain, senderInfo.startSlot);
      totalAuthTime += keyVerificationTime; // Add key verification time to total authentication time
      console.log(keyVerified);

      console.log(`Time to compute HMACs for interval ${interval}: ${hmacTime.toFixed(2)} ms`);
      bloom = new BloomFilter(bloomFilter.length, state.numHashFunctions, bloomFilter);

      // Check Bloom filter
      const startBloom = performance.now();
      const bloomCheck = bloom.check(message);
      const endBloom = performance.now();
      const bloomTime = endBloom - startBloom;
      totalAuthTime += bloomTime; // Add Bloom filter check time to total authentication time

      state.totalBloomFilterCheckTime += bloomTime;

      if (bloomCheck) {
        console.log('Message is possibly in the Bloom filter');
      } else {
        console.log('Message is not in the Bloom filter');
      }
    } else {
      // Check Bloom filter
      const startBloom = performance.now();
      const bloomCheck = bloom.check(message);
      const endBloom = performance.now();
      const bloomTime = endBloom - startBloom;
      totalAuthTime += bloomTime; // Add Bloom filter check time to total authentication time

      state.totalBloomFilterCheckTime += bloomTime;

      if (bloomCheck) {
        console.log('Message is possibly in the Bloom filter');
      } else {
        console.log('Message is not in the Bloom filter');
      }
    }

    console.log(`Total authentication time for interval ${interval}: ${totalAuthTime.toFixed(2)} ms`);
    state.totalAuthenticationTime += totalAuthTime; // Accumulate total authentication time
  });
};

// Add new variable in state to track total authentication time
const state = {
  knownKeys: {},
  storedHmacs: {},
  totalAuthenticatedMessages: 0,
  totalMacVerificationTime: 0,
  numHashFunctions: 3, // Number of hash functions for Bloom filter

  // For tracking computation time
  totalKeyVerificationTime: 0,
  totalHmacComputationTime: 0,
  totalBloomFilterCheckTime: 0,
  totalAuthenticationTime: 0, // Track total authentication time

  // For tracking storage usage (in bytes)
  totalHmacStorage: 0,
  totalKeyStorage: 0,
  totalBloomFilterStorage: 0,
};

// Update the `client.on('close', ...)` block to display the total authentication time:




// Function to create receiver client and connect to sender
const createReceiverClient = (port, host) => {
  const client = new net.Socket();
  let initialBloomFilter = null;

  client.connect(port, host, () => {
    const start=performance.now()
    console.log(`Connected to sender at ${host}:${port}`);
    const end=performance.now()
    console.log(end-start)
  });

  client.on('data', (data) => {
    const messages = JSON.parse(data);
    console.log('Received:', messages);

    if (messages.mode === 'initial') {
      // Store initial Bloom filter
      initialBloomFilter = messages.bloomFilter;
      console.log(`Initial Bloom Filter stored: ${initialBloomFilter}`);
    } else if (messages.mode === 'probabilistic') {
      storeHmacs([messages], state);
    } else {
      // Handle key disclosure and message authentication
      updateKnownKeys(messages, state);
    }
  });

  client.on('close', () => {
    console.log(`Connection to sender at ${host}:${port} closed`);
    console.log(`Total authenticated messages: ${state.totalAuthenticatedMessages}`);
    console.log(`Total MAC verification time: ${state.totalMacVerificationTime.toFixed(2)} ms`);
    console.log(`Total HMAC computation time: ${state.totalHmacComputationTime.toFixed(2)} ms`);
    console.log(`Total key verification time: ${state.totalKeyVerificationTime.toFixed(2)} ms`);
    console.log(`Total Bloom filter check time: ${state.totalBloomFilterCheckTime.toFixed(2)} ms`);
    console.log(`Total authentication time: ${state.totalAuthenticationTime.toFixed(2)} ms`);
    console.log(`Total HMAC storage: ${state.totalHmacStorage} bytes`);
    console.log(`Total key storage: ${state.totalKeyStorage} bytes`);
    console.log(`Total Bloom filter storage: ${state.totalBloomFilterStorage} bytes`);
  });
  
  

  client.on('error', (err) => {
    console.error(`Error connecting to sender at ${host}:${port}:`, err.message);
  });
};

// Create receiver clients for each server
serverPorts.forEach((port) => {
  createReceiverClient(port, serverHost);
});

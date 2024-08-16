const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const keyChainLength = 6;  // Number of intervals
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 1000;  // Interval duration in milliseconds (1 second)
const serverPorts = [12345, 12346];  // List of server ports
const lambda = 2;  // Lambda for Poisson distribution (average number of messages per interval)
const packetLossProbability = 0.1;  // Probability of packet loss (10%)

// Function to generate a random key
const generateRandomKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

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

// Generate key chain with time measurement
const generateKeyChain = (length) => {
  let keys = [];
  const start = performance.now();
  keys[length] = generateRandomKey();
  for (let i = length - 1; i >= 0; i--) {
    keys[i] = hash(keys[i + 1]);
  }
  const end = performance.now();
  const hashChainTime = end - start;
  console.log(`Time to generate hash chain: ${hashChainTime.toFixed(2)} ms`);
  return { keys, hashChainTime };
};

// Initialize key chain
const { keys: keyChain, hashChainTime } = generateKeyChain(keyChainLength);

// Function to calculate memory usage
const calculateMemoryUsage = (object) => {
  const objectList = [];
  const stack = [object];
  let bytes = 0;

  while (stack.length) {
    const value = stack.pop();

    if (typeof value === 'boolean') {
      bytes += 4;
    } else if (typeof value === 'string') {
      bytes += value.length * 2;
    } else if (typeof value === 'number') {
      bytes += 8;
    } else if (typeof value === 'object' && objectList.indexOf(value) === -1) {
      objectList.push(value);
      for (let i in value) {
        stack.push(value[i]);
      }
    }
  }
  return bytes;
};

// Function to simulate packet loss
const simulatePacketLoss = () => {
  return 0.1 < packetLossProbability;
};

// Function to create a TCP server
const createServer = (port) => {
  const server = net.createServer((socket) => {
    socket.on('data', (data) => {
      const message = data.toString();
      
      // Handle bootstrapping request
      if (message.startsWith('NONCE')) {
        const nonce = message.split(' ')[1];
        const currentTime = Date.now();
        const commitmentKey = keyChain[0];  // Key chain commitment
        const startingTime = currentTime;
        const timeIntervalDuration = 1000;  // 1 second interval duration
        const response = {
          TS: currentTime,
          Ki: commitmentKey,
          Ti: startingTime,
          Tint: timeIntervalDuration,
          disclosureDelay: disclosureDelay
        };
        const macData = `${nonce}${currentTime}${commitmentKey}${startingTime}${timeIntervalDuration}${disclosureDelay}`;
        const mac = crypto.createHmac('sha256', 'shared_secret').update(macData).digest('hex');
        response.MAC = mac;
        socket.write(JSON.stringify(response));
      }
    });

    // Broadcast HMACs and disclose keys with messages
    let currentInterval = 0;
    let prevMessages = [];
    let keyDisclosed = false;
    let totalHmacTime = 0;

    const intervalId = setInterval(() => {
      if (currentInterval >= keyChainLength) {
        clearInterval(intervalId);
        const totalComputationTime = hashChainTime + totalHmacTime;
        console.log(`Total computation time (hash chain + all HMACs): ${totalComputationTime.toFixed(2)} ms`);
        
        // Close the connection after processing all intervals
        socket.end();
        return;
      }

      // Generate the number of messages based on Poisson distribution
      const numberOfMessages = poisson(lambda);
      const messages = Array.from({ length: numberOfMessages }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);
      console.log(messages);

      const start = performance.now();
      const currentHmacs = messages.map((message) => {
        const mac = crypto.createHmac('sha256', keyChain[currentInterval]).update(message).digest('hex');
        return { interval: currentInterval, mac };
      });
      const end = performance.now();
      const hmacTime = end - start;
      totalHmacTime += hmacTime;
      console.log(`Time to compute HMACs for interval ${currentInterval}: ${hmacTime.toFixed(2)} ms`);

      console.log(`Broadcasting HMACs for interval ${currentInterval}:`, currentHmacs);
      if (!simulatePacketLoss()) {
        socket.write(JSON.stringify(currentHmacs));
      } else {
        console.log(`Simulated packet loss: HMACs for interval ${currentInterval} not sent`);
      }

      // Simulate key disclosure with messages after the delay
      if (currentInterval >= disclosureDelay) {
        const disclosedMessages = prevMessages[currentInterval - disclosureDelay].map((message, index) => {
          if (!keyDisclosed) {
            keyDisclosed = true;
            return { interval: currentInterval - disclosureDelay, message, key: keyChain[currentInterval - disclosureDelay], index };
          } else {
            return { interval: currentInterval - disclosureDelay, message, index };
          }
        });
        console.log(`Disclosing messages for interval ${currentInterval - disclosureDelay}:`, disclosedMessages);
        if (!simulatePacketLoss()) {
          socket.write(JSON.stringify(disclosedMessages));
        } else {
          console.log(`Simulated packet loss: Disclosed messages for interval ${currentInterval - disclosureDelay} not sent`);
        }
      }
      keyDisclosed = false;
      prevMessages[currentInterval] = messages;
      currentInterval++;
    }, intervalDuration);
  });

  server.listen(port, () => {
    console.log(`Sender server listening on port ${port}`);
  });

  // Calculate storage overhead
  const hashChainMemoryUsage = calculateMemoryUsage(keyChain);
  console.log(`Memory usage for hash chain: ${hashChainMemoryUsage} bytes`);
};

// Create servers on all specified ports
serverPorts.forEach(createServer);
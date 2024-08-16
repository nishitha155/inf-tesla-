const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const keyChainLength = 20;  // Number of intervals
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 1000;  // Interval duration in milliseconds (1 second)
const serverPort = 12345;

// Function to generate a random key
const generateRandomKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
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

// Initialize
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

// Create a TCP server
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

    // Send HMACs for the current interval
    const messages = Array.from({ length: 2 }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);
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
    socket.write(JSON.stringify(currentHmacs));

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
      socket.write(JSON.stringify(disclosedMessages));
    }
    keyDisclosed = false;
    prevMessages[currentInterval] = messages;
    currentInterval++;
  }, intervalDuration);
});

server.listen(serverPort, () => {
  console.log(`Sender server listening on port ${serverPort}`);
});

// Calculate storage overhead
const hashChainMemoryUsage = calculateMemoryUsage(keyChain);


console.log(`Memory usage for hash chain: ${hashChainMemoryUsage} bytes`);


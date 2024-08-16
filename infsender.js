const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const keyChainLength = 10;  // Number of intervals
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 1000;  // Interval duration in milliseconds (1 second)
const serverPorts = [12345];  // List of server ports
const lambda = 8;  // Lambda for Poisson distribution (average number of messages per interval)

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
  keys[length - 1] = generateRandomKey();
  for (let i = length - 2; i >= 0; i--) {
    keys[i] = hash(keys[i + 1]);
  }
  const end = performance.now();
  const hashChainTime = end - start;
  console.log(`Time to generate hash chain: ${hashChainTime.toFixed(2)} ms`);
  return { keys, hashChainTime };
};

// Initialize two key chains
const { keys: keyChain1, hashChainTime: hashChainTime1 } = generateKeyChain(keyChainLength);
const { keys: keyChain2, hashChainTime: hashChainTime2 } = generateKeyChain(keyChainLength);

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

// Function to create a TCP server
const createServer = (port) => {
  const server = net.createServer((socket) => {
    socket.on('data', (data) => {
      const start = performance.now();
      const message = data.toString();
      
      // Handle bootstrapping request
      if (message.startsWith('NONCE')) {
        const nonce = message.split(' ')[1];
        const currentTime = Date.now();
        const commitmentKey1 = keyChain1[0];  // Key chain 1 commitment
        const commitmentKey2 = keyChain2[0];  // Key chain 2 commitment
        const startingTime = currentTime;
        const timeIntervalDuration = 1000;  // 1 second interval duration
        const response = {
          TS: currentTime,
          Ki1: commitmentKey1,
          Ki2: commitmentKey2,
          Ti: startingTime,
          Tint: timeIntervalDuration,
          disclosureDelay: disclosureDelay
        };
        const macData = `${nonce}${currentTime}${commitmentKey1}${commitmentKey2}${startingTime}${timeIntervalDuration}${disclosureDelay}`;
        const mac = crypto.createHmac('sha256', 'shared_secret').update(macData).digest('hex');
        response.MAC = mac;
        socket.write(JSON.stringify(response));
      }
      const end = performance.now();
      console.log(end-start)
    });

    // Broadcast HMACs and disclose keys with messages
    let currentInterval = 0;
    let prevMessages = [];
    let keyDisclosed = false;
    let totalHmacTime = 0;

    const intervalId = setInterval(() => {
      if (currentInterval >= keyChainLength * 2) {
        clearInterval(intervalId);
        const totalComputationTime = hashChainTime1 + hashChainTime2 + totalHmacTime;
        console.log(`Total computation time (hash chains + all HMACs): ${totalComputationTime.toFixed(2)} ms`);
        
        // Close the connection after processing all intervals
        socket.end();
        return;
      }

      // Generate the number of messages based on Poisson distribution
      const numberOfMessages = poisson(lambda);
      const messages = Array.from({ length: numberOfMessages }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);
      console.log(messages);

      const start = performance.now();
      const chainIndex = Math.floor(currentInterval / 2);
      const currentKey = currentInterval % 2 === 0 ? keyChain1[chainIndex] : keyChain2[chainIndex];
      const currentHmacs = messages.map((message) => {
        const mac = crypto.createHmac('sha256', currentKey).update(message).digest('hex');
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
        const disclosureInterval = currentInterval - disclosureDelay;
        const disclosureChainIndex = Math.floor(disclosureInterval / 2);
        const disclosedKey = disclosureInterval % 2 === 0 ? 
          keyChain1[disclosureChainIndex] : 
          keyChain2[disclosureChainIndex];
        const disclosedMessages = prevMessages[disclosureInterval].map((message, index) => {
          if (!keyDisclosed) {
            keyDisclosed = true;
            return { interval: disclosureInterval, message, key: disclosedKey, index };
          } else {
            return { interval: disclosureInterval, message, index };
          }
        });
        console.log(`Disclosing messages for interval ${disclosureInterval}:`, disclosedMessages);
        socket.write(JSON.stringify(disclosedMessages));
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
  const hashChainMemoryUsage = calculateMemoryUsage(keyChain1) + calculateMemoryUsage(keyChain2);
  console.log(`Memory usage for hash chains: ${hashChainMemoryUsage} bytes`);
};

// Create servers on all specified ports
serverPorts.forEach(createServer);
const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const keyChainLength = 10;  // Number of intervals per chain
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 1000;  // Interval duration in milliseconds (1 second)
const serverPorts = [12345];  // List of server ports
const lambda = 2;  // Lambda for Poisson distribution (average number of messages per interval)
const totalTime = 24; // Total running time in seconds

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

// Initialize key chains
let keyChains = [
  generateKeyChain(keyChainLength),
  generateKeyChain(keyChainLength)
];

// Function to create a TCP server
const createServer = (port) => {
  const server = net.createServer((socket) => {
    let currentInterval = 0;
    let prevMessages = [];
    let keyDisclosed = false;
    let totalHmacTime = 0;
    let randomKey = generateRandomKey();
    let currentRandomKey = randomKey;

    socket.on('data', (data) => {
      const start = performance.now();
      const message = data.toString();
      
      // Handle bootstrapping request
      if (message.startsWith('NONCE')) {
        const nonce = message.split(' ')[1];
        const currentTime = Date.now();
        const commitmentKey1 = keyChains[0].keys[0];  // Key chain 1 commitment
        const commitmentKey2 = keyChains[1].keys[0];  // Key chain 2 commitment
        const startingTime = currentTime;
        const timeIntervalDuration = intervalDuration;
        const response = {
          TS: currentTime,
          Ki1: commitmentKey1,
          Ki2: commitmentKey2,
          Ti: startingTime,
          Tint: timeIntervalDuration,
          disclosureDelay: disclosureDelay,
          randomKey: randomKey
        };
        const macData = `${nonce}${currentTime}${commitmentKey1}${commitmentKey2}${startingTime}${timeIntervalDuration}${disclosureDelay}${randomKey}`;
        const mac = crypto.createHmac('sha256', 'shared_secret').update(macData).digest('hex');
        response.MAC = mac;
        socket.write(JSON.stringify(response));
      }
      const end = performance.now();
      console.log(end-start)
    });

    // Broadcast HMACs and disclose keys with messages
    const intervalId = setInterval(() => {
      if (currentInterval >= totalTime) {
        clearInterval(intervalId);
        const totalComputationTime = keyChains.reduce((sum, chain) => sum + chain.hashChainTime, 0) + totalHmacTime;
        console.log(`Total computation time (hash chains + all HMACs): ${totalComputationTime.toFixed(2)} ms`);
        
        // Close the connection after processing all intervals
        socket.end();
        return;
      }

      // Generate the number of messages based on Poisson distribution
      const numberOfMessages = poisson(lambda);
      const messages = Array.from({ length: numberOfMessages }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);
      console.log(`Interval ${currentInterval} messages:`, messages);

      
      console.log('key chains',keyChains)
      const chainSetIndex = Math.floor(currentInterval / (2 * keyChainLength));
      if (chainSetIndex >= keyChains.length / 2) {
        // Generate two new key chains if necessary
        keyChains.push(generateKeyChain(keyChainLength));
        keyChains.push(generateKeyChain(keyChainLength));
      }
      const chainIndex = chainSetIndex * 2 + (currentInterval % 2);
      const keyIndex = Math.floor((currentInterval % (2 * keyChainLength)) / 2);
      console.log('chain index', chainIndex);
      console.log('key index', keyIndex);
      const currentKey = keyChains[chainIndex].keys[keyIndex];
      const currentHmacs = messages.map((message) => {
        const start = performance.now();
        const mac = crypto.createHmac('sha256', currentKey).update(message).digest('hex');
        
        const end = performance.now();
      const hmacTime = end - start;
      totalHmacTime += hmacTime;
      console.log(`Time to compute HMACs for interval ${currentInterval}: ${hmacTime.toFixed(2)} ms`);
      return { interval: currentInterval, mac };
      });
      
     

      console.log(`Broadcasting HMACs for interval ${currentInterval}:`, currentHmacs);
      socket.write(JSON.stringify(currentHmacs));

      // Simulate key disclosure with messages after the delay
      if (currentInterval >= disclosureDelay) {
        const disclosureInterval = currentInterval - disclosureDelay;
        const disclosureChainSetIndex = Math.floor(disclosureInterval / (2 * keyChainLength));
        const disclosureChainIndex = disclosureChainSetIndex * 2 + (disclosureInterval % 2);
        const disclosureKeyIndex = Math.floor((disclosureInterval % (2 * keyChainLength)) / 2);
        const disclosedKey = keyChains[disclosureChainIndex].keys[disclosureKeyIndex];
        const disclosedMessages = prevMessages[disclosureInterval].map((message, index) => {
          if (!keyDisclosed) {
            keyDisclosed = true;
            return { interval: disclosureInterval, message, key: disclosedKey, index };
          } else {
            return { interval: disclosureInterval, message, index };
          }
        });

        // Check if we need to send a new hash chain key
        if (disclosureKeyIndex === keyChainLength - 1 && disclosureInterval % 2 === 1) {
          const start=performance.now()
          const newChainIndex = keyChains.length;
          const newKeyChain = generateKeyChain(keyChainLength);
          keyChains.push(newKeyChain);
          const newChainFirstKey = newKeyChain.keys[0];
          const iv = crypto.randomBytes(16);
          const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(currentRandomKey, 'hex'), iv);
          let encryptedKey = cipher.update(Buffer.from(newChainFirstKey, 'hex'));
          encryptedKey = Buffer.concat([encryptedKey, cipher.final()]);
          disclosedMessages.push({ 
            newChainKey: encryptedKey.toString('hex'),
            iv: iv.toString('hex')
          });
          currentRandomKey = hash(currentRandomKey);
          const end=performance.now()
          console.log('new',end-start)
        }

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
};

// Create servers on all specified ports
serverPorts.forEach(createServer);

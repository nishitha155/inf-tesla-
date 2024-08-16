const crypto = require('crypto');
const net = require('net');
const fs = require('fs');
const zlib = require('zlib');
const { performance } = require('perf_hooks');

// Configuration
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 1000;  // Interval duration in milliseconds (1 second)
const serverPort = 12345;  // Port on which the sender will send data
const lambda = 2;  // Lambda for Poisson distribution (average number of messages per interval)

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

// Compression function
const compressData = (data) => {
    const start = performance.now();
    const compressed = zlib.gzipSync(JSON.stringify(data)).toString('base64');
    const end = performance.now();
    console.log(`Time to compress data: ${end - start} ms`);
    return compressed;
  };
  
  const decompressData = (compressedData) => {
    const start = performance.now();
    const buffer = Buffer.from(compressedData, 'base64');
    const decompressed = zlib.gunzipSync(buffer);
    const end = performance.now();
    console.log(`Time to decompress data: ${end - start} ms`);
    return JSON.parse(decompressed.toString());
  };
  
// Hashing function
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Derive a key if it's not stored
const deriveKey = (storedKeys, targetInterval, senderInfo) => {
  let storedKey = storedKeys
    .filter(keyObj => keyObj.interval >= targetInterval)
    .sort((a, b) => a.interval - b.interval)[0];

  if (storedKey.interval === targetInterval) {
    return storedKey.key;
  } else {
    const x = storedKey.interval - targetInterval;
    let derivedKey = storedKey.key;
    for (let i = 0; i < x; i++) {
      derivedKey = hash(derivedKey);
    }
    return derivedKey;
  }
};

// Sender server to broadcast HMACs and disclose keys
const createSenderServer = (port) => {
  const senderInfo = loadSenderInfo('sender1');  // Load sender info based on ID
  let currentInterval = senderInfo.startSlot;

  // Initial key storage (storing keys at intervals 6, 4, 2 for example)
  let storedKeysA = [
    { interval: 1000, key: senderInfo.keyChain[120 - senderInfo.startSlot] },
    { interval: 750, key: senderInfo.keyChain[115 - senderInfo.startSlot] },
  ];
  let storedKeysB = [
    { interval: 500, key: senderInfo.keyChain[110 - senderInfo.startSlot] },
    { interval: 250, key: senderInfo.keyChain[105 - senderInfo.startSlot] },
  ];

  // Compress the stored keys
  let compressedStoredKeysA = compressData(storedKeysA);
  let compressedStoredKeysB = compressData(storedKeysB);

  const server = net.createServer((socket) => {
    let prevMessages = [];
    let keyDisclosed = false;
    let totalHmacTime = 0;
    let prevKey;

    const intervalId = setInterval(() => {
      if (currentInterval >= senderInfo.expirySlot) {
        clearInterval(intervalId);
        socket.end();
        return;
      }

      // Decompress the required part based on the current interval
      let storedKeys;
      if (currentInterval >= 501) {
        storedKeys = decompressData(compressedStoredKeysA);
      } else {
        storedKeys = decompressData(compressedStoredKeysB);
      }

      // Derive the key for the current interval
      console.log('currentinterval', currentInterval);
      const key = deriveKey(storedKeys, currentInterval, senderInfo);
      console.log(key);

      const numberOfMessages = poisson(lambda);
      const messages = Array.from({ length: numberOfMessages }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);
      console.log(messages);

      // Broadcast HMACs
      const start = performance.now();
      const currentHmacs = messages.map((message) => ({
        interval: currentInterval,
        hmac: hmac(key, message),
      }));
      const end = performance.now();
      const hmacTime = end - start;
      totalHmacTime += hmacTime;
      console.log(`Time to compute HMACs for interval ${currentInterval}: ${hmacTime.toFixed(2)} ms`);
      socket.write(JSON.stringify(currentHmacs));

      // Simulate key disclosure with messages after the delay
      if (currentInterval >= senderInfo.startSlot + disclosureDelay) {
        const disclosedMessages = prevMessages[currentInterval - senderInfo.startSlot - disclosureDelay].map((message, index) => {
          if (!keyDisclosed) {
            keyDisclosed = true;
            return { interval: currentInterval - disclosureDelay, message, prevKey, index };
          } else {
            return { interval: currentInterval - disclosureDelay, message, index };
          }
        });
        console.log(`Disclosing messages for interval ${currentInterval - disclosureDelay}:`, disclosedMessages);
        socket.write(JSON.stringify(disclosedMessages));
      }
      prevKey = key;
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

const crypto = require('crypto');
const net = require('net');
const fs = require('fs');
const { performance } = require('perf_hooks');

// Configuration
const disclosureDelay = 1;  // Delay before key disclosure (in intervals)
const intervalDuration = 1000;  // Interval duration in milliseconds (12 seconds)
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

// Key storage optimization algorithm
const keyStorageAlgorithm = (N, S, t, storedKeys, senderInfo) => {
  const xtminus1S = storedKeys[storedKeys.length - 1].interval;
  const xtminus1Sminus1 = storedKeys[storedKeys.length - 2].interval;
  const xtminus1Sminus2 = storedKeys[storedKeys.length - 3].interval;

  if (xtminus1S === t) {
    if (storedKeys.length >= 2 && (xtminus1S - xtminus1Sminus1) > 1) {
      storedKeys[storedKeys.length - 1] = {
        interval: Math.floor((xtminus1S - xtminus1Sminus1) / 2),
        key: deriveKey(storedKeys, Math.floor((xtminus1S - xtminus1Sminus1) / 2), senderInfo)
      };
    } else {
      storedKeys[storedKeys.length - 1] = {
        interval: storedKeys[storedKeys.length - 2].interval,
        key: storedKeys[storedKeys.length - 2].key
      };
      storedKeys[storedKeys.length - 2] = {
        interval: Math.floor((xtminus1Sminus1 - xtminus1Sminus2) / 2),
        key: deriveKey(storedKeys, Math.floor((xtminus1Sminus1 - xtminus1Sminus2) / 2), senderInfo)
      };
    }
  }

  return storedKeys;
};

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Derive a key if it's not stored
const deriveKey = (storedKeys, targetInterval, senderInfo) => {
  let storedKey = storedKeys
    .filter(keyObj => keyObj.interval >= targetInterval)
    .sort((a, b) => a.interval - b.interval)[0];

  console.log(storedKey)

  if (storedKey.interval === targetInterval) {
    return storedKey.key;
  } else {
    const x = storedKey.interval - targetInterval;
    let derivedKey = storedKey.key;
    const start=performance.now()
    for (let i = 0; i < x; i++) {
      
      derivedKey = hash(derivedKey);
    }
    const end=performance.now()
    const time=end-start

    // Update the stored key for the completed interval
    let updateIndex = storedKeys.findIndex(keyObj => keyObj.interval < targetInterval);
    if (updateIndex !== -1) {
      storedKeys[updateIndex].interval = targetInterval;
      storedKeys[updateIndex].key = derivedKey;
    }

    console.log(storedKeys);
    return {derivedKey:derivedKey,time:time};
  }
};


// Sender server to broadcast HMACs and disclose keys
const createSenderServer = (port) => {
  const start=performance.now();
  let senderInfo = loadSenderInfo('sender1');  // Load sender info based on ID
  const end=performance.now()
  console.log(end-start)
  let currentInterval = senderInfo.startSlot;

  // Initial key storage (storing keys at specific intervals)
  let storedKeys = [
    { interval: currentInterval + 1000, key: senderInfo.keyChain[1000] },
    { interval: currentInterval + 900, key: senderInfo.keyChain[900] },
    { interval: currentInterval + 800, key: senderInfo.keyChain[800] },
    { interval: currentInterval + 700, key: senderInfo.keyChain[700] },
    { interval: currentInterval + 600, key: senderInfo.keyChain[600] },
    { interval: currentInterval + 500, key: senderInfo.keyChain[500] },
    { interval: currentInterval + 400, key: senderInfo.keyChain[400] },
    { interval: currentInterval + 300, key: senderInfo.keyChain[300] },
    { interval: currentInterval + 200, key: senderInfo.keyChain[200] },
    { interval: currentInterval + 100, key: senderInfo.keyChain[100] }
      
  ];

  let totalKeyDerivationTime = 0;  // Track total key derivation time

  const server = net.createServer((socket) => {
    let prevMessages = [];
    let keyDisclosed = false;
    let totalHmacTime = 0;
    let prevKey;
    let keyTime=0;

    const intervalId = setInterval(() => {
      if (currentInterval >= senderInfo.expirySlot) {
        // Reload sender info for new key chain
        senderInfo = loadSenderInfo('sender1');
        currentInterval = senderInfo.startSlot;

        // Update stored keys with new key chain
        storedKeys = [
          { interval: currentInterval + 20, key: senderInfo.keyChain[20] },
          { interval: currentInterval + 15, key: senderInfo.keyChain[15] },
          { interval: currentInterval + 10, key: senderInfo.keyChain[10] },
          { interval: currentInterval + 5, key: senderInfo.keyChain[5] }
        ];
        console.log(`New key chain loaded, starting at interval ${currentInterval}`);
      }

      // Derive the key for the current interval and measure the time taken
      const startKeyDerivation = performance.now();
      const {derivedKey,time} = deriveKey(storedKeys, currentInterval, senderInfo);
      const endKeyDerivation = performance.now();
     const key=derivedKey
      totalKeyDerivationTime += time;
      // console.log(`Time to derive key for interval ${currentInterval}: ${keyDerivationTime.toFixed(2)} ms`);
      console.log(totalKeyDerivationTime)

      const numberOfMessages = poisson(lambda);
      const messages = Array.from({ length: numberOfMessages }, (_, i) => `Packet ${i + 1} for interval ${currentInterval}`);

      // Broadcast HMACs
      const startHmac = performance.now();
      const currentHmacs = messages.map((message) => ({
        interval: currentInterval,
        hmac: hmac(key, message),
      }));
      const endHmac = performance.now();
      const hmacTime = endHmac - startHmac;
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

    // Handle server shutdown and display total key derivation time
    server.on('close', () => {
      console.log(`Total key derivation time: ${totalKeyDerivationTime.toFixed(2)} ms`);
    });

  });

  server.listen(port, () => {
    console.log(`Sender server listening on port ${port}`);
  });
};

// Start the sender server
createSenderServer(serverPort);

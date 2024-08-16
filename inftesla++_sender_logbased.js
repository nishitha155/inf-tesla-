const crypto = require('crypto');
const net = require('net');
const fs = require('fs');
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

// Key storage optimization algorithm
const keyStorageAlgorithm = (N, S, t, storedKeys,senderInfo) => {
  const xtminus1S = storedKeys[storedKeys.length - 1].interval;
  const xtminus1Sminus1 = storedKeys[storedKeys.length - 2].interval;
  const xtminus1Sminus2 = storedKeys[storedKeys.length - 3].interval;

  if (xtminus1S === t) {
    if (storedKeys.length >= 2 && (xtminus1S.interval - xtminus1Sminus1.interval) > 1) {
      storedKeys[storedKeys.length - 1] = {
        interval: Math.floor((xtminus1S.interval - xtminus1Sminus1.interval) / 2),
        key: deriveKey(storedKeys,Math.floor((xtminus1S.interval - xtminus1Sminus1.interval) / 2),senderInfo)
       
      };
    } else {
      storedKeys[storedKeys.length - 1] = {
        interval: storedKeys[storedKeys.length - 2].interval,
        key: storedKeys[storedKeys.length - 2].key
      };
      storedKeys[storedKeys.length - 2] = {
        interval: Math.floor((xtminus1Sminus1.interval - xtminus1Sminus2.interval) / 2),
        key: deriveKey(storedKeys,Math.floor((xtminus1Sminus1.interval - xtminus1Sminus2.interval) / 2),senderInfo)
      };
    }
  }

  return storedKeys;
};

const hash = (data) => {
    return crypto.createHash('sha256').update(data).digest('hex');
  };

// Derive a key if it's not stored
const deriveKey = (storedKeys, targetInterval, senderInfo) => {
    console.log(targetInterval)
    let storedKey = storedKeys
      .filter(keyObj => keyObj.interval >= targetInterval)
      .sort((a, b) => a.interval - b.interval)[0];
      console.log(storedKey)
   if(storedKey.interval==targetInterval){
      return storedKey.key
   }
    else  {
      const x=storedKey.interval-targetInterval;
      let derivedKey=storedKey.key
      for(let i=0;i<x;i++){
          derivedKey=hash(derivedKey)
      }
      if (storedKeys[1].interval < targetInterval) {
        storedKeys[1].interval = targetInterval;
        storedKeys[1].key = derivedKey;
      }
      return derivedKey;
      
    }
    
  };
  
// Sender server to broadcast HMACs and disclose keys
const createSenderServer = (port) => {
  const senderInfo = loadSenderInfo('sender1');  // Load sender info based on ID
  let currentInterval = senderInfo.startSlot;

  // Initial key storage (storing keys at intervals 6, 4, 2 for example)
  
  let storedKeys = [
    { interval: currentInterval + 1000, key: senderInfo.keyChain[100] },
    { interval: currentInterval + 512, key: senderInfo.keyChain[500] },
    // { interval: currentInterval + 10, key: senderInfo.keyChain[10] },
    // { interval: currentInterval + 5, key: senderInfo.keyChain[5] }
  ];


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

      // Run the key storage optimization algorithm
      //storedKeys = keyStorageAlgorithm(senderInfo.expirySlot-senderInfo.startSlot, storedKeys.length, currentInterval, storedKeys,senderInfo);
      console.log('storedkeys',storedKeys)
      // Derive the key for the current interval
      console.log('currentinterval',currentInterval)
      const key = deriveKey(storedKeys, currentInterval, senderInfo);
      console.log(key)

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
      prevKey=key;
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

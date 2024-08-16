const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const serverPorts = [12345]; // List of server ports
const serverHost = '127.0.0.1';
const nonce = crypto.randomBytes(16).toString('hex');

// Function to load sender info from file
const loadSenderInfo = () => {
  return JSON.parse(fs.readFileSync('sender1.json', 'utf8'));
};

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Function to verify a MAC
let prev={}
const verifyKey = (temp, interval, keyChain, startSlot) => {
  console.log('key being verified')
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


const verifyMac = (message, mac, key, interval, state,index) => {
  console.log(index)
  if(index==0){
    const { result: keyVerified, time: keyVerificationTime } = verifyKey(key, interval, state.keyChain, state.startSlot);
  state.totalKeyVerificationTime += keyVerificationTime;

  }
 
  

  // if (!keyVerified) {
  //   console.log(`Key verification failed for interval ${interval}`);
  //   return false;
  // }

  const start = performance.now();
  const computedMac = crypto.createHmac('sha256', key).update(message).digest('hex');
  const end = performance.now();
  state.totalMacVerificationTime += (end - start);
  return mac === computedMac;
};

// Function to store HMACs temporarily
const storeHmacs = (hmacs, state) => {
  hmacs.forEach(({ interval, hmac }) => {
    if (!state.storedHmacs[interval]) {
      state.storedHmacs[interval] = [];
    }
    state.storedHmacs[interval].push(hmac);
  });
};

// Function to update known keys and authenticate messages
const updateKnownKeys = (disclosures, state) => {
  disclosures.forEach(({ interval, message, prevKey,index }) => {
    let key = prevKey;

    if (key) {
      state.knownKeys[interval] = key;
    } else {
      key = state.knownKeys[interval];
    }

    // Authenticate stored messages
    const storedMacs = state.storedHmacs[interval];

    if (storedMacs && storedMacs.length > 0) {
      const messageIndex = parseInt(message.split(' ')[1]) - 1;

      if (messageIndex >= 0 && messageIndex < storedMacs.length) {
        const mac = storedMacs[messageIndex];

        if (mac) {
          if (verifyMac(message, mac, key, interval, state,index)) {
            console.log(`Message authenticated: ${message} with key ${key}`);
            storedMacs[messageIndex] = null;
          } else {
            console.log(`Message authentication failed: ${message} with key ${key}`);
          }
        } else {
          console.log(`No stored HMAC for message ${message} in interval ${interval}`);
        }
      } else {
        console.log(`Invalid message index for interval ${interval}: ${messageIndex}`);
      }
    } else {
      console.log(`No stored HMACs for interval ${interval}`);
    }
  });

  // Clean up authenticated HMACs
  for (const interval in state.storedHmacs) {
    state.storedHmacs[interval] = state.storedHmacs[interval].filter(mac => mac !== null);
    if (state.storedHmacs[interval].length === 0) {
      delete state.storedHmacs[interval];
    }
  }
};

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

// Function to start the receiver
const startReceiver = () => {
  const states = {}; // Stores the state for each sender, identified by port

  serverPorts.forEach((port) => {
    const initialSenderInfo = loadSenderInfo();

    states[port] = {
      startSlot: initialSenderInfo.startSlot,
      expirySlot: initialSenderInfo.expirySlot,
      keyChain: initialSenderInfo.keyChain, // Load key chain from sender info
      knownKeys: {},
      storedHmacs: {},
      totalKeyVerificationTime: 0,
      totalMacVerificationTime: 0,
      intervalCount: 0, // Track interval count
    };

    const client = net.createConnection({ port, host: serverHost }, () => {
      const start=performance.now()
      console.log(`Connected to sender on port ${port}`);

      client.write(`NONCE ${nonce}`);  // Send nonce to sender
      const end=performance.now()
      console.log(start-end)
    });

    client.on('data', (data) => {
      const message = data.toString();
      console.log('Received message:', message);
      try {
        const jsonArrays = message.match(/\[.*?\]/g);
        if (jsonArrays) {
          jsonArrays.forEach(jsonArray => {
            const parsedData = JSON.parse(jsonArray);
            processData(parsedData, states[port]);
          });
        } else {
          console.log('No valid JSON data found in the message');
        }
      } catch (error) {
        console.error('Error processing data:', error);
      }
      
    });

    function processData(parsedData, state) {
      console.log('Processing parsed data:', parsedData);

      if (Array.isArray(parsedData) && parsedData.length > 0) {
        if (parsedData[0].message) {
          // It's a disclosure
          updateKnownKeys(parsedData, state);
        } else {
          // It's HMACs
          storeHmacs(parsedData, state);
        }

      } else {
        console.log('Parsed data is not a valid array or is empty');
      }

      state.intervalCount += 1;
      console.log('Interval count:', state.intervalCount);

      // Check if 40 intervals have passed
      if ((state.intervalCount) % 40 === 0) {
        console.log('Reloading sender info after 40 intervals');
        const newSenderInfo = loadSenderInfo();
        state.startSlot = newSenderInfo.startSlot;
        state.expirySlot = newSenderInfo.expirySlot;
        state.keyChain = newSenderInfo.keyChain;
      }
      console.log(`Total key verification time: ${state.totalKeyVerificationTime.toFixed(2)} ms`);
      console.log(`Total MAC verification time: ${state.totalMacVerificationTime.toFixed(2)} ms`);
    }

    client.on('end', () => {
      const state = states[port];
      console.log(`Disconnected from sender on port ${port}`);
      console.log(`Total key verification time: ${state.totalKeyVerificationTime.toFixed(2)} ms`);
      console.log(`Total MAC verification time: ${state.totalMacVerificationTime.toFixed(2)} ms`);

      // Calculate storage overhead
      const keyChainMemoryUsage = calculateMemoryUsage(state.keyChain);
      const storedHmacsMemoryUsage = calculateMemoryUsage(state.storedHmacs);

      console.log(`Memory usage for key chain: ${keyChainMemoryUsage} bytes`);
      console.log(`Memory usage for stored HMACs: ${storedHmacsMemoryUsage} bytes`);

      // Calculate total authentication time
      const totalAuthenticationTime = state.totalKeyVerificationTime + state.totalMacVerificationTime;
      console.log(`Total authentication time: ${totalAuthenticationTime.toFixed(2)} ms`);
    });

    client.on('error', (err) => {
      console.error(`Connection error on port ${port}: ${err.message}`);
    });
  });
};

// Run the receiver
startReceiver();

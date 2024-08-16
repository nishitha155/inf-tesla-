const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const serverPorts = [12345]; // List of server ports
const serverHost = '127.0.0.1';
const nonce = crypto.randomBytes(16).toString('hex');
const keyChainLength = 4;

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Function to verify a key
const verifyKey = (temp, interval, knownKeys) => {
  const start = performance.now();
  if (!knownKeys || knownKeys.length === 0) {
    console.log('Known keys not properly initialized');
    return { result: false, time: 0 };
  }
  const chainSetIndex = Math.floor(interval / (2 * keyChainLength));
  const chainIndex = chainSetIndex * 2 + (interval % 2);
  const keyIndex = Math.floor((interval % (2 * keyChainLength)) / 2);
  if (!knownKeys[chainIndex]) {
    console.log(`Chain ${chainIndex} not found in known keys`);
    return { result: false, time: 0 };
  }
  let hashedKey = knownKeys[chainIndex][0];
  for (let i = 0; i < keyIndex; i++) {
    hashedKey = hash(hashedKey);
  }
  const end = performance.now();
  return { result: hashedKey === temp, time: end - start };
};

// Function to verify a MAC using the key disclosed with the first packet in the interval
const verifyMac = (message, mac, interval, state) => {
  // const { result: keyVerified, time: keyVerificationTime } = verifyKey(key, interval, state.knownKeys);
  // state.totalKeyVerificationTime += keyVerificationTime;
  // key = state.disclosedKeys[interval]

  // if (!keyVerified) {
  //   console.log(`Key verification failed for interval ${interval}`);
  //   return false;
  // }


  const key = state.disclosedKeys[interval];
  if (!key) {
    console.log(`No key disclosed for interval ${interval}`);
    return false;
  }

  const start = performance.now();
  const computedMac = crypto.createHmac('sha256', key).update(message).digest('hex');
  const end = performance.now();
  state.totalMacVerificationTime += end - start;

  return mac === computedMac;
};

// Function to store HMACs temporarily
const storeHmacs = (hmacs, state) => {
  hmacs.forEach(({ interval, mac }) => {
    if (!state.storedHmacs[interval]) {
      state.storedHmacs[interval] = [];
    }
    state.storedHmacs[interval].push(mac);
  });
};

const updateKnownKeys = (disclosures, state) => {
  console.log('Disclosures:', disclosures);

  disclosures.forEach((disclosure) => {
    const { interval, message, key, newChainKey, iv } = disclosure;

    if (newChainKey) {
      // Decrypt and add new chain key
      const start=performance.now()
      const ivBuffer = Buffer.from(iv, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(state.currentRandomKey, 'hex'), ivBuffer);
      let decryptedKey = decipher.update(Buffer.from(newChainKey, 'hex'));
      decryptedKey = Buffer.concat([decryptedKey, decipher.final()]).toString('hex');
      state.knownKeys.push([decryptedKey]);
      state.currentRandomKey = hash(state.currentRandomKey);
      const end=performance.now()
          console.log('new',end-start)
    } else if (key) {
      // Store the disclosed key for the interval if not already stored
      if (!state.disclosedKeys[interval]) {
        state.disclosedKeys[interval] = key;
        console.log(`Disclosed key for interval ${interval}: ${key}`);
      }

      // Authenticate stored messages
      const storedMacs = state.storedHmacs[interval];
      console.log(`Stored MACs for interval ${interval}:`, storedMacs);

      if (storedMacs && storedMacs.length > 0) {
        const messageIndex = parseInt(message.split(' ')[1]) - 1;

        if (messageIndex >= 0 && messageIndex < storedMacs.length) {
          const mac = storedMacs[messageIndex];

          if (mac) {
            if (verifyMac(message, mac, interval, state)) {
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

// Function to start the receiver
const startReceiver = () => {
  const states = {}; // Stores the state for each sender, identified by port

  serverPorts.forEach((port) => {
    states[port] = {
      knownKeys: [], // Initialize as an empty array that can hold multiple arrays
      storedHmacs: {},
      disclosedKeys: {}, // Stores the disclosed keys per interval
      totalKeyVerificationTime: 0,
      totalMacVerificationTime: 0,
      currentRandomKey: null,
    };

    const client = net.createConnection({ port, host: serverHost }, () => {
      const start = performance.now();
      console.log(`Connected to sender on port ${port}`);
      client.write(`NONCE ${nonce}`);  // Send nonce to sender
      const end = performance.now();
      console.log(end-start)
    });

    client.on('data', (data) => {
      const message = data.toString();
      console.log('Received message:', message);
      try {
        // First, try to parse the entire message as a single JSON array
        try {
          const parsedData = JSON.parse(message);
          processData(parsedData, states[port]);
        } catch (singleParseError) {
          // If parsing as a single JSON fails, try to split into multiple JSON arrays
          const jsonArrays = message.match(/\[.*?\]/g);
          if (jsonArrays) {
            jsonArrays.forEach(jsonArray => {
              try {
                const parsedData = JSON.parse(jsonArray);
                processData(parsedData, states[port]);
              } catch (arrayParseError) {
                console.error('Error parsing JSON array:', arrayParseError);
              }
            });
          } else {
            console.log('No valid JSON data found in the message');
          }
        }
      } catch (error) {
        console.error('Error processing data:', error);
      }
    });

    function processData(parsedData, state) {
      console.log('Processing parsed data:', parsedData);
      
      // Convert single object to array if necessary
      const dataArray = Array.isArray(parsedData) ? parsedData : [parsedData];
      
      if (dataArray.length > 0) {
        const firstItem = dataArray[0];
        if (firstItem.MAC) {
          // Handle bootstrapping response
          const macData = `${nonce}${firstItem.TS}${firstItem.Ki1}${firstItem.Ki2}${firstItem.Ti}${firstItem.Tint}${firstItem.disclosureDelay}${firstItem.randomKey}`;
          const mac = crypto.createHmac('sha256', 'shared_secret').update(macData).digest('hex');
          if (mac === firstItem.MAC) {
            console.log('Bootstrap successful:', firstItem);
            state.knownKeys[0] = [firstItem.Ki1];
            state.knownKeys[1] = [firstItem.Ki2];
            state.currentRandomKey = firstItem.randomKey;
          } else {
            console.log('Bootstrap failed: MAC verification failed');
          }
        } else if (firstItem.message !== undefined || firstItem.newChainKey !== undefined) {
          // It's a disclosure
          updateKnownKeys(dataArray, state);
        } else {
          storeHmacs(dataArray, state);
          console.log('Stored HMACs:', state.storedHmacs);
        }
      } else {
        console.log('Parsed data is empty');
      }
    }

    client.on('end', () => {
      const state = states[port];
      console.log(`Disconnected from sender on port ${port}`);
      console.log(`Total key verification time: ${state.totalKeyVerificationTime.toFixed(2)} ms`);
      console.log(`Total MAC verification time: ${state.totalMacVerificationTime.toFixed(2)} ms`);

      // Calculate storage overhead
      const knownKeysMemoryUsage = calculateMemoryUsage(state.knownKeys);
      const storedHmacsMemoryUsage = calculateMemoryUsage(state.storedHmacs);

      console.log(`Memory usage for known keys: ${knownKeysMemoryUsage} bytes`);
      console.log(`Memory usage for stored HMACs: ${storedHmacsMemoryUsage} bytes`);
    });

    client.on('error', (err) => {
      console.error(`Connection error on port ${port}:`, err);
    });
  });
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

// Run the receiver
startReceiver();

const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const serverPorts = [12345, 12346]; // List of server ports
const serverHost = '127.0.0.1';
const nonce = crypto.randomBytes(16).toString('hex');

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

const verifyKey = (temp, interval, knownKeys) => {
    const start = performance.now();
    let hashedKey = knownKeys[0];
    for (let i = 0; i < interval; i++) {
      temp = hash(temp);
    }
    const end = performance.now();
    return { result: hashedKey === temp, time: end - start };
  };

  
  const verifyMac = (message, mac, key, interval, state) => {
    const { result: keyVerified, time: keyVerificationTime } = verifyKey(key, interval, state.knownKeys);
    state.totalKeyVerificationTime += keyVerificationTime;
  
    if (!keyVerified) {
      console.log(`Key verification failed for interval ${interval}`);
      return false;
    }
  
    const start = performance.now();
    const computedMac = crypto.createHmac('sha256', key).update(message).digest('hex');
    const end = performance.now();
    state.totalMacVerificationTime += (end - start);
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

// Function to update known keys and authenticate messages
const updateKnownKeys = (disclosures, state) => {
  console.log('Disclosures:', disclosures);

  disclosures.forEach(({ interval, message, key }) => {
    if (key) {
      state.knownKeys[interval] = key;
      
      // Derive and store keys for previous intervals
      for (let i = interval - 1; i >= 0; i--) {
        if (!state.knownKeys[i]) {
          state.knownKeys[i] = hash(state.knownKeys[i + 1]);
        } else {
          break;
        }
      }

      // Try to authenticate stored HMACs for previous intervals
      for (let i = interval - 1; i >= 0; i--) {
        if (state.storedHmacs[i] && state.storedHmacs[i].length > 0) {
          authenticateStoredHmacs(i, state);
        }
      }
    }

    // Authenticate current interval's messages
    if (state.storedHmacs[interval] && state.storedHmacs[interval].length > 0) {
      authenticateStoredHmacs(interval, state);
    }
  });
};

// Function to authenticate stored HMACs for a given interval
const authenticateStoredHmacs = (interval, state) => {
  const key = state.knownKeys[interval];
  const storedHmacs = state.storedHmacs[interval];

  console.log(`Authenticating stored HMACs for interval ${interval}`);

  storedHmacs.forEach((storedHmac, index) => {
    const message = `Packet ${index + 1} for interval ${interval}`;
    if (verifyMac(message, storedHmac, key)) {
      console.log(`Message authenticated: ${message}`);
      storedHmacs[index] = null; // Mark as authenticated
    } else {
      console.log(`Message authentication failed: ${message}`);
    }
  });

  // Remove authenticated HMACs
  state.storedHmacs[interval] = storedHmacs.filter(hmac => hmac !== null);
  if (state.storedHmacs[interval].length === 0) {
    delete state.storedHmacs[interval];
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
    states[port] = {
      knownKeys: {},
      storedHmacs: {},
      totalKeyVerificationTime: 0,
      totalMacVerificationTime: 0,
    };

    const client = net.createConnection({ port, host: serverHost }, () => {
      console.log(`Connected to sender on port ${port}`);
      client.write(`NONCE ${nonce}`);  // Send nonce to sender
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
      
      if (Array.isArray(parsedData) && parsedData.length > 0) {
        if (parsedData[0].MAC) {
          // Handle bootstrapping response
          const macData = `${nonce}${parsedData[0].TS}${parsedData[0].Ki}${parsedData[0].Ti}${parsedData[0].Tint}${parsedData[0].disclosureDelay}`;
          const mac = crypto.createHmac('sha256', 'shared_secret').update(macData).digest('hex');
          if (mac === parsedData[0].MAC) {
            console.log('Bootstrap successful:', parsedData[0]);
            state.knownKeys[0] = parsedData[0].Ki;  // Store commitment key
          } else {
            console.log('Bootstrap failed: MAC verification failed');
          }
        } else if (parsedData[0].message) {
          // It's a disclosure
          updateKnownKeys(parsedData, state);
        } else {
          // It's HMACs
          storeHmacs(parsedData, state);
          console.log('Stored HMACs:', state.storedHmacs);
        }
      } else {
        console.log('Parsed data is not a valid array or is empty');
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

// Run the receiver
startReceiver();
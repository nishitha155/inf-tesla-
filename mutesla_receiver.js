const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks');

// Configuration
const serverPort = 12345;
const serverHost = '127.0.0.1';
const nonce = crypto.randomBytes(16).toString('hex');

// Initialize variables
let knownKeys = {};
let storedHmacs = {};
let totalKeyVerificationTime = 0;
let totalMacVerificationTime = 0;

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Function to verify a MAC
const verifyKey = (temp, interval) => {
  const start = performance.now();
  let hashedKey = knownKeys[0];
  for (let i = 0; i < interval; i++) {
    temp = hash(temp);
  }
  const end = performance.now();
  totalKeyVerificationTime += (end - start);
  return hashedKey === temp;
};

const verifyMac = (message, mac, key, interval) => {
  if (!verifyKey(key, interval)) {
    console.log(`Key verification failed for interval ${interval}`);
    return false;
  }
  const start = performance.now();
  const computedMac = crypto.createHmac('sha256', key).update(message).digest('hex');
  const end = performance.now();
  totalMacVerificationTime += (end - start);
  return mac === computedMac;
};

// Function to store HMACs temporarily
const storeHmacs = (hmacs) => {
  hmacs.forEach(({ interval, mac }) => {
    if (!storedHmacs[interval]) {
      storedHmacs[interval] = [];
    }
    storedHmacs[interval].push(mac);
  });
};

// Function to update known keys and authenticate messages
const updateKnownKeys = (disclosures) => {
  console.log('Disclosures:', disclosures);

  disclosures.forEach(({ interval, message, key }, index) => {
    if (key) {
      knownKeys[interval] = key;
    } else {
      key = knownKeys[interval];
    }

    // Authenticate stored messages
    const storedMacs = storedHmacs[interval];
    console.log(`Stored MACs for interval ${interval}:`, storedMacs);

    if (storedMacs && storedMacs.length > 0) {
      // Find the index of the current message in the interval
      const messageIndex = parseInt(message.split(' ')[1]) - 1;

      if (messageIndex >= 0 && messageIndex < storedMacs.length) {
        const mac = storedMacs[messageIndex];

        if (mac) {
          if (verifyMac(message, mac, key, interval)) {
            console.log(`Message authenticated: ${message} with key ${key}`);
            // Remove the authenticated HMAC from the list
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
  for (const interval in storedHmacs) {
    storedHmacs[interval] = storedHmacs[interval].filter(mac => mac !== null);
    if (storedHmacs[interval].length === 0) {
      delete storedHmacs[interval];
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
  // Connect to the sender
  const client = net.createConnection({ port: serverPort, host: serverHost }, () => {
    console.log('Connected to sender');
    client.write(`NONCE ${nonce}`);  // Send nonce to sender
  });

  client.on('data', (data) => {
    const message = data.toString();
    try {
      const parsedData = JSON.parse(message);

      if (parsedData.MAC) {
        // Handle bootstrapping response
        const macData = `${nonce}${parsedData.TS}${parsedData.Ki}${parsedData.Ti}${parsedData.Tint}${parsedData.disclosureDelay}`;
        const mac = crypto.createHmac('sha256', 'shared_secret').update(macData).digest('hex');
        if (mac === parsedData.MAC) {
          console.log('Bootstrap successful:', parsedData);
          knownKeys[0] = parsedData.Ki;  // Store commitment key
        } else {
          console.log('Bootstrap failed: MAC verification failed');
        }
      } else if (Array.isArray(parsedData)) {
        // Handle HMACs or disclosures
        if (parsedData[0].message) {
          // It's a disclosure
          updateKnownKeys(parsedData);
        } else {
          // It's HMACs
          storeHmacs(parsedData);
          console.log('Stored HMACs:', storedHmacs);
        }
      }
    } catch (error) {
      console.error('Error parsing data:', error);
    }
  });

  client.on('end', () => {
    console.log('Disconnected from sender');
    console.log(`Total key verification time: ${totalKeyVerificationTime.toFixed(2)} ms`);
    console.log(`Total MAC verification time: ${totalMacVerificationTime.toFixed(2)} ms`);

    // Calculate storage overhead
    const knownKeysMemoryUsage = calculateMemoryUsage(knownKeys);
    const storedHmacsMemoryUsage = calculateMemoryUsage(storedHmacs);

    console.log(`Memory usage for known keys: ${knownKeysMemoryUsage} bytes`);
    console.log(`Memory usage for stored HMACs: ${storedHmacsMemoryUsage} bytes`);
  });
};

// Run the receiver
startReceiver();

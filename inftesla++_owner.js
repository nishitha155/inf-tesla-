const crypto = require('crypto');
const fs = require('fs');
const { performance } = require('perf_hooks');

// Configuration
const keyChainLength = 1000;  // Number of keys in the hash chain
const slotDuration = 1000;  // Slot duration in milliseconds (12 seconds)

// Function to generate a random key
const generateRandomKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Function to apply SHA-256 hash
const hash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Generate key chain
const generateKeyChain = (length) => {
  let keys = [];
  keys[length] = generateRandomKey();
  for (let i = length - 1; i >= 0; i--) {
    keys[i] = hash(keys[i + 1]);
  }
  return keys;
};

// Function to create or update sender info file
const createOrUpdateSenderInfo = (id, newKeys, startSlot, expirySlot) => {
  const filePath = `${id}.json`;

  // Create or overwrite the sender info with the new key chain
  const senderInfo = {
    id,
    startSlot,
    expirySlot,
    keyChain: newKeys,  // Replace with the new key chain
  };

  const startWrite = performance.now();  // Start timing file write
  fs.writeFileSync(filePath, JSON.stringify(senderInfo, null, 2));
  const endWrite = performance.now();  // End timing file write

  console.log(`Sender information updated in file: ${id}.json`);
  console.log(`Time taken to write to file: ${(endWrite - startWrite).toFixed(2)} milliseconds`);
};

// Generate and save key chain for a sender
const createSender = (id, currentSlot) => {
  let startSlot = currentSlot;
  let expirySlot = startSlot + keyChainLength;

  const startGen = performance.now();  // Start timing key chain generation
  let keyChain = generateKeyChain(keyChainLength);
  const endGen = performance.now();  // End timing key chain generation

  createOrUpdateSenderInfo(id, keyChain, startSlot, expirySlot);

  console.log(`Time taken to generate key chain: ${(endGen - startGen).toFixed(2)} milliseconds`);
};

// Function to handle key chain regeneration
const regenerateKeyChainIfNeeded = (id, currentSlot) => {
  const senderInfo = JSON.parse(fs.readFileSync(`${id}.json`));

  if (currentSlot >= senderInfo.expirySlot) {
    const newStartSlot = senderInfo.expirySlot;
    const newExpirySlot = newStartSlot + keyChainLength;

    // Generate a new key chain and overwrite the existing one in sender info
    createSender(id, newStartSlot);

    console.log(`New key chain generated for sender ${id} starting at slot ${newStartSlot}`);
  } else {
    console.log(`Current slot ${currentSlot} is within the existing key chain range.`);
  }
};

// Example usage
let currentSlot = 0;  // This would be the current slot number from the system
const senderId = 'sender1';

// Initial creation of the sender and key chain
createSender(senderId, currentSlot);

// Simulate the progression of slots and key chain regeneration
setInterval(() => {
  regenerateKeyChainIfNeeded(senderId, currentSlot);
  currentSlot++;
}, slotDuration);

"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const SALT_LENGTH = 16;           // Length of salt for PBKDF2
const AES_KEY_LENGTH = 256;       // AES key length in bits
const HMAC_KEY_LENGTH = 256;      // HMAC key length in bits
const IV_LENGTH = 12;             // AES-GCM IV length

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = {};
    this.kvs = {};
    this.secrets = {
         masterKey: null,
         salt: null,
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    let keychain = new Keychain();

    keychain.secrets.salt = getRandomBytes(SALT_LENGTH); 

    keychain.secrets.masterKey = await Keychain.deriveKey(password, keychain.secrets.salt);

    keychain.secrets.verification = await Keychain.encrypt(keychain.secrets.masterKey, "test");

    return keychain;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    let parsed = JSON.parse(repr);
    let keychain = new Keychain();

    
    if (trustedDataCheck) {
        let computedHash = await Keychain.hashData(repr);
        if (computedHash !== trustedDataCheck) {
          throw new Error("Data integrity check failed! Possible rollback attack.");
        }
    }

    keychain.secrets.salt = decodeBuffer(parsed.salt);
    keychain.secrets.masterKey = await Keychain.deriveKey(password, keychain.secrets.salt);

    try {
      let decryptedTest = await Keychain.decrypt(keychain.secrets.masterKey, parsed.verification);
      if (decryptedTest !== "test") throw new Error("Incorrect password.");
    } catch (error) {
      throw new Error("Incorrect password.");
    }

    keychain.kvs = parsed.kvs || {};
    return keychain;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    let data = JSON.stringify({ 
      kvs: this.kvs,
      salt: encodeBuffer(this.secrets.salt),
      verification: this.secrets.verification
    });

    return [data, await Keychain.hashData(data)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (!this.kvs || !this.secrets.masterKey) throw new Error("Key-value store or master key is not initialized.");

    let hmacKey = await Keychain.deriveHMACKey(this.secrets.masterKey);
    let obfuscatedKey = await Keychain.computeHMAC(hmacKey, name);

    if (!this.kvs[obfuscatedKey]) return null;

    return await Keychain.decrypt(this.secrets.masterKey, this.kvs[obfuscatedKey]);
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (!this.kvs || !this.secrets.masterKey) throw new Error("Key-value store or master key is not initialized.");

    let hmacKey = await Keychain.deriveHMACKey(this.secrets.masterKey);
    let obfuscatedKey = await Keychain.computeHMAC(hmacKey, name);

    const encryptedValue = await Keychain.encrypt(this.secrets.masterKey, value);
    this.kvs[obfuscatedKey] = encryptedValue;

  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (!this.kvs) throw new Error("Key-value store is not initialized.");

    let hmacKey = await Keychain.deriveHMACKey(this.secrets.masterKey);
    let obfuscatedKey = await Keychain.computeHMAC(hmacKey, name);

    if (this.kvs.hasOwnProperty(obfuscatedKey)) {
        delete this.kvs[obfuscatedKey];
        return true;
    }
    return false;
  };

  /********* Utility Functions ********/

  static async deriveKey(password, salt) {
    let keyMaterial = await subtle.importKey(
        "raw",
        stringToBuffer(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return await subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

  static async deriveHMACKey(masterKey) {
    const rawKey = await subtle.exportKey("raw", masterKey);
    return subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
  }

  static async computeHMAC(key, data) {
    const signature = await subtle.sign("HMAC", key, stringToBuffer(data));
    return encodeBuffer(signature);
  }

  static async encrypt(key, plaintext) {
    const iv = getRandomBytes(IV_LENGTH);
    const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, stringToBuffer(plaintext));
    return { iv: encodeBuffer(iv), data: encodeBuffer(ciphertext) };
  }

  static async decrypt(key, encryptedData) {
    const iv = decodeBuffer(encryptedData.iv);
    const ciphertext = decodeBuffer(encryptedData.data);
    const plaintextBuffer = await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return bufferToString(plaintextBuffer);
  }

  static async hashData(data) {
    const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(data));
    return encodeBuffer(hashBuffer);
  }
};

module.exports = { Keychain }
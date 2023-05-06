import fs from 'fs';
import sha256 from 'crypto-js/sha256';
import process from 'process';

const filePath = './password.bin';
const secretKey = 'mySecretKey';

/**
 * Prints the usage instructions for the app.
 *
 * @returns {void}
 */
function usage() {
    console.log('Usage: node app.js store|check <password>');
}

/**
 * Stores a hashed password in a file.
 * 
 * @param {string} filePath - The path to the file where the hashed password will be stored.
 * @param {string} password - The password to be hashed and stored.
 * @returns {Promise<boolean>} - A promise that resolves to true if the password was successfully hashed and stored, and false otherwise.
 */
async function storePassword(filePath, password) {
    try {
        const encryptedPassword = sha256(password).toString();
        await fs.promises.writeFile(filePath, encryptedPassword);
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Check if the provided password matches the hashed password stored in the specified file.
 *
 * @param {string} filePath - The path to the file containing the hashed password.
 * @param {string} password - The password to be checked.
 * @returns {Promise<boolean|undefined>} - Resolves with true if the password matches, false otherwise. Rejects with an error if one occurs.
 */
async function checkPassword(filePath, password) {
    try {
        const storedHashedPassword = await fs.promises.readFile(filePath, { encoding: 'utf-8' });
        const hashedPassword = sha256(password).toString();
        return storedHashedPassword === hashedPassword;
    } catch (error) {
        return undefined;
    }
}

if (process.argv.length !== 4) {
    usage();
    process.exit(1);
}

const action = process.argv[2];
const password = process.argv[3];

switch (action) {
    case 'store':
        const result = await storePassword(filePath, password);
        if (result) {
            console.log('Password stored successfully.');
        } else {
            console.log('Failed to store password.');
        }
        break;
    case 'check':
        const isPasswordValid = await checkPassword(filePath, password);
        if (isPasswordValid === undefined) {
            console.log('Password not found. Store it first.');
            usage();
        } else {
            console.log(`The provided password is ${isPasswordValid ? 'valid' : 'invalid'}.`);
        }
        break;
    default:
        console.log(`Unknown action: ${action}.`);
        usage();
        process.exit(1);
}


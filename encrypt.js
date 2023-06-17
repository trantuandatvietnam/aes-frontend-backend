import CryptoJS from "crypto-js"

function encryptData(plaintext) {
  const key = CryptoJS.enc.Utf8.parse(secretKey);
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const encryptMessage = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
  return {
    encryptMessage,
    iv: iv.toString(CryptoJS.enc.Hex),
  };
}

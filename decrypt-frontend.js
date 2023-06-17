import CryptoJS from "crypto-js"

function decrypt(encryptedData) {
  try {
    const key = CryptoJS.enc.Utf8.parse(secretKey);
    const ivString = encryptedData.substring(0, 24);
    const encryptedString = encryptedData.substring(24);
    const iv = CryptoJS.enc.Base64.parse(ivString);

    const decrypted = CryptoJS.AES.decrypt(encryptedString, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    return decryptedText;
  } catch (error) {
    console.log(error);
    return null;
  }
}

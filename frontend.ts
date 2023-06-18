import CryptoJS from 'crypto-js'

function encrypt(plaintext: string) {
  try {
    const key = CryptoJS.enc.Utf8.parse(process.env.REACT_APP_SECRET_AES_KEY as string)
    const iv = CryptoJS.lib.WordArray.random(16)
    const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    })

    const encryptMessage = encrypted.ciphertext.toString(CryptoJS.enc.Base64)
    return iv.toString(CryptoJS.enc.Base64) + encryptMessage
  } catch (error) {
    return null
  }
}

function decrypt(encryptedData: string) {
  try {
    const key = CryptoJS.enc.Utf8.parse(process.env.REACT_APP_SECRET_AES_KEY as string)
    const ivString = encryptedData.substring(0, 24)
    const encryptedString = encryptedData.substring(24)
    
    const iv = CryptoJS.enc.Base64.parse(ivString)

    const decrypted = CryptoJS.AES.decrypt(encryptedString, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    })

    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8)
    return decryptedText
  } catch (error) {
    console.log(error)
    return null
  }
}

export const AES = {
  decrypt,
  encrypt,
}

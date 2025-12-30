import { NextResponse } from "next/server"
import crypto from "crypto"

// RSA Key Pair Storage (in production, use secure key management)
const rsaKeys = new Map<string, { publicKey: string, privateKey: string }>()

// RSA Functions
function generateRSAKeyPair(keyId: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })

  rsaKeys.set(keyId, { publicKey, privateKey })
  return { publicKey, privateKey }
}

function signWithRSA(message: string, privateKey: string): string {
  const sign = crypto.createSign('SHA256')
  sign.update(message)
  const signature = sign.sign(privateKey, 'base64')
  return signature
}

function verifyWithRSA(message: string, signature: string, publicKey: string): boolean {
  try {
    const verify = crypto.createVerify('SHA256')
    verify.update(message)
    return verify.verify(publicKey, signature, 'base64')
  } catch {
    return false
  }
}

function getRSAKeys(keyId: string) {
  return rsaKeys.get(keyId)
}

class HMACSHA512 {
  private blockSize = 128 // SHA512 block size
  private opad = Buffer.alloc(this.blockSize, 0x5c)
  private ipad = Buffer.alloc(this.blockSize, 0x36)

  private hash(data: Buffer): Buffer {
    return crypto.createHash('sha512').update(data).digest()
  }

  private xorBuffers(a: Buffer, b: Buffer): Buffer {
    const result = Buffer.alloc(a.length)
    for (let i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i]
    }
    return result
  }

  compute(message: string, key: string): Buffer {
    const keyBytes = Buffer.from(key, 'utf-8')

    // Prepare key
    let keyPadded: Buffer
    if (keyBytes.length > this.blockSize) {
      const keyHash = this.hash(keyBytes)
      keyPadded = Buffer.concat([keyHash, Buffer.alloc(this.blockSize - keyHash.length, 0)])
    } else {
      keyPadded = Buffer.concat([keyBytes, Buffer.alloc(this.blockSize - keyBytes.length, 0)])
    }

    // Inner hash
    const innerKey = this.xorBuffers(keyPadded, this.ipad)
    const innerData = Buffer.concat([innerKey, Buffer.from(message, 'utf-8')])
    const innerHash = this.hash(innerData)

    // Outer hash
    const outerKey = this.xorBuffers(keyPadded, this.opad)
    const outerData = Buffer.concat([outerKey, innerHash])
    const outerHash = this.hash(outerData)

    return outerHash
  }
}

// Encrypt message using secret key for secure storage
function encryptMessage(message: string, secretKey: string): string {
  const key = crypto.scryptSync(secretKey, 'salt', 32)
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  let encrypted = cipher.update(message, 'utf-8', 'base64')
  encrypted += cipher.final('base64')
  return iv.toString('base64') + '.' + encrypted
}

// Decrypt message using secret key
function decryptMessage(encryptedData: string, secretKey: string): string | null {
  try {
    const [ivB64, encrypted] = encryptedData.split('.')
    const key = crypto.scryptSync(secretKey, 'salt', 32)
    const iv = Buffer.from(ivB64, 'base64')
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    let decrypted = decipher.update(encrypted, 'base64', 'utf-8')
    decrypted += decipher.final('utf-8')
    return decrypted
  } catch {
    return null
  }
}

function generateSecureSignature(message: string, secretKey: string): string {
  // Encrypt the message
  const encryptedMessage = encryptMessage(message, secretKey)

  // Generate HMAC signature of the encrypted message
  const hmac = new HMACSHA512()
  const signature = hmac.compute(encryptedMessage, secretKey)

  // Combine encrypted message and signature
  const combined = Buffer.concat([
    Buffer.from(encryptedMessage, 'utf-8'),
    Buffer.from('|SEPARATOR|', 'utf-8'),
    signature
  ])

  return combined.toString('base64')
}

function verifyAndDecryptSignature(signature: string, secretKey: string): { valid: boolean, message?: string } {
  try {
    // Decode the combined data
    const combinedData = Buffer.from(signature, 'base64')
    const separator = Buffer.from('|SEPARATOR|', 'utf-8')
    const separatorIndex = combinedData.indexOf(separator)

    if (separatorIndex === -1) {
      return { valid: false }
    }

    // Extract encrypted message and signature
    const encryptedMessage = combinedData.subarray(0, separatorIndex).toString('utf-8')
    const storedSignature = combinedData.subarray(separatorIndex + separator.length)

    // Verify HMAC signature
    const hmac = new HMACSHA512()
    const expectedSignature = hmac.compute(encryptedMessage, secretKey)

    const signaturesMatch = crypto.timingSafeEqual(expectedSignature, storedSignature)

    if (!signaturesMatch) {
      return { valid: false }
    }

    // Decrypt the message
    const decryptedMessage = decryptMessage(encryptedMessage, secretKey)

    if (!decryptedMessage) {
      return { valid: false }
    }

    return { valid: true, message: decryptedMessage }
  } catch {
    return { valid: false }
  }
}

export async function POST(req: Request) {
  try {
    const { action, message, secret, signature, keyId, publicKey } = await req.json()

    // HMAC Actions
    if (action === "generate") {
      if (!message || !secret) {
        return NextResponse.json({ error: "Message and secret are required" }, { status: 400 })
      }

      const secureSignature = generateSecureSignature(message, secret)
      return NextResponse.json({ signature: secureSignature })
    }

    if (action === "verify") {
      if (!signature || !secret) {
        return NextResponse.json({ error: "Signature and secret are required for verification" }, { status: 400 })
      }

      const result = verifyAndDecryptSignature(signature, secret)

      if (result.valid && result.message) {
        return NextResponse.json({
          valid: true,
          message: result.message,
          status: "Document successfully decrypted and verified!"
        })
      } else {
        return NextResponse.json({
          valid: false,
          error: "Invalid signature or secret key"
        })
      }
    }

    // RSA Actions
    if (action === "generate-rsa-keys") {
      if (!keyId) {
        return NextResponse.json({ error: "Key ID is required" }, { status: 400 })
      }

      const keyPair = generateRSAKeyPair(keyId)
      return NextResponse.json({
        success: true,
        publicKey: keyPair.publicKey,
        message: "RSA key pair generated successfully"
      })
    }

    if (action === "rsa-sign") {
      if (!message || !keyId) {
        return NextResponse.json({ error: "Message and key ID are required" }, { status: 400 })
      }

      const keys = getRSAKeys(keyId)
      if (!keys) {
        return NextResponse.json({ error: "RSA key pair not found. Generate keys first." }, { status: 400 })
      }

      const rsaSignature = signWithRSA(message, keys.privateKey)
      return NextResponse.json({
        signature: rsaSignature,
        publicKey: keys.publicKey
      })
    }

    if (action === "rsa-verify") {
      if (!message || !signature || !publicKey) {
        return NextResponse.json({ error: "Message, signature, and public key are required" }, { status: 400 })
      }

      const isValid = verifyWithRSA(message, signature, publicKey)
      return NextResponse.json({
        valid: isValid,
        status: isValid ? "RSA signature verified successfully!" : "RSA signature verification failed"
      })
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 })
  } catch (error) {
    console.error("API Error:", error)
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 })
  }
}

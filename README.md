# Digital Signature with HMAC-SHA512

A secure digital document signing and verification system built with Next.js, featuring custom HMAC-SHA512 implementation, AES-256 encryption, and document download capabilities.

![Digital Signature](https://img.shields.io/badge/Security-HMAC--SHA512-blue)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--CBC-green)
![Frontend](https://img.shields.io/badge/Frontend-Next.js-black)
![UI](https://img.shields.io/badge/UI-shadcn/ui-purple)

## 🔐 Features

- **Custom HMAC-SHA512 Implementation**: Built from scratch without external crypto libraries
- **Document Encryption**: AES-256-CBC encryption for secure document storage
- **Secure Verification**: Constant-time comparison to prevent timing attacks
- **Document Download**: Download decrypted documents as .txt files
- **Modern UI**: Beautiful interface with shadcn/ui components and Lucide icons
- **Real-time Feedback**: Toast notifications and loading states

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- npm or pnpm

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd digital-signature-with-hmac
```

2. Install dependencies:
```bash
npm install
# or
pnpm install
```

3. Start the development server:
```bash
npm run dev
# or
pnpm dev
```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

## 📖 How to Use

### 1. Generate Digital Signature

1. Go to the **"Generate Signature"** tab
2. Enter your document content in the text area
3. Enter a strong secret key
4. Click **"Generate HMAC Signature"**
5. Copy the generated signature (safe to share publicly)

### 2. Verify & Decrypt Document

1. Go to the **"Verify Signature"** tab
2. Paste the signature you received
3. Enter the secret key
4. Click **"Decrypt & Verify Document"**
5. If successful, the original document will be displayed
6. Click **"Download .txt"** to save the document

## 🔧 Technical Implementation

### HMAC-SHA512 Algorithm

The system implements HMAC-SHA512 from scratch using the standard construction:

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```

Where:
- `H` = SHA-512 hash function
- `K` = Secret key (padded to block size)
- `m` = Message to authenticate
- `opad` = 0x5c repeated
- `ipad` = 0x36 repeated

### Document Encryption

Documents are encrypted using AES-256-CBC with:
- **Key Derivation**: scrypt with salt for strong key generation
- **IV Generation**: Random 16-byte initialization vector
- **Cipher**: AES-256-CBC mode

### Security Features

- **Constant-Time Verification**: Prevents timing attacks during signature comparison
- **Secure Key Padding**: Proper HMAC key preparation
- **Encrypted Storage**: Documents are encrypted before signing
- **Secure Random**: Cryptographically secure random number generation

## 📁 Project Structure

```
digital-signature-with-hmac/
├── app/
│   ├── api/hmac/route.ts      # API endpoint with HMAC implementation
│   ├── globals.css            # Global styles
│   ├── layout.tsx             # Root layout
│   └── page.tsx               # Main page
├── components/
│   ├── signature-dashboard.tsx # Main UI component
│   └── ui/                    # shadcn/ui components
├── scripts/
│   └── hmac_signature.py      # Python implementation (legacy)
├── lib/
│   └── utils.ts               # Utility functions
└── public/                    # Static assets
```

## 🔌 API Documentation

### POST /api/hmac

#### Generate Signature
```json
{
  "action": "generate",
  "message": "Your document content here",
  "secret": "your-secret-key"
}
```

**Response:**
```json
{
  "signature": "base64-encoded-encrypted-signature"
}
```

#### Verify Signature
```json
{
  "action": "verify",
  "signature": "base64-encoded-signature",
  "secret": "your-secret-key"
}
```

**Response (Success):**
```json
{
  "valid": true,
  "message": "Decrypted document content",
  "status": "Document successfully decrypted and verified!"
}
```

**Response (Failure):**
```json
{
  "valid": false,
  "error": "Invalid signature or secret key"
}
```

## 🛡️ Security Considerations

### Key Management
- Use strong, unique secret keys for each document
- Never share secret keys publicly
- Store keys securely (not in code or version control)

### Signature Distribution
- Generated signatures are safe to share publicly
- They contain encrypted documents but require the secret key to decrypt
- Signatures include HMAC authentication to prevent tampering

### Best Practices
- Use HTTPS in production
- Implement rate limiting for API endpoints
- Regularly rotate secret keys
- Validate input lengths and formats

## 🎨 UI Components

Built with modern React components:

- **shadcn/ui**: High-quality, accessible UI components
- **Tailwind CSS**: Utility-first CSS framework
- **Lucide React**: Beautiful, consistent icons
- **Next.js 16**: React framework with App Router
- **TypeScript**: Type-safe development

## 🔄 Development

### Available Scripts

```bash
npm run dev      # Start development server
npm run build    # Build for production
npm run start    # Start production server
npm run lint     # Run ESLint
```

### Testing the Implementation

A test script is available to verify the HMAC implementation:

```bash
python scripts/hmac_signature.py generate '{"message": "test", "secret": "key"}'
python scripts/hmac_signature.py verify '{"message": "test", "signature": "...", "secret": "key"}'
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This implementation is for educational and demonstration purposes. For production use, consider additional security measures and professional security audits.

## 🙏 Acknowledgments

- [HMAC-SHA512 RFC](https://tools.ietf.org/html/rfc4231)
- [Next.js Documentation](https://nextjs.org/docs)
- [shadcn/ui Components](https://ui.shadcn.com)
- [Lucide Icons](https://lucide.dev)

---

**Built with Revel ❤️ for secure digital document signing**

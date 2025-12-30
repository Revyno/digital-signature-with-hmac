"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Shield, Key, FileText, CheckCircle2, XCircle, Copy, RefreshCw, Download } from "lucide-react"
import { useToast } from "@/hooks/use-toast"

export function SignatureDashboard() {
  const [message, setMessage] = useState("")
  const [secret, setSecret] = useState("")
  const [generatedSignature, setGeneratedSignature] = useState("")
  const [verifySignature, setVerifySignature] = useState("")
  const [decryptedMessage, setDecryptedMessage] = useState("")
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  // RSA specific state
  const [keyId, setKeyId] = useState("")
  const [publicKey, setPublicKey] = useState("")
  const [rsaSignature, setRsaSignature] = useState("")
  const [rsaVerificationResult, setRsaVerificationResult] = useState<boolean | null>(null)

  const { toast } = useToast()

  const handleGenerate = async () => {
    if (!message || !secret) {
      toast({
        title: "Missing fields",
        description: "Please provide both a message and a secret key.",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch("/api/hmac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "generate", message, secret }),
      })
      const data = await res.json()
      if (data.signature) {
        setGeneratedSignature(data.signature)
        toast({
          title: "Signature Generated",
          description: "HMAC-SHA512 signature has been created.",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to generate signature.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleVerify = async () => {
    if (!secret || !verifySignature) {
      toast({
        title: "Missing fields",
        description: "Please provide secret key and signature to verify.",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch("/api/hmac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "verify",
          secret,
          signature: verifySignature,
        }),
      })
      const data = await res.json()

      if (data.valid && data.message) {
        setDecryptedMessage(data.message)
        setVerificationResult(true)
        toast({
          title: "Document Decrypted Successfully!",
          description: "The signature is authentic and document has been decrypted.",
        })
      } else {
        setVerificationResult(false)
        setDecryptedMessage("")
        toast({
          title: "Verification Failed",
          description: data.error || "Invalid signature or secret key.",
          variant: "destructive",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to verify signature.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: "Copied",
      description: "Signature copied to clipboard.",
    })
  }

  const downloadDocument = (content: string) => {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `decrypted-document-${new Date().toISOString().split('T')[0]}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    toast({
      title: "Download Started",
      description: "Document has been downloaded as .txt file.",
    })
  }

  // RSA Functions
  const generateRSAKeys = async () => {
    if (!keyId) {
      toast({
        title: "Missing Key ID",
        description: "Please provide a key ID for RSA key pair.",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch("/api/hmac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "generate-rsa-keys", keyId }),
      })
      const data = await res.json()

      if (data.success) {
        setPublicKey(data.publicKey)
        toast({
          title: "RSA Keys Generated",
          description: "RSA key pair has been created successfully.",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to generate RSA keys.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const signWithRSA = async () => {
    if (!message || !keyId) {
      toast({
        title: "Missing fields",
        description: "Please provide message and key ID.",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch("/api/hmac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "rsa-sign", message, keyId }),
      })
      const data = await res.json()

      if (data.signature) {
        setRsaSignature(data.signature)
        setPublicKey(data.publicKey)
        toast({
          title: "RSA Signature Created",
          description: "Document has been signed with RSA.",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to sign with RSA.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const verifyWithRSA = async () => {
    if (!message || !rsaSignature || !publicKey) {
      toast({
        title: "Missing fields",
        description: "Please provide message, signature, and public key.",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch("/api/hmac", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "rsa-verify",
          message,
          signature: rsaSignature,
          publicKey
        }),
      })
      const data = await res.json()

      setRsaVerificationResult(data.valid)
      toast({
        title: data.valid ? "RSA Verification Successful" : "RSA Verification Failed",
        description: data.status,
        variant: data.valid ? "default" : "destructive",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to verify RSA signature.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto p-4 md:p-8 space-y-8">
      <div className="text-center space-y-2">
        <h1 className="text-4xl font-bold tracking-tight text-primary flex items-center justify-center gap-2">
          <Shield className="w-10 h-10" />
          Digital Signature
        </h1>
        <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
          Secure digital signatures with HMAC-SHA512 (symmetric) and RSA (asymmetric) cryptography. Sign, verify, and decrypt documents with enterprise-grade security.
        </p>
      </div>

      <Tabs defaultValue="hmac-generate" className="w-full">
        <TabsList className="grid w-full grid-cols-4 mb-8">
          <TabsTrigger value="hmac-generate">HMAC Generate</TabsTrigger>
          <TabsTrigger value="hmac-verify">HMAC Verify</TabsTrigger>
          <TabsTrigger value="rsa-generate">RSA Generate</TabsTrigger>
          <TabsTrigger value="rsa-verify">RSA Verify</TabsTrigger>
        </TabsList>

        <TabsContent value="hmac-generate">
          <Card className="border-2 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-primary" />
                Create Digital Signature
              </CardTitle>
              <CardDescription>
                Enter your message and a secret key to generate a unique HMAC signature.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="message">Document Content</Label>
                <Textarea
                  id="message"
                  placeholder="Enter the digital document content you want to sign..."
                  className="min-h-[120px] resize-none"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="secret">Secret Key</Label>
                <div className="relative">
                  <Input
                    id="secret"
                    type="password"
                    placeholder="Your strong shared secret..."
                    className="pr-10"
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                  />
                  <Key className="absolute right-3 top-2.5 h-5 w-5 text-muted-foreground" />
                </div>
              </div>
              <Button onClick={handleGenerate} className="w-full h-12 text-lg font-semibold" disabled={isLoading}>
                {isLoading ? <RefreshCw className="mr-2 h-5 w-5 animate-spin" /> : "Generate HMAC Signature"}
              </Button>

              {generatedSignature && (
                <div className="mt-8 p-6 bg-muted rounded-xl border-dashed border-2 border-primary/20 space-y-4">
                  <div className="flex items-center justify-between">
                    <Label className="text-primary font-bold">Generated Signature (Base64)</Label>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(generatedSignature)}>
                      <Copy className="h-4 w-4 mr-2" />
                      Copy
                    </Button>
                  </div>
                  <div className="font-mono text-xs break-all bg-background p-4 rounded-lg border shadow-inner leading-relaxed">
                    {generatedSignature}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="hmac-verify">
          <Card className="border-2 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                Open & Verify Document
              </CardTitle>
              <CardDescription>
                Enter the signature and secret key to decrypt and verify the original document.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="v-secret">Secret Key</Label>
                  <div className="relative">
                    <Input
                      id="v-secret"
                      type="password"
                      placeholder="Enter your secret key..."
                      className="pr-10"
                      value={secret}
                      onChange={(e) => setSecret(e.target.value)}
                    />
                    <Key className="absolute right-3 top-2.5 h-5 w-5 text-muted-foreground" />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="v-sig">Signature to Verify</Label>
                  <Input
                    id="v-sig"
                    placeholder="Paste the signature here..."
                    value={verifySignature}
                    onChange={(e) => setVerifySignature(e.target.value)}
                  />
                </div>
              </div>
              <Button
                onClick={handleVerify}
                variant="secondary"
                className="w-full h-12 text-lg font-semibold border-2 border-primary/20"
                disabled={isLoading}
              >
                {isLoading ? <RefreshCw className="mr-2 h-5 w-5 animate-spin" /> : "Decrypt & Verify Document"}
              </Button>

              {decryptedMessage && verificationResult && (
                <div className="mt-8 p-6 bg-green-500/10 rounded-xl border-2 border-green-500/30 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-6 h-6 text-green-600" />
                      <Label className="text-green-700 dark:text-green-400 font-bold text-lg">
                        Document Successfully Decrypted!
                      </Label>
                    </div>
                    <Button
                      onClick={() => downloadDocument(decryptedMessage)}
                      variant="outline"
                      size="sm"
                      className="border-green-500/30 text-green-700 hover:bg-green-500/10"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Download .txt
                    </Button>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-green-700 dark:text-green-400 font-semibold">Original Document Content:</Label>
                    <div className="bg-background p-4 rounded-lg border shadow-inner">
                      <pre className="whitespace-pre-wrap text-sm leading-relaxed">{decryptedMessage}</pre>
                    </div>
                  </div>
                </div>
              )}

              {verificationResult === false && (
                <div className="mt-6 p-6 bg-destructive/10 rounded-xl border-2 border-destructive/30 space-y-4">
                  <div className="flex items-center gap-2">
                    <XCircle className="w-6 h-6 text-destructive" />
                    <div>
                      <p className="font-bold text-lg leading-tight text-destructive">Verification Failed</p>
                      <p className="text-sm opacity-90 text-destructive">
                        Invalid signature or secret key. Cannot decrypt document.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rsa-generate">
          <Card className="border-2 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Key className="w-5 h-5 text-primary" />
                Generate RSA Key Pair
              </CardTitle>
              <CardDescription>
                Create RSA public/private key pair for digital signatures.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="keyId">Key ID</Label>
                <Input
                  id="keyId"
                  placeholder="Enter a unique key ID..."
                  value={keyId}
                  onChange={(e) => setKeyId(e.target.value)}
                />
              </div>
              <Button onClick={generateRSAKeys} className="w-full h-12 text-lg font-semibold" disabled={isLoading}>
                {isLoading ? <RefreshCw className="mr-2 h-5 w-5 animate-spin" /> : "Generate RSA Key Pair"}
              </Button>

              {publicKey && (
                <div className="mt-8 p-6 bg-blue-500/10 rounded-xl border-2 border-blue-500/30 space-y-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-6 h-6 text-blue-600" />
                    <Label className="text-blue-700 dark:text-blue-400 font-bold text-lg">
                      RSA Key Pair Generated!
                    </Label>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-blue-700 dark:text-blue-400 font-semibold">Public Key (PEM Format):</Label>
                    <div className="bg-background p-4 rounded-lg border shadow-inner">
                      <pre className="whitespace-pre-wrap text-xs leading-relaxed font-mono break-all">{publicKey}</pre>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(publicKey)}
                      className="border-blue-500/30 text-blue-700 hover:bg-blue-500/10"
                    >
                      <Copy className="w-4 h-4 mr-2" />
                      Copy Public Key
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rsa-verify">
          <Card className="border-2 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                RSA Digital Signature
              </CardTitle>
              <CardDescription>
                Sign documents with RSA private key or verify signatures with RSA public key.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <Tabs defaultValue="rsa-sign" className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="rsa-sign">Sign Document</TabsTrigger>
                  <TabsTrigger value="rsa-verify">Verify Signature</TabsTrigger>
                </TabsList>

                <TabsContent value="rsa-sign" className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="rsa-message">Document Content</Label>
                    <Textarea
                      id="rsa-message"
                      placeholder="Enter document to sign..."
                      className="min-h-[100px] resize-none"
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="rsa-keyId">Key ID</Label>
                    <Input
                      id="rsa-keyId"
                      placeholder="Enter key ID..."
                      value={keyId}
                      onChange={(e) => setKeyId(e.target.value)}
                    />
                  </div>
                  <Button onClick={signWithRSA} className="w-full" disabled={isLoading}>
                    {isLoading ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : "Sign with RSA"}
                  </Button>

                  {rsaSignature && (
                    <div className="mt-4 p-4 bg-green-500/10 rounded-lg border border-green-500/30">
                      <Label className="text-green-700 font-semibold">RSA Signature:</Label>
                      <div className="mt-2 p-2 bg-background rounded font-mono text-xs break-all">
                        {rsaSignature}
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(rsaSignature)}
                        className="mt-2"
                      >
                        <Copy className="w-4 h-4 mr-2" />
                        Copy Signature
                      </Button>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="rsa-verify" className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="verify-message">Original Message</Label>
                    <Textarea
                      id="verify-message"
                      placeholder="Enter original message..."
                      className="min-h-[80px] resize-none"
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="verify-sig">RSA Signature</Label>
                    <Input
                      id="verify-sig"
                      placeholder="Paste RSA signature..."
                      value={rsaSignature}
                      onChange={(e) => setRsaSignature(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="verify-pubkey">Public Key (PEM)</Label>
                    <Textarea
                      id="verify-pubkey"
                      placeholder="Paste RSA public key..."
                      className="min-h-[100px] resize-none font-mono text-xs"
                      value={publicKey}
                      onChange={(e) => setPublicKey(e.target.value)}
                    />
                  </div>
                  <Button onClick={verifyWithRSA} variant="secondary" className="w-full" disabled={isLoading}>
                    {isLoading ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : "Verify RSA Signature"}
                  </Button>

                  {rsaVerificationResult !== null && (
                    <div className={`mt-4 p-4 rounded-lg border ${
                      rsaVerificationResult
                        ? "bg-green-500/10 border-green-500/30 text-green-700"
                        : "bg-red-500/10 border-red-500/30 text-red-700"
                    }`}>
                      <div className="flex items-center gap-2">
                        {rsaVerificationResult ? (
                          <CheckCircle2 className="w-5 h-5" />
                        ) : (
                          <XCircle className="w-5 h-5" />
                        )}
                        <span className="font-semibold">
                          {rsaVerificationResult ? "Signature Valid" : "Signature Invalid"}
                        </span>
                      </div>
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pb-12">
        <div className="p-4 rounded-lg bg-card border text-center">
          <Shield className="w-6 h-6 mx-auto mb-2 text-primary" />
          <h3 className="font-semibold mb-1">SHA-512</h3>
          <p className="text-xs text-muted-foreground">High-security 512-bit hashing algorithm.</p>
        </div>
        <div className="p-4 rounded-lg bg-card border text-center">
          <Key className="w-6 h-6 mx-auto mb-2 text-primary" />
          <h3 className="font-semibold mb-1">HMAC</h3>
          <p className="text-xs text-muted-foreground">Authentication via shared cryptographic secret.</p>
        </div>
        <div className="p-4 rounded-lg bg-card border text-center">
          <FileText className="w-6 h-6 mx-auto mb-2 text-primary" />
          <h3 className="font-semibold mb-1">Integrity</h3>
          <p className="text-xs text-muted-foreground">Ensures data hasn't been tampered with.</p>
        </div>
      </div>
    </div>
  )
}

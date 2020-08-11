package com.example.config

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.spec.EncodedKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


object GeneratePublicPrivateKeys {
    private fun generateKeys(keyAlgorithm: String, numBits: Int) {
        try {
            // Get the public/private key pair
            val keyGen = KeyPairGenerator.getInstance(keyAlgorithm)
            keyGen.initialize(numBits)
            val keyPair = keyGen.genKeyPair()
            val privateKey = keyPair.private
            val publicKey = keyPair.public
            println("""
           Generating key/value pair using ${privateKey.algorithm} algorithm""")

            // Get the bytes of the public and private keys
            val privateKeyBytes = privateKey.encoded
            val publicKeyBytes = publicKey.encoded

            // Get the formats of the encoded bytes
            val formatPrivate = privateKey.format // PKCS#8
            val formatPublic = publicKey.format // X.509
            //System.out.println("Private Key : " + Base64Utils.en(String(privateKeyBytes)))
            //System.out.println("Public Key : " + Base64Utils.getEncoder().encode(publicKeyBytes))
            System.out.println("Private Key : " + String(Base64.getEncoder().encode(privateKeyBytes)))
            System.out.println("Public Key : " + String(Base64.getEncoder().encode(publicKeyBytes)))

            // The bytes can be converted back to public and private key objects
            val keyFactory = KeyFactory.getInstance(keyAlgorithm)
            val privateKeySpec: EncodedKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
            val privateKey2 = keyFactory.generatePrivate(privateKeySpec)
            val publicKeySpec: EncodedKeySpec = X509EncodedKeySpec(publicKeyBytes)
            val publicKey2 = keyFactory.generatePublic(publicKeySpec)

            // The original and new keys are the same
            println("  Are both private keys equal? " + (privateKey == privateKey2))
            println("  Are both public keys equal? " + (publicKey == publicKey2))
        } catch (specException: InvalidKeySpecException) {
            println("Exception")
            println("Invalid Key Spec Exception")
        } catch (e: NoSuchAlgorithmException) {
            println("Exception")
            println("No such algorithm: $keyAlgorithm")
        }
    }

    @JvmStatic
    fun main(args: Array<String>) {

        // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
        //generateKeys("DSA", 1024)

        // Generate a 576-bit DH key pair
        //generateKeys("DH", 576)

        // Generate a 1024-bit RSA key pair
        generateKeys("RSA", 1024)
    }
}

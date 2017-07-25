using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Cryptopals
{
  /// <summary>
  /// Cryptography class that handles block-ciphers
  /// </summary>
  public class BlockCryptography
  {
    /// <summary>
    /// The block size for ECB encryption
    /// </summary>
    public readonly int BLOCKSIZE = 16;

    /// <summary>
    /// Encrypt plain text with AES-CBC
    /// </summary>
    /// <param name="IV">The initialization vector</param>
    /// <param name="key">The key to encrypt with</param>
    /// <param name="plainText">The plain text to encrypt</param>
    /// <returns></returns>
    public byte[] EncryptCBC(byte[] IV, byte[] key, string plainText)
    {
      Cryptography crypto = new Cryptography();

      // Ensure the text is padded
      plainText = this.AppendPKCS7Padding(plainText, this.BLOCKSIZE);
      byte[] plainTextBytes = Encoding.ASCII.GetBytes(plainText);
      byte[] encryptedBytes = new byte[plainText.Length];
      byte[] tempBuffer = new byte[this.BLOCKSIZE];
      byte[] lastKnownCipher = null;
      byte[] XORBuffer = null;
      for (int i = 0; i * this.BLOCKSIZE < plainText.Length; i++)
      {
        // Copy plaintext blocks into a buffer
        Buffer.BlockCopy(plainTextBytes, i * this.BLOCKSIZE, tempBuffer, 0, this.BLOCKSIZE);

        // XOR the plaintext with the last known cipher block
        if (i == 0)
          XORBuffer = crypto.XORBuffer(tempBuffer, IV);
        else
          XORBuffer = crypto.XORBuffer(tempBuffer, lastKnownCipher);

        lastKnownCipher = this.EncryptECB(key, XORBuffer);

        // Store the Cipher into an array
        Buffer.BlockCopy(lastKnownCipher, 0, encryptedBytes, i * this.BLOCKSIZE, this.BLOCKSIZE);
      }

      return encryptedBytes;
    }

    /// <summary>
    /// Decrypts a cipher that has been encrypted via AES-CBC
    /// </summary>
    /// <param name="IV">The initialization vector</param>
    /// <param name="key">The key to decrypt with </param>
    /// <param name="cipherText">The cipher text to decrypt</param>
    /// <returns></returns>
    public string DecryptCBC(byte[] IV, byte[] key, byte[] cipherText)
    {
      Cryptography crypto = new Cryptography();

      byte[] lastKnownCipher = null;
      byte[] tempBuffer = new byte[this.BLOCKSIZE];
      byte[] plainTextBytes;
      byte[] plainText = new byte[cipherText.Length];
      for (int i = 0; i * this.BLOCKSIZE < cipherText.Length; i++)
      {
        // Copy a block into a buffer
        Buffer.BlockCopy(cipherText, i * this.BLOCKSIZE, tempBuffer, 0, this.BLOCKSIZE);

        // Decrypt the block using the key
        byte[] decryptedBytes = this.DecryptECB(key, tempBuffer);

        // XOR the buffer to retrieve the plain text
        if (i == 0)
          plainTextBytes = crypto.XORBuffer(decryptedBytes, IV);
        else
          plainTextBytes = crypto.XORBuffer(decryptedBytes, lastKnownCipher);

        // Store this block as the last known cipher
        lastKnownCipher = new byte[tempBuffer.Length];
        Buffer.BlockCopy(tempBuffer, 0, lastKnownCipher, 0, lastKnownCipher.Length);
        Buffer.BlockCopy(plainTextBytes, 0, plainText, i * this.BLOCKSIZE, this.BLOCKSIZE);
      }

      plainText = this.RemovePKCS7Padding(plainText);
      return Encoding.ASCII.GetString(plainText);
    }

    /// <summary>
    /// Appends PKCS7 Padding to plaintext
    /// </summary>
    /// <param name="plainText">The plain text in bytes</param>
    /// <param name="blockSize">The size of the blocks</param>
    /// <returns></returns>
    public byte[] AppendPKCS7Padding(byte[] plainText, int blockSize)
    {
      if (blockSize < 0x01 || blockSize > 0xFF)
        throw new Exceptions.InvalidPaddingSizeException("Padding size must be between 1 and 255");

      // If the text is bigger than the blocksize, pad the end of the string
      byte[] textToPad = plainText;
      int remainingText = 0;
      if (plainText.Length > blockSize)
      {
        remainingText = plainText.Length % blockSize;
        textToPad = plainText.Skip(plainText.Length - remainingText).ToArray();
      }

      byte paddingVal = (byte)(blockSize - textToPad.Length);
      byte[] paddedText = new byte[blockSize - remainingText];
      for (int i = 0; i < paddedText.Length; i++)
        paddedText[i] = paddingVal;

      Buffer.BlockCopy(plainText, 0, paddedText, 0, plainText.Length);
      return paddedText;
    }

    /// <summary>
    /// Pads the plaintext to the requested blocksize
    /// </summary>
    /// <param name="plainText">The plain text to manipulate</param>
    /// <param name="blockSize">The block size to pad to</param>
    public string AppendPKCS7Padding(string plainText, int blockSize)
    {
      byte[] paddedBytes = this.AppendPKCS7Padding(Encoding.ASCII.GetBytes(plainText), blockSize);
      return Encoding.ASCII.GetString(paddedBytes);
    }

    /// <summary>
    /// Removes the PKCS7 Padding
    /// </summary>
    /// <param name="plainText">The plain text bytes to check for padding</param>
    /// <returns>A byte array of the edited plaintext</returns>
    public byte[] RemovePKCS7Padding(byte[] plainText)
    {
      byte paddingVal = plainText[plainText.Length - 1];

      // Check if byte at the end is > the valid blocksize - 1 (implies the last byte must be data, not padding)
      if (paddingVal < 0 || paddingVal >= (this.BLOCKSIZE - 1))
        return plainText;

      // Skip to [end of array] - [padding length]
      byte[] padding = plainText.Skip(plainText.Length - paddingVal).ToArray();

      // Check to see if all the bytes are equal at the "padding"
      if (padding.All(x => x == paddingVal))
      {
        // All values at the padding must be equal (valid padding), remove
        return plainText.Take(plainText.Length - paddingVal).ToArray();
      }
      else
      {
        // The values were not all equal, byte must be part of plain text
        // Return the entire byte array
        return plainText;
      }
    }

    /// <summary>
    /// If the text contains duplicate 16-byte blocks, it is possible that it is an 
    /// ECB encrypted cipher
    /// </summary>
    /// <param name="cipher">The cipher's encrypted text</param>
    /// <returns>A boolean determining if the cipher is an ECB Cipher</returns>
    public bool DetectECB(byte[] cipher)
    {
      // If the cipher block size is not evenly divisible, it cannot be a block cipher
      if (!(cipher.Length % this.BLOCKSIZE == 0))
        return false;

      byte[] tempBuffer = new byte[this.BLOCKSIZE];
      List<string> blockList = new List<string>();

      // Partition the cipher into blocks
      for (int i = 0; i * this.BLOCKSIZE < cipher.Length; i++)
      {
        Buffer.BlockCopy(cipher, i * this.BLOCKSIZE, tempBuffer, 0, this.BLOCKSIZE);
        if (blockList.Contains(Encoding.ASCII.GetString(tempBuffer)))
          return true;
        else
          blockList.Add(Encoding.ASCII.GetString(tempBuffer));
      }

      // Cipher did not contain any duplicates
      return false;
    }

    /// <summary>
    /// Encrypts plain text using ECB Mode cipher
    /// </summary>
    /// <param name="key">The key to use to encrypt</param>
    /// <param name="plainText">The text to encrypt</param>
    /// <returns>The encrypted text as a byte array</returns>
    public byte[] EncryptECB(byte[] key, byte[] plainText)
    {
      AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
      aes.Mode = CipherMode.ECB;
      aes.Key = key;
      aes.Padding = PaddingMode.None;
      ICryptoTransform transform = aes.CreateEncryptor();
      plainText = this.AppendPKCS7Padding(plainText, this.BLOCKSIZE);

      // Decrypt and write to memory
      using (MemoryStream ms = new MemoryStream())
      {
        using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
        {
          cs.Write(plainText, 0, plainText.Length);
        }

        return ms.ToArray();
      }
    }

    /// <summary>
    /// Decrypt cipher text with a given key
    /// </summary>
    /// <param name="key">The key in bytes</param>
    /// <returns>the decrypted text</returns>
    public byte[] DecryptECB(byte[] key, byte[] cipherText)
    {
      AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
      aes.Mode = CipherMode.ECB;
      aes.Padding = PaddingMode.None;
      aes.Key = key;

      ICryptoTransform transform = aes.CreateDecryptor();

      // Decrypt and write to memory
      using (MemoryStream ms = new MemoryStream())
      {
        using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
        {
          cs.Write(cipherText, 0, cipherText.Length);
        }

        return ms.ToArray();
      }
    }
  }
}

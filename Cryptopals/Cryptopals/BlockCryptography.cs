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

    public byte[] EncryptCBC(byte[] IV, byte[] key, string plainText)
    {
      Cryptography crypto = new Cryptography();

      // Ensure the text is padded
      plainText = this.AppendPKCS7Padding(plainText, BLOCKSIZE);
      byte[] plainTextBytes = Encoding.ASCII.GetBytes(plainText);
      byte[] encryptedBytes = new byte[plainText.Length * 2];
      byte[] tempBuffer = new byte[BLOCKSIZE];
      byte[] XORBuffer = null;
      for (int i = 0; i < plainText.Length; i++)
      {
        // Copy plaintext blocks into a buffer
        Buffer.BlockCopy(plainTextBytes, i * BLOCKSIZE, tempBuffer, 0, BLOCKSIZE);

        // XOR the plaintext with the last known cipher block
        if (i == 0)
          XORBuffer = crypto.XORBuffer(tempBuffer, IV);
        else
          XORBuffer = crypto.XORBuffer(tempBuffer, XORBuffer);

        // Store the Cipher into an array
        Buffer.BlockCopy(this.EncryptECB(key, XORBuffer), 0, encryptedBytes, i * BLOCKSIZE, BLOCKSIZE);
      }

      return encryptedBytes;
    }

    public string DecryptCBC(byte[] IV, byte[] key, byte[] cipherText)
    {
      Cryptography crypto = new Cryptography();

      byte[] lastKnownCipher = null;
      byte[] tempBuffer = new byte[BLOCKSIZE];
      byte[] plainTextBytes;
      StringBuilder plainText = new StringBuilder();
      for (int i = 0; i * BLOCKSIZE < cipherText.Length; i++)
      {
        // Copy a block into a buffer
        Buffer.BlockCopy(cipherText, i * BLOCKSIZE, tempBuffer, 0, BLOCKSIZE);

        // Decrypt the block using the key
        byte[] decryptedBytes = this.DecryptECB(key, tempBuffer);

        // XOR the buffer to retrieve the plain text
        if (i == 0)
          plainTextBytes = crypto.XORBuffer(decryptedBytes, IV);
        else
          // Store this block as the last known cipher
          plainTextBytes = crypto.XORBuffer(decryptedBytes, lastKnownCipher);

        lastKnownCipher = tempBuffer;
        plainText.Append(Encoding.ASCII.GetString(plainTextBytes));
      }

      return plainText.ToString();
    }

    /// <summary>
    /// Pads the plaintext to the requested blocksize
    /// </summary>
    /// <param name="plainText">The plain text to manipulate</param>
    /// <param name="blockSize">The block size to pad to</param>
    public string AppendPKCS7Padding(string plainText, int blockSize)
    {
      if (blockSize < 0x01 || blockSize > 0xFF)
        throw new Exceptions.InvalidPaddingSizeException("Padding size must be between 1 and 255");

      // If the text is bigger than the blocksize, pad the end of the string
      string stringToPad = plainText;
      if (plainText.Length > blockSize)
      {
        int remainingText = plainText.Length % blockSize;
        stringToPad = plainText.Substring(plainText.Length - remainingText, remainingText);
      }

      StringBuilder PaddedString = new StringBuilder();
      PaddedString.Append(stringToPad);
      string blockSizeString = String.Format("{0}", Convert.ToChar(blockSize - stringToPad.Length));

      for (int i = 0; i < (blockSize - stringToPad.Length); i++)
        PaddedString.Append(blockSizeString);

      return PaddedString.ToString();
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
      ICryptoTransform transform = aes.CreateEncryptor();

      // Decrypt and write to memory
      using (MemoryStream ms = new MemoryStream())
      {
        using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
        {
          cs.Write(plainText, 0, plainText.Length);
          //cs.FlushFinalBlock();
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
          //cs.FlushFinalBlock();
        }

        return ms.ToArray();
      }
    }
  }
}

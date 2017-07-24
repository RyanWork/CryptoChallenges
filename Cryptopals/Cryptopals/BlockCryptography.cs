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
    public readonly int ECB_BLOCKSIZE = 16;

    /// <summary>
    /// Pads the plaintext to the requested blocksize
    /// </summary>
    /// <param name="plainText">The plain text to manipulate</param>
    /// <param name="blockSize">The block size to pad to</param>
    public string AppendPKCS7Padding(string plainText, int blockSize)
    {
      // If the text is bigger than the blocksize, pad the end of the string
      string stringToPad = plainText;
      if (plainText.Length > blockSize)
      {
        int remainingText = plainText.Length % blockSize;
        stringToPad = plainText.Substring(plainText.Length - remainingText, remainingText);
      }

      StringBuilder PaddedString = new StringBuilder();
      PaddedString.Append(stringToPad);
      string blockSizeString = String.Format("\0x{0:x2}", blockSize - stringToPad.Length);

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
      if (!(cipher.Length % this.ECB_BLOCKSIZE == 0))
        return false;

      byte[] tempBuffer = new byte[this.ECB_BLOCKSIZE];
      List<string> blockList = new List<string>();

      // Partition the cipher into blocks
      for (int i = 0; i * this.ECB_BLOCKSIZE < cipher.Length; i++)
      {
        Buffer.BlockCopy(cipher, i * this.ECB_BLOCKSIZE, tempBuffer, 0, this.ECB_BLOCKSIZE);
        if (blockList.Contains(Encoding.ASCII.GetString(tempBuffer)))
          return true;
        else
          blockList.Add(Encoding.ASCII.GetString(tempBuffer));
      }

      // Cipher did not contain any duplicates
      return false;
    }

    /// <summary>
    /// Decrypt cipher text with a given key
    /// </summary>
    /// <param name="key">The key in bytes</param>
    /// <returns>the decrypted text</returns>
    public string DecryptECBText(byte[] key, byte[] cipherText)
    {
      AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
      aes.Mode = CipherMode.ECB;
      aes.Key = key;

      ICryptoTransform transform = aes.CreateDecryptor();

      // Decrypt and write to memory
      using (MemoryStream ms = new MemoryStream())
      {
        using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
        {
          cs.Write(cipherText, 0, cipherText.Length);
          cs.FlushFinalBlock();
        }

        byte[] array = ms.ToArray();
        return Encoding.ASCII.GetString(array);
      }
    }
  }
}

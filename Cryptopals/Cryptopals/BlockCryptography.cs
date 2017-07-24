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

      Dictionary<string, int> duplicateCipher = new Dictionary<string, int>();
      byte[] temp = new byte[this.ECB_BLOCKSIZE];

      // Partition the cipher into blocks
      for (int i = 0; i * this.ECB_BLOCKSIZE < cipher.Length; i++)
      {
        Buffer.BlockCopy(cipher, i * this.ECB_BLOCKSIZE, temp, 0, this.ECB_BLOCKSIZE);
        if (!duplicateCipher.ContainsKey(Encoding.ASCII.GetString(temp)))
          duplicateCipher.Add(Encoding.ASCII.GetString(temp), 0);

        duplicateCipher[Encoding.ASCII.GetString(temp)]++;
      }

      // If the cipher has any duplicate values
      return duplicateCipher.Count < (cipher.Length / 16);
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

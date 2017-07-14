using System;
using Cryptopals.Exceptions;
using System.Text;

namespace Cryptopals
{
  public class Cryptography
  {
    static void Main(string[] args)
    {

    }

    public string JoinArrayToString(byte[] array) 
    {
      StringBuilder joinedString = new StringBuilder();
      for (int i = 0; i < array.Length; i++)
        joinedString.AppendFormat("{0:x}", array[i]);
      return joinedString.ToString();
    }

    /// <summary>
    /// Converts a hex string into base 64
    /// </summary>
    /// <param name="hexString">The hex string to convert</param>
    /// <returns>A string representation of the base 64 version of the hex string</returns>
    public byte[] ConvertHexToBase64(string hexString)
    {
      // Convert string to byte array
      int NumberChars = hexString.Length;
      byte[] bytes = new byte[NumberChars / 2];
      for (int i = 0; i < NumberChars; i += 2)
        bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);

      // Return Converted array as a string
      return bytes;
    }

    /// <summary>
    /// XORs two hex strings with each other
    /// </summary>
    /// <param name="input">The first string input</param>
    /// <param name="XOR">The value to XOR the input string against</param>
    /// <returns></returns>
    public byte[] XORBuffer(string input, string XOR)
    {
      // Check if the buffers are equal sizes
      if (input.Length != XOR.Length)
        throw new UnequalLengthException("The input string and the XOR string do not have equal lengths");

      byte[] input1 = this.ConvertHexToBase64(input);
      byte[] input2 = this.ConvertHexToBase64(XOR);

      byte[] resultXOR = new byte[input1.Length];
      StringBuilder stringXOR = new StringBuilder();
      for (int i = 0; i < input1.Length; i++)
        resultXOR[i] = (byte)(input1[i] ^ input2[i]);

      return resultXOR;
    }
  }
}

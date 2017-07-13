using System;
using Cryptopals.Exceptions;
using System.Text;

namespace Cryptopals
{
  public class Cryptography
  {
    static void Main(string[] args)
    {
      Cryptography crypto = new Cryptography();
      string firstChallenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
      string expectedString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
      string Base64 = Convert.ToBase64String(crypto.ConvertHexToBase64(firstChallenge));
      Console.WriteLine("Received: " + Base64 + "\nExpecting: " + expectedString + "\nResult: " + Base64.Equals(expectedString));
      Console.ReadKey();

      crypto.XORBuffer("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965");
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
    public string XORBuffer(string input, string XOR)
    {
      if (input.Length != XOR.Length)
        throw new UnequalLengthException("The input string and the XOR string do not have equal lengths");

      byte[] input1 = this.ConvertHexToBase64(input);
      byte[] input2 = this.ConvertHexToBase64(XOR);

      StringBuilder stringXOR = new StringBuilder();
      for (int i = 0; i < input1.Length; i++)
        stringXOR.Append(input1[i] ^ input2[i]);

      return stringXOR.ToString();
    }

    private byte[] ConvertHexStringToByteArray(string hexString)
    {
      byte[] byteArray = new byte[hexString.Length / 2];
      for (int i = 0; i < hexString.Length / 2; i += 2)
        byteArray[i / 2] = Convert.ToByte(hexString.Substring(i, 2));
      return byteArray;
    }
  }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals
{
  class Program
  {
    static void Main(string[] args)
    {
      string firstChallenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
      string expectedString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
      string Base64 = Program.ConvertHexToBase64(firstChallenge);
      Console.WriteLine("Received: " + Base64 + "\nExpecting: " + expectedString + "\nResult: " + Base64.Equals(expectedString));
      Console.ReadKey();
    }

    /// <summary>
    /// Converts a hex string into base 64
    /// </summary>
    /// <param name="hexString">The hex string to convert</param>
    /// <returns>A string representation of the base 64 version of the hex string</returns>
    public static string ConvertHexToBase64(string hexString)
    {
      // Convert string to byte array
      int NumberChars = hexString.Length;
      byte[] bytes = new byte[NumberChars / 2];
      for (int i = 0; i < NumberChars; i += 2)
        bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);

      // Return Converted array as a string
      return Convert.ToBase64String(bytes);
    }
  }
}

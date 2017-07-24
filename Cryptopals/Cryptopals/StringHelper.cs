using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals
{
  /// <summary>
  /// Helper class that parses and deals with strings
  /// </summary>
  public static class StringHelper
  {
    public enum StringType
    {
      Hex,
      String
    }

    /// <summary>
    /// Parses a byte array into a string
    /// </summary>
    /// <param name="array">The byte array to convert</param>
    /// <returns>A string representation of the array</returns>
    public static string JoinArrayToString(byte[] array)
    {
      StringBuilder joinedString = new StringBuilder();
      for (int i = 0; i < array.Length; i++)
        joinedString.AppendFormat("{0:x2}", array[i]);
      return joinedString.ToString();
    }

    /// <summary>
    /// Converts a hex string into a byte array
    /// </summary>
    /// <param name="hexString">The hex string to convert</param>
    /// <returns>A byte array containing the hex string</returns>
    public static byte[] ConvertHexStringToByteArray(string hexString)
    {
      // Convert string to byte array
      int NumberChars = hexString.Length;

      // Divide by 2, since 1 character = (16^2) - 1. Ex: 1 character = 0x00 to 0xFF
      byte[] bytes = new byte[NumberChars / 2];
      for (int i = 0; i < NumberChars; i += 2)
        bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);

      // Return Converted array as a string
      return bytes;
    }
  }
}

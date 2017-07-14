using System;
using Cryptopals.Exceptions;
using System.Text;
using System.Collections.Generic;

namespace Cryptopals
{
  public class Cryptography
  {
    /// <summary>
    /// Most common letters in English alphabet
    /// </summary>
    private const string MOST_COMMON_LETTERS = "ETAOIN SHRDLU";

    static void Main(string[] args)
    {
      Cryptography crypto = new Cryptography();

    }

    /// <summary>
    /// Decode a string encrypted via a single character
    /// </summary>
    /// <param name="encryptedString"></param>
    /// <returns></returns>
    public string DecodeSingleByteXOR(string encryptedString)
    {
      char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
      string characterString = string.Empty;
      Dictionary<char, int> mostFrequent = null;
      string associatedString = string.Empty;
      foreach (char letter in alphabet)
      {
        characterString = new string(letter, encryptedString.Length / 2);
        byte[] test3 = this.XORBuffer(encryptedString, this.JoinArrayToString(Encoding.ASCII.GetBytes(characterString)));
        string decoded = Encoding.ASCII.GetString(test3);
        Dictionary<char, int> scored = this.ScoreFrequency(decoded);

        if (mostFrequent == null || (mostFrequent != null && this.CompareFrequencies(scored, mostFrequent)))
        {
          mostFrequent = scored;
          associatedString = decoded;
        }
      }

      return associatedString;
    }

    /// <summary>
    /// Parses a byte array into a string
    /// </summary>
    /// <param name="array">The byte array to convert</param>
    /// <returns>A string representation of the array</returns>
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

    /// <summary>
    /// Return a dictionary showing the most frequent characters
    /// </summary>
    /// <param name="input">The string input</param>
    /// <returns>A Dictionary showing the frequencies of the most common letters</returns>
    public Dictionary<char, int> ScoreFrequency(string input)
    {
      Dictionary<char, int> frequency = new Dictionary<char, int>();
      foreach (char character in Cryptography.MOST_COMMON_LETTERS)
        frequency.Add(character, 0);

      // Score the frequency of "ETAOIN SHRDLU"
      foreach(char letter in input)
      {
        if (frequency.ContainsKey(letter))
          frequency[letter]++;
      }

      return frequency;
    }

    /// <summary>
    /// Compare the dictionaries that count the frequency of ETAOIN SHRDLU
    /// </summary>
    /// <param name="newInput">The new dictionary</param>
    /// <param name="mostFrequent">The currently most frequent dictionary</param>
    /// <returns></returns>
    public bool CompareFrequencies(Dictionary<char, int> newInput, Dictionary<char, int> mostFrequent)
    {
      int inputTotal = 0, leadingTotal = 0;
      foreach(char letter in Cryptography.MOST_COMMON_LETTERS)
      {
        inputTotal += newInput[letter];
        leadingTotal += mostFrequent[letter];
      }
      
      return inputTotal > leadingTotal;
    }
  }
}

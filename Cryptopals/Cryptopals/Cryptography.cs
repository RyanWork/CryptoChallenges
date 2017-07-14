using System;
using Cryptopals.Exceptions;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Threading;
using System.Linq;

namespace Cryptopals
{
  public class Cryptography
  {
    /// <summary>
    /// Most common letters in English alphabet
    /// </summary>
    private const string MOST_COMMON_LETTERS = "ETAOIN";

    /// <summary>
    /// Least common letters in English alphabet
    /// </summary>
    private const string LEAST_COMMON_LETTERS = "VKJXQZ";

    static void Main(string[] args)
    {
      Cryptography crypto = new Cryptography();
      string inputString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
      string expectedString = "Cooking MC's like a pound of bacon";
      string result = crypto.DecodeSingleByteXOR(inputString);

      Console.WriteLine(crypto.DecodeSingleByteXOR(inputString));
      Console.ReadKey();

      string[] array = File.ReadAllLines(@"C:\Users\rha\Desktop\Encryption\CryptoChallenges\Cryptopals\Cryptopals\Challenge4Text.txt");
      string best = string.Empty;
      int bestInput = 0;
      foreach (string line in array)
      {
        string returnVal = crypto.DecodeSingleByteXOR(line);
        Console.WriteLine(returnVal);
        Thread.Sleep(25);
        //int input = crypto.GetFrequencyScore(returnVal);

        //if (input > bestInput)
        //{
        //  bestInput = input;
        //  best = returnVal;
        //}
      }

      //Console.WriteLine(best + bestInput);
      Console.ReadKey();
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
      string associatedString = string.Empty;
      int highestScore = 0;
      foreach (char letter in alphabet)
      {
        characterString = new string(letter, encryptedString.Length / 2);
        byte[] xorBytes = this.XORBuffer(encryptedString, this.JoinArrayToString(Encoding.ASCII.GetBytes(characterString)));
        string decoded = Encoding.ASCII.GetString(xorBytes);
        int scored = this.GetFrequencyScore(decoded);

        if (scored > highestScore)
        {
          highestScore = scored;
          associatedString = decoded;
        }
      }

      return associatedString;
    }

    public string DecodeSingleByteXORFile(string filePath)
    {
      return string.Empty;
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
    /// Scores the value of a string. The higher the score, the better.
    /// </summary>
    /// <param name="input">The string to evaluate</param>
    /// <returns>an integer representing the frequency score of the string</returns>
    private int GetFrequencyScore(string input)
    {
      //Dictionary<char, int> frequencyCommon = new Dictionary<char, int>(), frequencyUncommon = new Dictionary<char, int>();
      //int frequencyScore = 0;
      //foreach (char character in Cryptography.MOST_COMMON_LETTERS)
      //  frequencyCommon.Add(character, 0);

      //foreach (char character in Cryptography.LEAST_COMMON_LETTERS)
      //  frequencyUncommon.Add(character, 0);

      //foreach (char letter in input)
      //{
      //  char letterFormatted = Char.ToUpper(letter);
      //  if (frequencyCommon.ContainsKey(letterFormatted))
      //  {
      //    // Score the frequency of "ETAOIN"
      //    frequencyCommon[letterFormatted]++;
      //    frequencyScore++;
      //  }
      //  else if (frequencyUncommon.ContainsKey(letterFormatted))
      //  {
      //    // Remove score if the program finds the most uncommon letters
      //    frequencyUncommon[letterFormatted]++;
      //    frequencyScore--;
      //  }
      //}

      Dictionary<char, int> frequency = new Dictionary<char, int>();
      //foreach (char character in Cryptography.MOST_COMMON_LETTERS)
      //  frequency.Add(character, 0);

      //foreach (char character in Cryptography.LEAST_COMMON_LETTERS)
      //  frequency.Add(character, 0);

      foreach (char letter in input)
      {
        char letterFormatted = Char.ToUpper(letter);
        if (!frequency.ContainsKey(letterFormatted))
          frequency.Add(letterFormatted, 0);

        frequency[letterFormatted]++;
      }

      List<KeyValuePair<char, int>> list = frequency.ToList();
      list.Sort((x, y) => y.Value.CompareTo(x.Value));

      char[] common = { 'E', 'T', 'A', 'O', 'I', 'N', ' ' };
      char[] least = { 'V', 'K', 'J', 'Q', 'Z' };
      int frequencyScore = 0;

      List<KeyValuePair<char, int>> TopFive = list.GetRange(0, 5);
      List<KeyValuePair<char, int>> LastFive = list.GetRange(list.Count - 5, 5);

      foreach (KeyValuePair<char, int> kvp in TopFive)
        if (common.Contains(kvp.Key))
          frequencyScore++;

      foreach(KeyValuePair<char, int> kvp in LastFive)
        if(common.Contains(kvp.Key))

      return frequencyScore;
    }
  }
}

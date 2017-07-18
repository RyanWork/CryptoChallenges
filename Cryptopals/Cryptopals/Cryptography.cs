using System;
using Cryptopals.Exceptions;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Cryptopals
{
  public class Cryptography
  {

    /// <summary>
    /// Relative file path of the challenge four text file
    /// </summary>
    public static string CHALLENGE_FOUR_FILE { get; private set; } = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName + @"\Challenge4Text.txt";

    /// <summary>
    /// Relative file path of challenge six text file
    /// </summary>
    public static string CHALLENGE_SIX_FILE { get; private set; } = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.FullName + @"\Challenge6Text.txt";

    static void Main(string[] args)
    {
      Cryptography crypto = new Cryptography();
      HammingDistanceCalculator calc = new HammingDistanceCalculator();

      int MAX_SIZE = 40;
      FileInfo info = new FileInfo(Cryptography.CHALLENGE_SIX_FILE);
      byte[] allBytes = File.ReadAllBytes(Cryptography.CHALLENGE_SIX_FILE);
      for (int KEYSIZE = 2; KEYSIZE <= MAX_SIZE; KEYSIZE++)
      {
        int blockNum = (int)(info.Length / KEYSIZE);
        int count = 0;
        List<float> distances = new List<float>();
        byte[] firstBuffer = new byte[KEYSIZE], secondBuffer = new byte[KEYSIZE];
        while (count < 4)
        {
          // Copy data into separate buffers
          int offset = KEYSIZE * count;
          Buffer.BlockCopy(allBytes, offset, firstBuffer, 0, KEYSIZE);
          Buffer.BlockCopy(allBytes, offset + KEYSIZE, secondBuffer, 0, KEYSIZE);
          
          // Calculate distance
          distances.Add(calc.CalculateDistance(firstBuffer, secondBuffer));
          count++;
        }

        float averageNormalized = distances.Sum() / (KEYSIZE * 4);
        Console.WriteLine("{0}: Hamming Distance: {1}, Normalized: {2}", KEYSIZE, string.Join(", ", distances), averageNormalized.ToString("0.00"));
      }

      Console.ReadKey();
    }

    public enum StringType
    {
      Hex,
      String
    }

    /// <summary>
    /// Decode a string encrypted via a single character
    /// </summary>
    /// <param name="encryptedString"></param>
    /// <param name="stringType">The type of the string</param>
    /// <returns></returns>
    public string DecodeSingleByteXOR(string encryptedString, StringType stringType)
    {
      string associatedString = string.Empty;
      int highestScore = 0;

      byte[] parsedString, filledByteArray;
      switch (stringType)
      {
        case StringType.Hex:
          parsedString = this.ConvertHexStringToByteArray(encryptedString);
          filledByteArray = new byte[encryptedString.Length / 2];
          break;
        case StringType.String:
          parsedString = Encoding.ASCII.GetBytes(encryptedString);
          filledByteArray = new byte[encryptedString.Length];
          break;
        default:
          parsedString = this.ConvertHexStringToByteArray(encryptedString);
          filledByteArray = new byte[encryptedString.Length / 2];
          break;
      }

      // Loop for each possible byte
      for (int i = byte.MinValue; i <= byte.MaxValue; i ++)
      {
        for (int k = 0; k < encryptedString.Length / 2; k++)
          filledByteArray[k] = (byte)i;

        // Decrypt for every value of a byte
        byte[] xorBytes = this.XORBuffer(filledByteArray, parsedString);
        string decoded = Encoding.ASCII.GetString(xorBytes);
        int scored = this.GetFrequencyScore(decoded);

        // Evalute the string with the best frequency score
        if (scored > highestScore)
        {
          highestScore = scored;
          associatedString = decoded;
        }
      }

      return associatedString;
    }

    /// <summary>
    /// Decode a file
    /// </summary>
    /// <param name="filepath">the file path</param>
    /// <returns>The decoded string</returns>
    public string DecodeSingleByteXORFile(string filepath, StringType stringType)
    {
      string[] challengeText = File.ReadAllLines(filepath);
      string bestString = string.Empty;
      int bestScore = 0;
      foreach (string line in challengeText)
      {
        string ret = this.DecodeSingleByteXOR(line, stringType);
        int retScore = this.GetFrequencyScore(ret);

        if (retScore > bestScore)
        {
          bestScore = retScore;
          bestString = ret;
        }
      }

      return bestString.Trim();
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
        joinedString.AppendFormat("{0:x2}", array[i]);
      return joinedString.ToString();
    }

    /// <summary>
    /// Converts a hex string into a byte array
    /// </summary>
    /// <param name="hexString">The hex string to convert</param>
    /// <returns>A string representation of the base 64 version of the hex string</returns>
    public byte[] ConvertHexStringToByteArray(string hexString)
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

      byte[] input1 = this.ConvertHexStringToByteArray(input);
      byte[] input2 = this.ConvertHexStringToByteArray(XOR);

      return XORBuffer(input1, input2);
    }

    /// <summary>
    /// XOR Two byte buffers
    /// </summary>
    /// <param name="input">First buffer</param>
    /// <param name="XOR">buffer to xor against</param>
    /// <returns>A byte array containing the XOR'd buffer</returns>
    public byte[] XORBuffer(byte[] input, byte[] XOR)
    {
      if (input.Length != XOR.Length)
        throw new UnequalLengthException("The input string and the XOR string do not have equal lengths");

      byte[] resultXOR = new byte[input.Length];
      StringBuilder stringXOR = new StringBuilder();
      for (int i = 0; i < input.Length; i++)
        resultXOR[i] = (byte)(input[i] ^ XOR[i]);

      return resultXOR;
    }

    /// <summary>
    /// Encrypts plaintext with a key-string.
    /// Encrypts text sequentially for each character in the key
    /// </summary>
    /// <param name="plainText">The text to encrypt</param>
    /// <param name="key">The key word to encrypt with</param>
    /// <returns></returns>
    public byte[] RepeatingKeyXOR(string plainText, string key)
    {
      byte[] parsedString = Encoding.ASCII.GetBytes(plainText);
      byte[] keyBytes = Encoding.ASCII.GetBytes(key);
      byte[] XORBuffer = new byte[plainText.Length];
      for (int i = 0; i < parsedString.Length; i++)
        XORBuffer[i] = (byte)(parsedString[i] ^ keyBytes[i % keyBytes.Length]);

      return XORBuffer;
    }

    /// <summary>
    /// Scores the value of a string. The higher the score, the better.
    /// </summary>
    /// <param name="input">The string to evaluate</param>
    /// <returns>an integer representing the frequency score of the string</returns>
    private int GetFrequencyScore(string input)
    {
      Dictionary<char, int> frequency = new Dictionary<char, int>();

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
      int frequencyScore = 0;

      List<KeyValuePair<char, int>> TopFive = list.GetRange(0, list.Count >= 5 ? 5 : list.Count);
      
      foreach (KeyValuePair<char, int> kvp in TopFive)
        if (common.Contains(kvp.Key))
        {
          frequencyScore++;
          frequencyScore += kvp.Value;
        }

      return frequencyScore;
    }
  }
}

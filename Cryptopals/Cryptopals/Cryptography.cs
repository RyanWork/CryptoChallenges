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
      //Console.WriteLine(Encoding.ASCII.GetString(new byte[] { 0x100 }));
      //Console.ReadKey();

      Cryptography crypto = new Cryptography();
      HammingDistanceCalculator calc = new HammingDistanceCalculator();

      string base64Text = File.ReadAllText(Cryptography.CHALLENGE_SIX_FILE);
      byte[] allBytes = Convert.FromBase64String(base64Text);
      Console.WriteLine(crypto.BreakRepeatingXOR(allBytes));

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
      byte[] parsedString;
      switch (stringType)
      {
        case StringType.Hex:
          parsedString = this.ConvertHexStringToByteArray(encryptedString);
          break;
        case StringType.String:
          parsedString = Encoding.ASCII.GetBytes(encryptedString);
          break;
        default:
          parsedString = this.ConvertHexStringToByteArray(encryptedString);
          break;
      }

      int character = -1;
      string message = DecodeSingleByteXOR(parsedString, out character);
      return message;
    }

    /// <summary>
    /// Decode a single byte XOR on an array of bytes that has been encrypted
    /// </summary>
    /// <param name="encryptedBytes">The bytes that are encrypted</param>
    /// <returns>Return a string with the associated message of the decrypted bytes</returns>
    public string DecodeSingleByteXOR(byte[] encryptedBytes, out int character)
    {
      string associatedString = string.Empty;
      double highestScore = -1;
      character = 0;

      byte[] filledByteArray = new byte[encryptedBytes.Length];
      // Loop for each possible byte
      for (int i = byte.MinValue; i <= byte.MaxValue; i++)
      {
        for (int k = 0; k < encryptedBytes.Length; k++)
          filledByteArray[k] = (byte)i;

        // Decrypt for every value of a byte
        byte[] xorBytes = this.XORBuffer(filledByteArray, encryptedBytes);
        string decoded = Encoding.ASCII.GetString(xorBytes);
        double scored = this.GetFrequencyScore(xorBytes);

        // Evalute the string with the best frequency score
        if (highestScore < 0 || (scored >= 0 && scored < highestScore))
        {
          highestScore = scored;
          associatedString = decoded;
          character = i;
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
      double bestScore = -1;
      foreach (string line in challengeText)
      {
        string ret = this.DecodeSingleByteXOR(line, stringType);
        double retScore = this.GetFrequencyScore(ret);

        if (bestScore < 0 || (retScore >= 0 && retScore < bestScore))
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
    /// <returns>A byte array containing the hex string</returns>
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
    /// Decrypt text that has been encrypted via a Repeating XOR
    /// </summary>
    /// <param name="cipherText">The encrypted text</param>
    /// <returns>The decrypted string</returns>
    public string BreakRepeatingXOR(byte[] cipherText)
    {
      List<KeyValuePair<int, float>> potentialKeys = this.FindKeySize(cipherText);

      double keyScore = -1;
      string keyBest = string.Empty;

      foreach (KeyValuePair<int, float> entry in potentialKeys)
      {
        int colNum = entry.Key;
        int numBlocks = cipherText.Length / colNum;
        int bytesLeft = cipherText.Length % colNum;

        byte[][] dataMatrix = new byte[colNum][];

        // Loop for every column in matrix
        for (int i = 0; i < colNum; i++)
        {
          bool leftOverData = i < bytesLeft;
          byte[] columnData = new byte[leftOverData ? numBlocks + 1 : numBlocks];

          // Loop for the entire row
          for (int j = 0; j < numBlocks; j++)
            columnData[j] = cipherText[j * colNum + i];

          if (leftOverData)
          {
            columnData[numBlocks] = cipherText[numBlocks * colNum + i];
          }

          dataMatrix[i] = columnData;
        }

        StringBuilder key = new StringBuilder();
        foreach (byte[] keyPiece in dataMatrix)
        {
          int character = -1;
          this.DecodeSingleByteXOR(keyPiece, out character);
          key.Append((char)character);
        }

        double score = this.GetFrequencyScore(key.ToString());
        if (keyScore < 0 || score >= 0 && score < keyScore)
        {
          keyScore = score;
          keyBest = key.ToString();
        }
      }

      byte[] plainText = this.RepeatingKeyXOR(Encoding.ASCII.GetString(cipherText), keyBest);
      return Encoding.ASCII.GetString(plainText);
    }

    private double GetFrequencyScore(string input)
    {
      return this.GetFrequencyScore(Encoding.ASCII.GetBytes(input));
    }

    /// <summary>
    /// Scores the value of a string. The higher the score, the better.
    /// </summary>
    /// <param name="input">The string to evaluate</param>
    /// <returns>an integer representing the frequency score of the string</returns>
    private double GetFrequencyScore(byte[] input)
    {
      // If the input was empty
      if (input.Length <= 0)
        return -1;

      Dictionary<char, int> frequency = new Dictionary<char, int>();
      int ignoreCharacterCount = 0;

      // Populate dictionary with the alphabet
      for(int i = 0; i < 26; i++)
        frequency.Add((char)(0x41 + i), 0);

      // Add space to dictionary
      frequency.Add(' ', 0);

      foreach (char letter in input)
      {
        if ((letter >= 0x41 && letter <= 0x5A) || (letter >= 0x61 && letter <= 0x7a) || letter == 0x20)
        {
          // If the letter is part of the alphabet (A-Z || a-z || ' ')
          char letterFormatted = Char.ToUpper(letter);
          frequency[letterFormatted]++;
        }
        else if (
          (letter >= 0x20 && letter <= 0x7E) ||
          letter == 0x09 ||
          letter == 0x0A ||
          letter == 0x0D
          )
        {
          // Character exists but is a number/punctuation
          // Or character is a tab, carriage return, or line feed
          ignoreCharacterCount++;
        }
        else
        { 
          // Some other non-valid english character, not valid
          return -1;
        }
      }

      // If the entire sentence has invalid characters, return a negative (invalid) number
      if (ignoreCharacterCount >= input.Length)
        return -1;

      CharacterFrequency expectedFrequencies = new CharacterFrequency();
      double sum = 0;
      int validCharLength = input.Length - ignoreCharacterCount;
      foreach (KeyValuePair<char, int> kvp in frequency)
      {
        double expectedFrequency = validCharLength * expectedFrequencies.FrequencyDictionarySpace[kvp.Key];
        double difference = kvp.Value - expectedFrequency;
        sum += Math.Pow(difference, 2) / expectedFrequency;
      }

      return sum;

      //List<KeyValuePair<char, int>> list = frequency.ToList();
      //list.Sort((x, y) => y.Value.CompareTo(x.Value));

      //char[] common = { 'E', 'T', 'A', 'O', 'I', 'N', ' ' };
      //int frequencyScore = 0;

      //List<KeyValuePair<char, int>> TopFive = list.GetRange(0, list.Count >= 5 ? 5 : list.Count);
      
      //foreach (KeyValuePair<char, int> kvp in TopFive)
      //  if (common.Contains(kvp.Key))
      //  {
      //    frequencyScore++;
      //    frequencyScore += kvp.Value;
      //  }

      //return frequencyScore;
    }


    /// <summary>
    /// Finds the potential key sizes in a cipher text
    /// </summary>
    /// <param name="cipherText">The encrypted text</param>
    /// <returns>A list of possible key sizes</returns>
    private List<KeyValuePair<int, float>> FindKeySize(byte[] cipherText)
    {
      HammingDistanceCalculator calc = new HammingDistanceCalculator();
      Dictionary<int, float> normalizedEntries = new Dictionary<int, float>();

      // Suggested Key size assumption by challenge
      int MAX_SIZE = 40, MIN_SIZE = 2;

      for (int KEYSIZE = MIN_SIZE; KEYSIZE <= MAX_SIZE; KEYSIZE++)
      {
        int blockNum = (int)(cipherText.Length / KEYSIZE);
        List<float> distances = new List<float>();
        byte[] firstBuffer = new byte[KEYSIZE], secondBuffer = new byte[KEYSIZE], thirdBuffer = new byte[KEYSIZE], fourthBuffer = new byte[KEYSIZE];

        // Partition Data into buffers
        Buffer.BlockCopy(cipherText, 0, firstBuffer, 0, KEYSIZE);
        Buffer.BlockCopy(cipherText, KEYSIZE * 1, secondBuffer, 0, KEYSIZE);
        Buffer.BlockCopy(cipherText, KEYSIZE * 2, thirdBuffer, 0, KEYSIZE);
        Buffer.BlockCopy(cipherText, KEYSIZE * 3, fourthBuffer, 0, KEYSIZE);

        // Calculate distances
        distances.Add(calc.CalculateDistance(firstBuffer, secondBuffer));
        distances.Add(calc.CalculateDistance(firstBuffer, thirdBuffer));
        distances.Add(calc.CalculateDistance(firstBuffer, fourthBuffer));
        distances.Add(calc.CalculateDistance(secondBuffer, thirdBuffer));
        distances.Add(calc.CalculateDistance(secondBuffer, fourthBuffer));
        distances.Add(calc.CalculateDistance(thirdBuffer, fourthBuffer));

        float averageNormalized = distances.Sum() / KEYSIZE;
        normalizedEntries.Add(KEYSIZE, averageNormalized);
      }

      List<KeyValuePair<int, float>> list = normalizedEntries.ToList();
      list.Sort((pair1, pair2) => pair1.Value.CompareTo(pair2.Value));

      // Only save the top 4 entries
      return list.GetRange(0, 4);
    }

  }
}

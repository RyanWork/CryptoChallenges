using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals
{
  public class HammingDistanceCalculator
  {
    /// <summary>
    /// Calculates the Hamming distance between two byte arrays
    /// </summary>
    /// <param name="originalText">First text input</param>
    /// <param name="newText">The text to change to</param>
    /// <returns>An integer calculation representing the hamming distance</returns>
    public float CalculateDistance(byte[] originalText, byte[] newText)
    {
      if (originalText.Length != newText.Length)
        throw new Exceptions.UnequalLengthException();

      int changeCounter = 0;
      for (int i = 0; i < originalText.Length; i++)
      {
        byte XORBytes = (byte)(originalText[i] ^ newText[i]);
        while (true)
        {
          // If we finished iterating through the byte
          if (XORBytes == 0x00)
            break;

          // Check if the byte is 1
          if ((XORBytes & 0x01) == 0x01)
            changeCounter++;

          // Shift the byte to count
          XORBytes = (byte)(XORBytes >> 0x01);
        }
      }

      return changeCounter;
    }
  }
}

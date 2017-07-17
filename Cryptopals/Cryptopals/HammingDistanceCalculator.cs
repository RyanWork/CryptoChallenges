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
    public int CalculateDistance(byte[] originalText, byte[] newText)
    {
      if (originalText.Length != newText.Length)
        throw new Exceptions.UnequalLengthException();

      int changeCounter = 0;
      for(int i = 0; i < originalText.Length; i++)
      {
        while (true)
        {
          if (originalText[i] == 0x00 && newText[i] == 0x00)
            break;

          if ((originalText[i] & 0x01) != (newText[i] & 0x01))
            changeCounter++;

          originalText[i] = (byte)(originalText[i] >> 0x01);
          newText[i] = (byte)(newText[i] >> 0x01);
        }
      }

      return changeCounter;
    }
  }
}

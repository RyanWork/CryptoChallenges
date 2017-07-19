using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals
{
  public class CharacterFrequency
  {
    public Dictionary<char, double> FrequencyDictionary { get; }

    public CharacterFrequency()
    {
      this.FrequencyDictionary = new Dictionary<char, double>()
      {
        { 'E', 0.12702 },
        { 'T', 0.09056 },
        { 'A', 0.08167 },
        { 'O', 0.07507 },
        { 'I', 0.06966 },
        { 'N', 0.06749 },
        { 'S', 0.06327 },
        { 'H', 0.06094 },
        { 'R', 0.05987 },
        { 'D', 0.04253 },
        { 'L', 0.04025 },
        { 'C', 0.02782 },
        { 'U', 0.02758 },
        { 'M', 0.02406 },
        { 'F', 0.02228 },
        { 'W', 0.02360 },
        { 'G', 0.02015 },
        { 'P', 0.01929 },
        { 'Y', 0.01974 },
        { 'B', 0.01492 },
        { 'V', 0.00978 },
        { 'K', 0.00772 },
        { 'X', 0.00150 },
        { 'J', 0.00153 },
        { 'Q', 0.00095 },
        { 'Z', 0.00074 }
      };
    }
  }
}

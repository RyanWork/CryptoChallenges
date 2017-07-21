using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals
{
  public class CharacterFrequency
  {
    public Dictionary<char, double> FrequencyDictionarySpace { get; }

    public Dictionary<char, double> FrequencyDictionary { get; }

    public CharacterFrequency()
    {
      // Taken from http://www.data-compression.com/english.html
      this.FrequencyDictionarySpace = new Dictionary<char, double>()
      {
        { 'E', 0.1041442 },
        { 'T', 0.0729357 },
        { 'A', 0.0651738 },
        { 'O', 0.0596302 },
        { 'I', 0.0558094 },
        { 'N', 0.0564513 },
        { 'S', 0.0515760 },
        { 'H', 0.0492888 },
        { 'R', 0.0497563 },
        { 'D', 0.0349835 },
        { 'L', 0.0331490 },
        { 'C', 0.0217339 },
        { 'U', 0.0225134 },
        { 'M', 0.0202124 },
        { 'F', 0.0197881 },
        { 'W', 0.0171272 },
        { 'G', 0.0158610 },
        { 'P', 0.0137645 },
        { 'Y', 0.0145984 },
        { 'B', 0.0124248 },
        { 'V', 0.0082903 },
        { 'K', 0.0050529 },
        { 'X', 0.0013692 },
        { 'J', 0.0009033 },
        { 'Q', 0.0008606 },
        { 'Z', 0.0007836 },
        { ' ', 0.1918182 }
      };

      // Taken from https://en.wikipedia.org/wiki/Letter_frequency
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
        { 'Z', 0.00074 },
      };
    }
  }
}

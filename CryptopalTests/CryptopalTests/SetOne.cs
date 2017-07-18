using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cryptopals;
using System.IO;
using System.Text;

namespace CryptopalTests
{
  [TestCategory("SetOne")]
  [TestClass]
  public class SetOne
  {
    Cryptography crypto;

    [TestInitialize]
    public void TestSetup()
    {
      this.crypto = new Cryptography();
    }

    [TestMethod]
    public void SetOneChallengeOne()
    {
      string firstChallenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
      string expectedString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
      string Base64 = Convert.ToBase64String(this.crypto.ConvertHexStringToByteArray(firstChallenge));

      Assert.AreEqual(expectedString, Base64);
    }

    [TestMethod]
    public void SetOneChallengeTwo()
    {
      string inputString = "1c0111001f010100061a024b53535009181c";
      string xorString = "686974207468652062756c6c277320657965";
      string expectedString = "746865206b696420646f6e277420706c6179";
      string result = this.crypto.JoinArrayToString((this.crypto.XORBuffer(inputString, xorString)));

      Assert.AreEqual(expectedString, result);
    }

    [TestMethod]
    public void SetOneChallengeThree()
    {
      string inputString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
      string expectedString = "Cooking MC's like a pound of bacon";
      string result = this.crypto.DecodeSingleByteXOR(inputString, Cryptography.StringType.Hex);

      Assert.AreEqual(expectedString, result);
    }

    [TestMethod]
    public void SetOneChallengeFour()
    {
      string expectedString = "Now that the party is jumping";
      string result = crypto.DecodeSingleByteXORFile(Cryptography.CHALLENGE_FOUR_FILE, Cryptography.StringType.Hex);

      Assert.AreEqual(expectedString, result);
    }

    [TestMethod]
    public void SetOneChallengeFive()
    {
      string expectedString = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
      string plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
      string result = crypto.JoinArrayToString(crypto.RepeatingKeyXOR(plaintext, "ICE"));

      Assert.AreEqual(expectedString, result);
    }

    [TestMethod]
    public void TestHammingDistance()
    {
      HammingDistanceCalculator calc = new HammingDistanceCalculator();
      float expectedValue = 37;
      float result = calc.CalculateDistance(Encoding.ASCII.GetBytes("this is a test"), Encoding.ASCII.GetBytes("wokka wokka!!!"));

      Assert.AreEqual(expectedValue, result);
    }
  }
}

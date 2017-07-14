using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cryptopals;

namespace CryptopalTests
{
  [TestClass]
  public class CryptoTests
  {
    Cryptography crypto;

    [TestInitialize]
    public void TestSetup()
    {
      this.crypto = new Cryptography();
    }

    [TestCategory("SetOne")]
    [TestMethod]
    public void SetOneChallengeOne()
    {
      string firstChallenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
      string expectedString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
      string Base64 = Convert.ToBase64String(this.crypto.ConvertHexToBase64(firstChallenge));

      Assert.AreEqual(expectedString, Base64);
    }

    [TestCategory("SetOne")]
    [TestMethod]
    public void SetOneChallengeTwo()
    {
      string inputString = "1c0111001f010100061a024b53535009181c";
      string xorString = "686974207468652062756c6c277320657965";
      string expectedString = "746865206b696420646f6e277420706c6179";

      string result = this.crypto.JoinArrayToString((this.crypto.XORBuffer(inputString, xorString)));

      Assert.AreEqual(expectedString, result);
    }
  }
}

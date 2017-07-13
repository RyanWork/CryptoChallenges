﻿using System;
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
  }
}

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptopals;

namespace CryptopalTests
{
  [TestCategory("SetTwo")]
  [TestClass]
  public class SetTwo
  {
    BlockCryptography blockCrypto;

    [TestInitialize]
    public void TestSetup()
    {
      blockCrypto = new BlockCryptography();
    }

    [TestMethod]
    public void ChallengeOne_AppendPKCS7Padding()
    {
      string expectedString = "YELLOW SUBMARINE\0x04\0x04\0x04\0x04";
      string result = blockCrypto.AppendPKCS7Padding("YELLOW SUBMARINE", 20);
      Assert.AreEqual(expectedString, result);
    }
  }
}

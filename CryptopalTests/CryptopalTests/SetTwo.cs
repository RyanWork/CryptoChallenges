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
    public void ChallengeNine_AppendPKCS7Padding()
    {
      string expectedString = "YELLOW SUBMARINE\u0004\u0004\u0004\u0004";
      string result = blockCrypto.AppendPKCS7Padding("YELLOW SUBMARINE", 20);
      Assert.AreEqual(expectedString, result);
    }

    [TestMethod]
    public void TestEncryptECB()
    {
      byte[] key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
      byte[] encryptedBytes = blockCrypto.EncryptECB(key, Encoding.ASCII.GetBytes("Hello World!"));
      string decryptedText = Encoding.ASCII.GetString(blockCrypto.DecryptECB(key, encryptedBytes)).Trim('\u0004');
      Assert.AreEqual("Hello World!", decryptedText);
    }

    [TestMethod]
    public void ChallengeTen_ImplementCBC()
    {
      string expectedString = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \n"
      + "And I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \n"
      + "Spaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n"
      + "'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\n"
      + "Play that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

      byte[] key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
      // Add null 0's (ASCII 0x00 value)
      byte[] IV = Encoding.ASCII.GetBytes("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000");
      string text = Properties.Resources.Challenge10Text.Replace(System.Environment.NewLine, string.Empty);
      byte[] textBytesHex = Convert.FromBase64String(text);
      string result = blockCrypto.DecryptCBC(IV, key, textBytesHex);
      //string result = blockCrypto.DecryptCBC(IV, key, Encoding.ASCII.GetBytes("CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRFV/xIN2k8Go7jtArLIy"));

      Assert.AreEqual(expectedString, result);
    }

    [TestMethod]
    public void TestEncryptCBC()
    {
      byte[] key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
      byte[] IV = Encoding.ASCII.GetBytes("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000");
      byte[] encryptedBytes = blockCrypto.EncryptCBC(IV, key, "Hello World!");
      string decryptedText = blockCrypto.DecryptCBC(IV, key, encryptedBytes);

      Assert.AreEqual("Hello World!", decryptedText);
    }
  }
}

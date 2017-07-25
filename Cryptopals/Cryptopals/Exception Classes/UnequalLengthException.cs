using System;

namespace Cryptopals.Exceptions
{
  /// <summary>
  /// Exception class thrown when user has provided values that are not equal in length
  /// </summary>
  public class UnequalLengthException : Exception
  {
    public UnequalLengthException()
    {
    }

    public UnequalLengthException(string message)
        : base(message)
    {
    }

    public UnequalLengthException(string message, Exception inner)
        : base(message, inner)
    {
    }
  }
}

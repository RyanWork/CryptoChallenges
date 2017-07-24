using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals.Exceptions
{
  public class InvalidPaddingSizeException : Exception
  {
    public InvalidPaddingSizeException()
    {
    }

    public InvalidPaddingSizeException(string message)
          : base(message)
      {
    }

    public InvalidPaddingSizeException(string message, Exception inner)
          : base(message, inner)
      {
    }
  }
}

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace NTDLS.SecureKeyExchange
{
    internal class Randomness
    {
        public static int GetRandomNumberFromList(List<int> numbers)
        {
            return numbers[GetRandomNumber(0, numbers.Count - 1)];
        }

        /// <summary>
        /// Generates a clamped-by-wrapping random number.
        /// </summary>
        public static int GetRandomNumber(int min, int max)
        {
            var randomInt = BitConverter.ToInt32(RandomNumberGenerator.GetBytes(4));

            if (randomInt < min)
            {
                return max - (min - randomInt) % (max - min);
            }
            else
            {
                return min + (randomInt - min) % (max - min);
            }
        }
    }
}

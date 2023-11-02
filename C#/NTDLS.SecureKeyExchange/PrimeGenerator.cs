using System.Collections.Generic;

namespace NTDLS.SecureKeyExchange
{
    internal class PrimeGenerator
    {
        /// <summary>
        /// Used to generate a list of primes between two numbers. These clamps are supplied at random.
        /// </summary>
        public static List<int> GeneratePrimesStartingFrom(int startPrime, int count)
        {
            var primes = new List<int>();
            int currentPrime = startPrime;

            while (primes.Count < count)
            {
                currentPrime = FindNextPrime(currentPrime + 1);
                primes.Add(currentPrime);
            }

            return primes;
        }

        private static int FindNextPrime(int start)
        {
            int number = start;

            while (true)
            {
                if (IsPrime(number))
                {
                    return number;
                }
                number++;
            }
        }

        private static bool IsPrime(int number)
        {
            if (number <= 1)
            {
                return false;
            }
            if (number <= 3)
            {
                return true;
            }
            if (number % 2 == 0 || number % 3 == 0)
            {
                return false;
            }

            for (int i = 5; i * i <= number; i += 6)
            {
                if (number % i == 0 || number % (i + 2) == 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}

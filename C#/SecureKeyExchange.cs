using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace SecureKeyExchange
{
    public class SecureKeyNegotiator
    {
        #region Backend Variables.

        private Random rand;

        private int minPrime = 1000;
        private int maxPrime = 100000;

        private int minSecret = 100;
        private int maxSecret = int.MaxValue;

        private int sharedPrime;
        private int sharedGenerator;
        private int secretNumber;

        private int publicNumber;
        private int sharedSecret;
        private int foreignPublicNumber;

        private bool negoationComplete = false;

        #endregion

        public SecureKeyNegotiator()
        {
            this.rand = new Random(Guid.NewGuid().GetHashCode());
        }

        public bool NegoationComplete
        {
            get
            {
                return negoationComplete;
            }
        }

        public int PublicNumber
        {
            get
            {
                if (negoationComplete == false)
                {
                    return 0;
                }

                return this.publicNumber;
            }
        }

        public byte[] PublicHash
        {
            get
            {
                if (negoationComplete == false)
                {
                    return null;
                }

                SHA256Managed sha = new SHA256Managed();

                byte[] bytes = new byte[12];

                Buffer.BlockCopy(BitConverter.GetBytes(this.sharedPrime), 0, bytes, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(this.publicNumber), 0, bytes, 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(this.sharedGenerator), 0, bytes, 8, 4);

                return sha.ComputeHash(bytes);
            }
        }

        public string PublicNumberString
        {
            get
            {
                if (negoationComplete == false)
                {
                    return null;
                }

                return BitConverter.ToString(PublicHash).Replace("-", string.Empty);
            }
        }

        public int SharedSecret
        {
            get
            {
                if (negoationComplete == false)
                {
                    return 0;
                }

                return this.sharedSecret;
            }
        }

        public byte[] SharedSecretHash
        {
            get
            {
                if (negoationComplete == false)
                {
                    return null;
                }

                using (SHA256Managed sha = new SHA256Managed())
                {
                    byte[] bytes = new byte[12];

                    Buffer.BlockCopy(BitConverter.GetBytes(this.sharedPrime), 0, bytes, 0, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(this.sharedSecret), 0, bytes, 4, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(this.sharedGenerator), 0, bytes, 8, 4);

                    return sha.ComputeHash(bytes);
                }
            }
        }

        public string SharedSecretString
        {
            get
            {
                if (negoationComplete == false)
                {
                    return null;
                }

                return BitConverter.ToString(SharedSecretHash).Replace("-", string.Empty);
            }
        }

        public byte[] GenerateNegotiationToken()
        {
            byte[] token = new byte[12];

            List<int> primes;

            do
            {
                int randomMax = rand.Next(minPrime, this.maxPrime);
                primes = GetPrimes(minPrime, randomMax);
            } while (primes.Count < 100);

            this.sharedPrime = GetRandomNumberFromList(primes);
            this.sharedGenerator = rand.Next(minPrime, this.sharedPrime - 1);
            this.secretNumber = rand.Next(minSecret, maxSecret);
            this.publicNumber = (int)BigInteger.ModPow(this.sharedGenerator, this.secretNumber, this.sharedPrime);

            Buffer.BlockCopy(BitConverter.GetBytes(this.sharedPrime), 0, token, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(this.sharedGenerator), 0, token, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(this.publicNumber), 0, token, 8, 4);

            return token;
        }

        public byte[] ApplyNegotiationToken(byte[] token)
        {
            byte[] buffer = new byte[4];

            Buffer.BlockCopy(token, 0, buffer, 0, 4);
            this.sharedPrime = BitConverter.ToInt32(buffer, 0);

            Buffer.BlockCopy(token, 4, buffer, 0, 4);
            this.sharedGenerator = BitConverter.ToInt32(buffer, 0);

            Buffer.BlockCopy(token, 8, buffer, 0, 4);
            this.foreignPublicNumber = BitConverter.ToInt32(buffer, 0);

            this.secretNumber = rand.Next(minSecret, maxSecret);
            this.publicNumber = (int)BigInteger.ModPow(this.sharedGenerator, this.secretNumber, this.sharedPrime);
            this.sharedSecret = (int)BigInteger.ModPow(this.foreignPublicNumber, this.secretNumber, this.sharedPrime);

            negoationComplete = true;

            return BitConverter.GetBytes(this.publicNumber);
        }

        public void ApplyNegotiationResponseToken(byte[] token)
        {
            this.foreignPublicNumber = BitConverter.ToInt32(token, 0);
            this.sharedSecret = (int)BigInteger.ModPow(this.foreignPublicNumber, this.secretNumber, this.sharedPrime);
            negoationComplete = true;
        }

        #region Internal Generation.

        private List<int> GetPrimeRoots(double prime)
        {
            List<int> roots = new List<int>();

            if (IsPrime(prime))
            {
                double exponent = 1;
                double power = 0;

                for (int iteration = 2; iteration < prime; iteration++)
                {
                    power = Math.Pow(iteration, exponent);
                    power %= prime;

                    while (power > 1)
                    {
                        power *= iteration;
                        power %= prime;
                        exponent++;
                    }

                    if (exponent == (prime - 1))
                    {
                        roots.Add(iteration);
                    }
                    exponent = 1;
                }
            }

            return roots;
        }

        private bool IsPrime(double possible)
        {
            for (var i = 2; i <= Math.Sqrt(possible); i++)
            {
                if (Math.Floor(possible / i) == (possible / i))
                {
                    return false;
                }
            }
            return (possible >= 2);
        }

        private List<int> GetPrimes(int min, int max)
        {
            return Enumerable.Range(0, (int)Math.Floor(2.52 * Math.Sqrt(max) / Math.Log(max))).Aggregate(
                    Enumerable.Range(2, max - 1).ToList(),
                    (result, index) =>
                    {
                        var bp = result[index];
                        var sqr = bp * bp;
                        result.RemoveAll(i => i >= sqr && i % bp == 0);
                        return result;
                    }
                ).Where(o => o >= min).ToList();
        }

        private int GetRandomNumberFromList(List<int> numbers)
        {
            return numbers[rand.Next(0, numbers.Count - 1)];
        }

        #endregion
    }
}

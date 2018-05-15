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

        private readonly Random _rand;

        private readonly int _minPrime = 1000;
        private readonly int _maxPrime = 100000;

        private readonly int _minSecret = 100;
        private readonly int _maxSecret = int.MaxValue;

        private int _sharedPrime;
        private int _sharedGenerator;
        private int _secretNumber;

        private int _publicNumber;
        private int _sharedSecret;
        private int _foreignPublicNumber;

        private bool _negoationComplete = false;

        #endregion

        public SecureKeyNegotiator()
        {
            this._rand = new Random(Guid.NewGuid().GetHashCode());
        }

        public bool NegoationComplete
        {
            get
            {
                return _negoationComplete;
            }
        }

        public int PublicNumber
        {
            get
            {
                if (_negoationComplete == false)
                {
                    return 0;
                }

                return this._publicNumber;
            }
        }

        public byte[] PublicHash
        {
            get
            {
                if (_negoationComplete == false)
                {
                    return null;
                }

                SHA256Managed sha = new SHA256Managed();

                byte[] bytes = new byte[12];

                Buffer.BlockCopy(BitConverter.GetBytes(this._sharedPrime), 0, bytes, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(this._publicNumber), 0, bytes, 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(this._sharedGenerator), 0, bytes, 8, 4);

                return sha.ComputeHash(bytes);
            }
        }

        public string PublicNumberString
        {
            get
            {
                if (_negoationComplete == false)
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
                if (_negoationComplete == false)
                {
                    return 0;
                }

                return this._sharedSecret;
            }
        }

        public byte[] SharedSecretHash
        {
            get
            {
                if (_negoationComplete == false)
                {
                    return null;
                }

                using (SHA256Managed sha = new SHA256Managed())
                {
                    byte[] bytes = new byte[12];

                    Buffer.BlockCopy(BitConverter.GetBytes(this._sharedPrime), 0, bytes, 0, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(this._sharedSecret), 0, bytes, 4, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes(this._sharedGenerator), 0, bytes, 8, 4);

                    return sha.ComputeHash(bytes);
                }
            }
        }

        public string SharedSecretString
        {
            get
            {
                if (_negoationComplete == false)
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
                int randomMax = _rand.Next(_minPrime, this._maxPrime);
                primes = GetPrimes(_minPrime, randomMax);
            } while (primes.Count < 100);

            this._sharedPrime = GetRandomNumberFromList(primes);
            this._sharedGenerator = _rand.Next(_minPrime, this._sharedPrime - 1);
            this._secretNumber = _rand.Next(_minSecret, _maxSecret);
            this._publicNumber = (int)BigInteger.ModPow(this._sharedGenerator, this._secretNumber, this._sharedPrime);

            Buffer.BlockCopy(BitConverter.GetBytes(this._sharedPrime), 0, token, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(this._sharedGenerator), 0, token, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(this._publicNumber), 0, token, 8, 4);

            return token;
        }

        public byte[] ApplyNegotiationToken(byte[] token)
        {
            byte[] buffer = new byte[4];

            Buffer.BlockCopy(token, 0, buffer, 0, 4);
            this._sharedPrime = BitConverter.ToInt32(buffer, 0);

            Buffer.BlockCopy(token, 4, buffer, 0, 4);
            this._sharedGenerator = BitConverter.ToInt32(buffer, 0);

            Buffer.BlockCopy(token, 8, buffer, 0, 4);
            this._foreignPublicNumber = BitConverter.ToInt32(buffer, 0);

            this._secretNumber = _rand.Next(_minSecret, _maxSecret);
            this._publicNumber = (int)BigInteger.ModPow(this._sharedGenerator, this._secretNumber, this._sharedPrime);
            this._sharedSecret = (int)BigInteger.ModPow(this._foreignPublicNumber, this._secretNumber, this._sharedPrime);

            _negoationComplete = true;

            return BitConverter.GetBytes(this._publicNumber);
        }

        public void ApplyNegotiationResponseToken(byte[] token)
        {
            this._foreignPublicNumber = BitConverter.ToInt32(token, 0);
            this._sharedSecret = (int)BigInteger.ModPow(this._foreignPublicNumber, this._secretNumber, this._sharedPrime);
            _negoationComplete = true;
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
            return numbers[_rand.Next(0, numbers.Count - 1)];
        }

        #endregion
    }
}

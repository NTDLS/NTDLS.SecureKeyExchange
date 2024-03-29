﻿using System;
using System.Numerics;
using System.Security.Cryptography;

namespace NTDLS.SecureKeyExchange
{
    /// <summary>
    /// Used to negoation a single share int32 using a Diffie-Helmlman algorithm.
    /// </summary>
    public class UnitNegotiator
    {
        private const int TOKEN_SZ = 12;
        private const int PRIME_BATCH_SZ = 10000;

        #region Private backend variables.

        private readonly int _minPrime = 2;
        private readonly int _maxPrime = 10000019;

        private readonly int _minSecret = 100;
        private readonly int _maxSecret = int.MaxValue;

        private int _sharedPrime;
        private int _sharedGenerator;
        private int _secretNumber;

        private int _publicNumber;
        private int _sharedSecretNumber;
        private int _foreignPublicNumber;

        #endregion

        /// <summary>
        /// Is set to true when key exchange is completed.
        /// </summary>
        public bool IsNegoationComplete { get; private set; }

        /// <summary>
        /// The length of the shared key.
        /// </summary>
        public int KeyLength { get; private set; }

        /// <summary>
        /// The complete bytes to the shared secret between the two nodes.
        /// </summary>
        public byte[] SharedSecret
        {
            get
            {
                if (IsNegoationComplete == false)
                {
                    return null;
                }

                var token = new byte[12];
                Buffer.BlockCopy(BitConverter.GetBytes(_sharedPrime), 0, token, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(_sharedSecretNumber), 0, token, 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(_sharedGenerator), 0, token, 8, 4);
                return token;
            }
        }

        /// <summary>
        /// The SHA256 hash of the shared secret.
        /// </summary>
        public string SharedSecretHash
        {
            get
            {
                if (IsNegoationComplete)
                {
                    return BitConverter.ToString(SHA512.HashData(SharedSecret)).Replace("-", string.Empty);
                }
                return null;
            }
        }

        /// <summary>
        /// Step #1-3, generates random numbers, primes, local secret and public numbers for exchange with a peer.
        /// </summary>
        /// <returns>Returns byte array containing the shared prime, shared generator and shared number. This is to be sent to the peer.</returns>
        public byte[] GenerateNegotiationToken()
        {
            KeyLength = TOKEN_SZ;

            byte[] token = new byte[12];

            int primeFloor = Randomness.GetRandomNumber(_minPrime, _maxPrime);
            var primes = PrimeGenerator.GeneratePrimesStartingFrom(primeFloor / 2, PRIME_BATCH_SZ);
            _sharedPrime = Randomness.GetRandomNumberFromList(primes);

            _sharedGenerator = Randomness.GetRandomNumber(_minPrime, _sharedPrime - 1);
            _secretNumber = Randomness.GetRandomNumber(_minSecret, _maxSecret);
            _publicNumber = (int)BigInteger.ModPow(_sharedGenerator, _secretNumber, _sharedPrime);

            Buffer.BlockCopy(BitConverter.GetBytes(_sharedPrime), 0, token, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(_sharedGenerator), 0, token, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(_publicNumber), 0, token, 8, 4);

            return token;
        }

        /// <summary>
        /// Step #2-3, applies, at the peer, the public information provided by a call to GenerateNegotiationToken().
        /// </summary>
        /// <param name="token">Bytes passed to us from peer call to GenerateNegotiationToken()</param>
        /// <returns>Returns the public product from the application of shared data from remote peer. This is to be sent back to the peer.</returns>
        public byte[] ApplyNegotiationToken(byte[] token)
        {
            KeyLength = TOKEN_SZ;

            byte[] buffer = new byte[4];

            Buffer.BlockCopy(token, 0, buffer, 0, 4);
            _sharedPrime = BitConverter.ToInt32(buffer, 0);

            Buffer.BlockCopy(token, 4, buffer, 0, 4);
            _sharedGenerator = BitConverter.ToInt32(buffer, 0);

            Buffer.BlockCopy(token, 8, buffer, 0, 4);
            _foreignPublicNumber = BitConverter.ToInt32(buffer, 0);

            _secretNumber = Randomness.GetRandomNumber(_minSecret, _maxSecret);
            _publicNumber = (int)BigInteger.ModPow(_sharedGenerator, _secretNumber, _sharedPrime);
            _sharedSecretNumber = (int)BigInteger.ModPow(_foreignPublicNumber, _secretNumber, _sharedPrime);

            IsNegoationComplete = true;

            return BitConverter.GetBytes(_publicNumber);
        }

        /// <summary>
        /// Step #3-3, applies the public number sent from the remote peers call to ApplyNegotiationToken and applies it locally. This completes the key exchaange process.
        /// </summary>
        /// <param name="token">Bytes passed to us from peer call to ApplyNegotiationToken()</param>
        public void ApplyNegotiationResponseToken(byte[] token)
        {
            _foreignPublicNumber = BitConverter.ToInt32(token, 0);
            _sharedSecretNumber = (int)BigInteger.ModPow(_foreignPublicNumber, _secretNumber, _sharedPrime);
            IsNegoationComplete = true;
        }
    }
}

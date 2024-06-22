using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace NTDLS.SecureKeyExchange
{
    /// <summary>
    /// Used to negotiate multiple units to create a compound key.
    /// </summary>
    public class CompoundNegotiator
    {
        #region Private backend variables.

        private const int UNIT_KEY_SIZE = 16;
        private const int EXCHANGE_SIZE = 12;
        private const int REPLY_TOKEN_SZ = 4;

        private readonly List<UnitNegotiator> _unitNegotiators = new();
        private byte[]? _sharedBytes = null;
        private int _unitCount;

        #endregion

        /// <summary>
        /// The desired length of the compound key.
        /// </summary>
        public int KeyLength { get; private set; }

        /// <summary>
        /// Step #1-3, generates random numbers, primes, local secret and public numbers for exchange with a peer.
        /// </summary>
        /// <param name="unitCount">The number of key exchange units to complete in this transaction. This determines the size of the final shared key.</param>
        /// <returns>Returns byte array containing the shared prime, shared generator and shared number. This is to be sent to the peer.</returns>
        public byte[] GenerateNegotiationToken(int unitCount)
        {
            _unitCount = unitCount;
            KeyLength = _unitCount * UNIT_KEY_SIZE;

            var tokens = new byte[_unitCount * EXCHANGE_SIZE];

            for (int i = 0; i < _unitCount; i++)
            {
                var unitNegotiator = new UnitNegotiator();
                var token = unitNegotiator.GenerateNegotiationToken();
                token.CopyTo(tokens, i * EXCHANGE_SIZE);
                _unitNegotiators.Add(unitNegotiator);
            }

            return tokens;
        }

        /// <summary>
        /// Step #2-3, applies, at the peer, the public information provided by a call to GenerateNegotiationToken().
        /// </summary>
        /// <returns>Returns the public product from the application of shared data from remote peer. This is to be sent back to the peer.</returns>
        /// <param name="tokens">Bytes passed to us from peer call to GenerateNegotiationToken()</param>
        public byte[] ApplyNegotiationToken(byte[] tokens)
        {
            if (tokens.Length % EXCHANGE_SIZE != 0)
            {
                throw new ArgumentException($"Invalid token size. The token size must be a multiple of {EXCHANGE_SIZE}", nameof(tokens));
            }

            _unitCount = tokens.Length / EXCHANGE_SIZE;
            KeyLength = _unitCount * UNIT_KEY_SIZE;
            var replyTokens = new byte[REPLY_TOKEN_SZ * _unitCount];

            for (int i = 0; i < _unitCount; i++)
            {
                var unitNegotiator = new UnitNegotiator();

                var token = new byte[EXCHANGE_SIZE];
                Buffer.BlockCopy(tokens, i * EXCHANGE_SIZE, token, 0, EXCHANGE_SIZE);
                var replyToken = unitNegotiator.ApplyNegotiationToken(token);
                replyToken.CopyTo(replyTokens, i * REPLY_TOKEN_SZ);

                _unitNegotiators.Add(unitNegotiator);
            }

            return replyTokens;
        }

        /// <summary>
        /// Step #3-3, applies the public number sent from the remote peers call to ApplyNegotiationToken and applies it locally. This completes the key exchaange process.
        /// </summary>
        /// <param name="tokens">Bytes passed to us from peer call to ApplyNegotiationToken()</param>
        public void ApplyNegotiationResponseToken(byte[] tokens)
        {
            if (tokens.Length % REPLY_TOKEN_SZ != 0)
            {
                throw new ArgumentException($"Invalid token size. The token size must be a multiple of {REPLY_TOKEN_SZ}", nameof(tokens));
            }

            for (int i = 0; i < _unitCount; i++)
            {
                var token = new byte[REPLY_TOKEN_SZ];
                Buffer.BlockCopy(tokens, i * REPLY_TOKEN_SZ, token, 0, REPLY_TOKEN_SZ);
                _unitNegotiators[i].ApplyNegotiationResponseToken(token);
            }
        }

        /// <summary>
        /// Is set to true when key exchange is completed.
        /// </summary>
        private bool _isNegotiationComplete;

        /// <summary>
        /// Is set to true when key exchange is completed.
        /// </summary>
        public bool IsNegotiationComplete
        {
            get
            {
                if (_isNegotiationComplete == false)
                {
                    _isNegotiationComplete = _unitNegotiators.Count > 0;

                    for (int i = 0; i < _unitCount; i++)
                    {
                        if (_unitNegotiators[i].IsNegotiationComplete == false)
                        {
                            return false;
                        }
                    }
                }

                return _isNegotiationComplete;
            }
        }

        /// <summary>
        /// The complete bytes to the shared secret between the two nodes.
        /// </summary>
        public byte[] SharedSecret
        {
            get
            {
                if (_sharedBytes != null)
                {
                    return _sharedBytes;
                }
                else if (_sharedBytes == null && IsNegotiationComplete)
                {
                    _sharedBytes = new byte[UNIT_KEY_SIZE * _unitCount];

                    for (int i = 0; i < _unitCount; i++)
                    {
                        Buffer.BlockCopy(_unitNegotiators[i].SharedSecret, 0, _sharedBytes, i * UNIT_KEY_SIZE, UNIT_KEY_SIZE);
                    }
                    return _sharedBytes;
                }
                else
                {
                    throw new Exception("Secure key negotiation is not complete.");
                }
            }
        }

        /// <summary>
        /// The SHA256 hash of the shared secret.
        /// </summary>
        public string SharedSecretHash
        {
            get
            {
                if (IsNegotiationComplete)
                {
                    return BitConverter.ToString(SHA512.HashData(SharedSecret)).Replace("-", string.Empty);
                }
                throw new Exception("Secure key negotiation is not complete.");
            }
        }
    }
}

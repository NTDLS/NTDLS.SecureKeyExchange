using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace NTDLS.SecureKeyExchange
{
    public class CompoundNegotiator
    {
        #region Private backend variables.

        private const int TOKEN_SZ = 12;
        private const int REPLY_TOKEN_SZ = 4;

        private List<UnitNegotiator> _unitNegotiators = new List<UnitNegotiator>();
        private byte[] _sharedBytes = null;
        private int _unitCount;

        #endregion

        public int KeyLength { get; private set; }

        /// <summary>
        /// Step #1-3, generates random numbers, primes, local secret and public numbers for exchange with a peer.
        /// </summary>
        /// <param name="unitCount">The number of key exchange units to complete in this transaction. This determines the size of the final shared key.</param>
        /// <returns>Returns byte array containing the shared prime, shared generator and shared number. This is to be sent to the peer.</returns>
        public byte[] GenerateNegotiationToken(int unitCount)
        {
            _unitCount = unitCount;
            KeyLength = _unitCount * TOKEN_SZ;

            var tokens = new byte[_unitCount * TOKEN_SZ];

            for (int i = 0; i < _unitCount; i++)
            {
                var unitNegotiator = new UnitNegotiator();
                var token = unitNegotiator.GenerateNegotiationToken();
                token.CopyTo(tokens, i * TOKEN_SZ);
                _unitNegotiators.Add(unitNegotiator);
            }

            return tokens;
        }

        /// <summary>
        /// Step #2-3, applies, at the peer, the public information provided by a call to GenerateNegotiationToken().
        /// </summary>
        /// <param name="token"></param>
        /// <returns>Returns the public product from the application of shared data from remote peer. This is to be sent back to the peer.</returns>
        /// <param name="token">Bytes passed to us from peer call to GenerateNegotiationToken()</param>
        public byte[] ApplyNegotiationToken(byte[] tokens)
        {
            if (tokens.Length % TOKEN_SZ != 0)
            {
                throw new Exception("Tokens size is invalid.");
            }

            _unitCount = tokens.Length / TOKEN_SZ;
            KeyLength = _unitCount * TOKEN_SZ;
            var replyTokens = new byte[REPLY_TOKEN_SZ * _unitCount];

            for (int i = 0; i < _unitCount; i++)
            {
                var unitNegotiator = new UnitNegotiator();

                var token = new byte[TOKEN_SZ];
                Buffer.BlockCopy(tokens, i * TOKEN_SZ, token, 0, TOKEN_SZ);
                var replyToken = unitNegotiator.ApplyNegotiationToken(token);
                replyToken.CopyTo(replyTokens, i * REPLY_TOKEN_SZ);

                _unitNegotiators.Add(unitNegotiator);
            }

            return replyTokens;
        }

        /// <summary>
        /// Step #3-3, applies the public number sent from the remote peers call to ApplyNegotiationToken and applies it locally. This completes the key exchaange process.
        /// </summary>
        /// <param name="token">Bytes passed to us from peer call to ApplyNegotiationToken()</param>
        public void ApplyNegotiationResponseToken(byte[] tokens)
        {
            if (tokens.Length % REPLY_TOKEN_SZ != 0)
            {
                throw new Exception("Tokens size is invalid.");
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
        private bool _isNegoationComplete;

        /// <summary>
        /// Is set to true when key exchange is completed.
        /// </summary>
        public bool IsNegoationComplete
        {
            get
            {
                if (_isNegoationComplete == false)
                {
                    _isNegoationComplete = _unitNegotiators.Count > 0;

                    for (int i = 0; i < _unitCount; i++)
                    {
                        if (_unitNegotiators[i].IsNegoationComplete == false)
                        {
                            return false;
                        }
                    }
                }

                return _isNegoationComplete;
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
                else if (_sharedBytes == null && IsNegoationComplete)
                {
                    _sharedBytes = new byte[TOKEN_SZ * _unitCount];

                    for (int i = 0; i < _unitCount; i++)
                    {
                        Buffer.BlockCopy(_unitNegotiators[i].SharedSecret, 0, _sharedBytes, i * TOKEN_SZ, TOKEN_SZ);
                    }
                    return _sharedBytes;
                }
                else
                {
                    return null;
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
                if (IsNegoationComplete)
                {
                    using (SHA256Managed sha = new SHA256Managed())
                    {
                        return BitConverter.ToString(sha.ComputeHash(SharedSecret)).Replace("-", string.Empty);
                    }
                }
                return null;
            }
        }
    }
}

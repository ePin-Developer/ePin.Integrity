// Copyright 2015 Coinprism, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//https://github.com/hellwolf/openchain/blob/master/src/Openchain.Ledger/ECKey.cs

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System;
using System.IO;

namespace Core
{
    public class ECKey
    {
        public static bool ValidECDSASignature(string signatureBase64, string messageBase64, string publicKeyBase64)
        {
            var publicKey = Convert.FromBase64String(publicKeyBase64);
            var messageHash = Convert.FromBase64String(messageBase64);
            var signature = Convert.FromBase64String(signatureBase64);
            ECKey Key = new ECKey(publicKey);
            return Key.VerifySignature(messageHash, signature);
        }

        public static string GenerateECDSASignature(string msgHash, string privateKey)
        {
            var signature = ECKey.GetSignature(privateKey, msgHash);
            return signature;
        }

        public static X9ECParameters Secp256k1 { get; } = SecNamedCurves.GetByName("secp256k1");

        public static ECDomainParameters DomainParameter { get; } = new ECDomainParameters(Secp256k1.Curve, Secp256k1.G, Secp256k1.N, Secp256k1.H);

        private ECPublicKeyParameters key;

        public ECKey(byte[] publicKey)
        {
            Org.BouncyCastle.Math.EC.ECPoint q = Secp256k1.Curve.DecodePoint(publicKey);
            this.key = new ECPublicKeyParameters("EC", q, DomainParameter);
        }

        public static string GenerateKeyIntPrivateKey()
        {
            BigInteger b = new BigInteger(256, new Random());
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(b.ToString());
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string GetPublicKeyFromPrivateKeyEx(string privateKey)

        {
            var curve = SecNamedCurves.GetByName("secp256k1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new Org.BouncyCastle.Math.BigInteger(privateKey);
            var q = domain.G.Multiply(d);
            var publicKey = new ECPublicKeyParameters(q, domain);
            return Convert.ToBase64String(publicKey.Q.GetEncoded());
        }

        public static string GetSignature(string privateKey, string messageBase64)
        {
            var curve = SecNamedCurves.GetByName("secp256k1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var keyParameters = new ECPrivateKeyParameters(new Org.BouncyCastle.Math.BigInteger(privateKey), domain);
            ECDsaSigner signer = new ECDsaSigner();
            signer.Init(true, keyParameters);
            BigInteger[] sig = signer.GenerateSignature(System.Convert.FromBase64String(messageBase64));

            ECDSASignature Signature = new ECDSASignature(sig[0], sig[1]);
            using (MemoryStream ms = new MemoryStream())
            using (Asn1OutputStream asn1stream = new Asn1OutputStream(ms))
            {
                DerSequenceGenerator seq = new DerSequenceGenerator(asn1stream);
                seq.AddObject(new DerInteger(sig[0]));
                seq.AddObject(new DerInteger(sig[1]));
                seq.Close();
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        public bool VerifySignature(byte[] hash, byte[] signature)
        {
            ECDsaSigner signer = new ECDsaSigner();
            ECDSASignature parsedSignature = ECDSASignature.FromDER(signature);
            signer.Init(false, key);
            return signer.VerifySignature(hash, parsedSignature.R, parsedSignature.S);
        }

        public class ECDSASignature
        {
            public Org.BouncyCastle.Math.BigInteger R { get; }

            public Org.BouncyCastle.Math.BigInteger S { get; }

            public ECDSASignature(Org.BouncyCastle.Math.BigInteger r, Org.BouncyCastle.Math.BigInteger s)
            {
                R = r;
                S = s;
            }

            public static ECDSASignature FromDER(byte[] signature)
            {
                try
                {
                    Asn1InputStream decoder = new Asn1InputStream(signature);
                    var seq = decoder.ReadObject() as DerSequence;
                    if (seq == null || seq.Count != 2)
                        throw new FormatException("Invalid DER signature");

                    return new ECDSASignature(((DerInteger)seq[0]).Value, ((DerInteger)seq[1]).Value);
                }
                catch (Exception ex)
                {
                    throw new FormatException("Invalid DER signature", ex);
                }
            }
        }
    }
}
using NTDLS.SecureKeyExchange;
using System;

namespace TestHarness
{
    internal class Program
    {
        static void TestUnitNegotiator()
        {
            var localHost = new UnitNegotiator();
            byte[] negotiationToken = localHost.GenerateNegotiationToken();

            var foreignHost = new UnitNegotiator();
            byte[] negotiationReply = foreignHost.ApplyNegotiationToken(negotiationToken);

            localHost.ApplyNegotiationResponseToken(negotiationReply);

            if (foreignHost.SharedSecretHash != localHost.SharedSecretHash)
            {
                throw new Exception("This should never happen.");
            }

            Console.WriteLine($"Key length: {localHost.KeyLength} bytes.");
            Console.WriteLine($"  Local Shared Secret: {localHost.SharedSecretHash}");
            Console.WriteLine($"Foreign Shared Secret: {foreignHost.SharedSecretHash}");
        }

        static void TestCompoundNegotiator()
        {
            var localHost = new CompoundNegotiator();
            byte[] negotiationToken = localHost.GenerateNegotiationToken(8);

            var foreignHost = new CompoundNegotiator();
            byte[] negotiationReply = foreignHost.ApplyNegotiationToken(negotiationToken);

            localHost.ApplyNegotiationResponseToken(negotiationReply);

            if (foreignHost.SharedSecretHash != localHost.SharedSecretHash)
            {
                throw new Exception("This should never happen.");
            }

            Console.WriteLine($"Key length: {localHost.KeyLength} bytes.");
            Console.WriteLine($"  Local Shared Secret: {localHost.SharedSecretHash}");
            Console.WriteLine($"Foreign Shared Secret: {foreignHost.SharedSecretHash}");
        }

        static void Main(string[] args)
        {
            TestUnitNegotiator();
            Console.WriteLine("");
            TestCompoundNegotiator();

            Console.ReadLine();
        }
    }
}

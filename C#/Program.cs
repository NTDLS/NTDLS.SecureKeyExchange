using System;

namespace SecureKeyExchange
{
    class Program
    {
        static void Test()
        {
            SecureKeyNegotiator localHost = new SecureKeyNegotiator();
            SecureKeyNegotiator foreignHost = new SecureKeyNegotiator();

            byte[] negotiationToken = localHost.GenerateNegotiationToken();

            byte[] negotiationReply = foreignHost.ApplyNegotiationToken(negotiationToken);

            localHost.ApplyNegotiationResponseToken(negotiationReply);

            if (foreignHost.SharedSecret != localHost.SharedSecret)
            {
                throw new Exception("This should never happen.");
            }

            Console.WriteLine("  Local Public:{0}", localHost.PublicNumber);
            Console.WriteLine("Foreign Public:{0}", foreignHost.PublicNumber);
            Console.WriteLine("L Share Secret:{0}", localHost.SharedSecret);
            Console.WriteLine("F Share Secret:{0}", foreignHost.SharedSecret);
        }

        static void Main(string[] args)
        {
            //for (int i = 0; i < 100000; i++)
            //{
                Test();
            //    Console.Write(i.ToString("N0") + "\r");
            //}

            //Console.WriteLine("Done!");

            Console.ReadLine();
        }
    }
}

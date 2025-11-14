# NTDLS.SecureKeyExchange

📦 Be sure to check out the NuGet package: https://www.nuget.org/packages/NTDLS.SecureKeyExchange

Easily generate a single or multi-round Diffie-Hellman keys in C#.

**Scenario (use your imagination):**
* localHost is a local service.
* remotePeer is a remote peer.

```csharp
//localHost starts the process with a call to GenerateNegotiationToken(),
//  specifying the size of the key (which is actually n*16).
var localHost = new CompoundNegotiator();
byte[] negotiationToken = localHost.GenerateNegotiationToken(8);

//localHost passes the resulting bytes from GenerateNegotiationToken()
//  to a remote peer which passes the bytes to ApplyNegotiationToken().
var remotePeer = new CompoundNegotiator();
byte[] negotiationReply = remotePeer.ApplyNegotiationToken(negotiationToken);

//The remotePeer passes the bytes from ApplyNegotiationToken() back to the 
//  localHost, where the localHost passes them to ApplyNegotiationResponseToken()
localHost.ApplyNegotiationResponseToken(negotiationReply);

//At this point, both the localHost and the remotePeer have the same bytes in
//  "SharedSecret" as we can see from comparing the "SharedSecretHash".
if (remotePeer.SharedSecretHash != localHost.SharedSecretHash)
{
    throw new Exception("This should never happen.");
}

Console.WriteLine($"Key length: {localHost.KeyLength} bytes.");
Console.WriteLine($" Local Shared Secret: {localHost.SharedSecretHash}");
Console.WriteLine($"Remote Shared Secret: {remotePeer.SharedSecretHash}");
```

## License
[[Apache-2.0](https://choosealicense.com/licenses/apache-2.0/)](https://choosealicense.com/licenses/mit/)


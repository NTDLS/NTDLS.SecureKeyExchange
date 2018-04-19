#pragma once
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_PRIMES 9592
#define MIN_PRIVATE 1
#define MAX_PRIVATE 4000000000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern int SKEPrimes[MAX_PRIMES];

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _tag_NegotiationToken {
	int PublicPrime;
	int PublicGenerator;
	int PublicNumber;
} NEGOTIATIONTOKEN, *LPNEGOTIATIONTOKEN;

typedef struct _tag_NegotiationReplyToken {
	int PublicNumber;
} NEGOTIATIONREPLYTOKEN, *LPNEGOTIATIONREPLYTOKEN;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CSecureKeyExchange
{
public:
	~CSecureKeyExchange();
	CSecureKeyExchange();
	CSecureKeyExchange(unsigned int iRandomSeed);
	CSecureKeyExchange(bool bUseInternalRNG);
	CSecureKeyExchange(unsigned int iRandomSeed, bool bUseInternalRNG);

public:
	void GenerateNegotiationToken(NEGOTIATIONTOKEN *pTok);
	void ApplyNegotiationToken(NEGOTIATIONTOKEN *pTok, NEGOTIATIONREPLYTOKEN *pReplyTok);
	void ApplyNegotiationResponseToken(NEGOTIATIONREPLYTOKEN *pTok);

	unsigned int PublicPrime();
	unsigned int PublicGenerator();
	unsigned int PrivateNumber();
	unsigned int PublicNumber();
	unsigned int SharedSecret();
	unsigned int ForeignPublicNumber();

private:
	bool bUseInternalRNG;

	unsigned int iPublicPrime;
	unsigned int iPublicGenerator;
	unsigned int iPrivateNumber;

	unsigned int iPublicNumber;
	unsigned int iSharedSecret;
	unsigned int iForeignPublicNumber;

	bool FlipCoin();
	unsigned int HardwareRandRange(unsigned int min, unsigned int max);
	unsigned int RandRange(unsigned int min, unsigned int max);
	unsigned int ModPow(unsigned __int64 base, unsigned __int64 exponent, unsigned int modulus);
	unsigned int GetRandomNumber(unsigned int min, unsigned int max);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

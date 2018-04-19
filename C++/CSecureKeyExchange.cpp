////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CSecureKeyExchange.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CSecureKeyExchange::CSecureKeyExchange(unsigned int iRandomSeed, bool bUseInternalRNG)
{
	srand(iRandomSeed);
	this->bUseInternalRNG = bUseInternalRNG;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CSecureKeyExchange::CSecureKeyExchange(bool bUseInternalRNG)
{
	srand(GetTickCount() + rand());
	this->bUseInternalRNG = bUseInternalRNG;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CSecureKeyExchange::CSecureKeyExchange(unsigned int iRandomSeed)
{
	srand(iRandomSeed);
	this->bUseInternalRNG = false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CSecureKeyExchange::CSecureKeyExchange()
{
	srand(GetTickCount() + rand());
	this->bUseInternalRNG = false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CSecureKeyExchange::~CSecureKeyExchange()
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CSecureKeyExchange::GenerateNegotiationToken(NEGOTIATIONTOKEN *pTok)
{
	iPublicPrime = SKEPrimes[GetRandomNumber(0, MAX_PRIMES - 1)];
	iPublicGenerator = GetRandomNumber(1, iPublicPrime);
	iPrivateNumber = GetRandomNumber(MIN_PRIVATE, MAX_PRIVATE);
	iPublicNumber = ModPow(iPublicGenerator, iPrivateNumber, iPublicPrime);

	memset(pTok, 0, sizeof(NEGOTIATIONTOKEN));
	pTok->PublicNumber = iPublicNumber;
	pTok->PublicGenerator = iPublicGenerator;
	pTok->PublicPrime = iPublicPrime;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CSecureKeyExchange::ApplyNegotiationToken(NEGOTIATIONTOKEN *pTok, NEGOTIATIONREPLYTOKEN *pReplyTok)
{
	this->iPublicPrime = pTok->PublicPrime;
	this->iPublicGenerator = pTok->PublicGenerator;
	this->iForeignPublicNumber = pTok->PublicNumber;

	this->iPrivateNumber = GetRandomNumber(MIN_PRIVATE, MAX_PRIVATE);
	this->iPublicNumber = ModPow(this->iPublicGenerator, this->iPrivateNumber, this->iPublicPrime);
	this->iSharedSecret = ModPow(this->iForeignPublicNumber, this->iPrivateNumber, this->iPublicPrime);

	pReplyTok->PublicNumber = this->iPublicNumber;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CSecureKeyExchange::ApplyNegotiationResponseToken(NEGOTIATIONREPLYTOKEN *pTok)
{
	this->iForeignPublicNumber = pTok->PublicNumber;
	this->iSharedSecret = ModPow(this->iForeignPublicNumber, this->iPrivateNumber, this->iPublicPrime);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::PublicPrime()
{
	return this->iPublicPrime;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::PublicGenerator()
{
	return this->iPublicGenerator;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::PrivateNumber()
{
	return this->iPrivateNumber;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::PublicNumber()
{
	return this->iPublicNumber;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::SharedSecret()
{
	return this->iSharedSecret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::ForeignPublicNumber()
{
	return this->iForeignPublicNumber;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::HardwareRandRange(unsigned int min, unsigned int max)
{
	unsigned int uiRandom = (unsigned int)__rdtsc();

	FILETIME ftIdle, ftKernel, ftUser;
	memset(&ftIdle, 0, sizeof(ftIdle));
	memset(&ftKernel, 0, sizeof(ftKernel));
	memset(&ftUser, 0, sizeof(ftUser));

	if (FlipCoin())
	{
		if (GetSystemTimes(&ftIdle, &ftKernel, &ftUser))
		{
			uiRandom += ftIdle.dwHighDateTime;
			uiRandom += ftIdle.dwLowDateTime;
			uiRandom += ftKernel.dwHighDateTime;
			uiRandom += ftKernel.dwLowDateTime;
			uiRandom += ftUser.dwHighDateTime;
			uiRandom += ftUser.dwLowDateTime;
		}
	}

	for (int iAttempts = 0; iAttempts < 1000; iAttempts++)
	{
		int iPID = RandRange(1, 100000);

		HANDLE hForeignProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, iPID);

		if (hForeignProcess != NULL)
		{
			DWORD dwExitCode = STILL_ACTIVE;

			if (FlipCoin())
			{
				if (!GetExitCodeProcess(hForeignProcess, &dwExitCode))
				{
					CloseHandle(hForeignProcess);
					continue;
				}
			}

			if (dwExitCode = STILL_ACTIVE)
			{
				if (FlipCoin())
				{
					FILETIME ftCreationTime, ftExitTime, ftKernelTime, ftUserTime;
					memset(&ftCreationTime, 0, sizeof(ftCreationTime));
					memset(&ftExitTime, 0, sizeof(ftExitTime));
					memset(&ftKernelTime, 0, sizeof(ftKernelTime));
					memset(&ftUserTime, 0, sizeof(ftUserTime));

					if (GetProcessTimes(hForeignProcess, &ftCreationTime, &ftExitTime, &ftKernelTime, &ftUserTime))
					{
						uiRandom += ftCreationTime.dwHighDateTime;
						uiRandom += ftCreationTime.dwLowDateTime;
						uiRandom += ftExitTime.dwHighDateTime;
						uiRandom += ftExitTime.dwLowDateTime;
						uiRandom += ftKernelTime.dwHighDateTime;
						uiRandom += ftKernelTime.dwLowDateTime;
						uiRandom += ftUserTime.dwHighDateTime;
						uiRandom += ftUserTime.dwLowDateTime;
					}
				}

				if (FlipCoin())
				{
					IO_COUNTERS pIOCounters;
					memset(&pIOCounters, 0, sizeof(pIOCounters));
					if (GetProcessIoCounters(hForeignProcess, &pIOCounters))
					{
						uiRandom += (unsigned int)pIOCounters.OtherOperationCount;
						uiRandom += (unsigned int)pIOCounters.OtherTransferCount;
						uiRandom += (unsigned int)pIOCounters.ReadOperationCount;
						uiRandom += (unsigned int)pIOCounters.ReadTransferCount;
						uiRandom += (unsigned int)pIOCounters.WriteOperationCount;
						uiRandom += (unsigned int)pIOCounters.WriteTransferCount;
					}
				}

				if (FlipCoin())
				{
					uiRandom += GetGuiResources(hForeignProcess, GR_GDIOBJECTS);
					uiRandom += GetGuiResources(hForeignProcess, GR_GDIOBJECTS_PEAK);
					uiRandom += GetGuiResources(hForeignProcess, GR_USEROBJECTS);
					uiRandom += GetGuiResources(hForeignProcess, GR_USEROBJECTS_PEAK);
				}

				CloseHandle(hForeignProcess);
				break;
			}
		}

		CloseHandle(hForeignProcess);
	}

	return (unsigned int)(min + (uiRandom % ((max - min) + 1)));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool CSecureKeyExchange::FlipCoin()
{
	return (RandRange(0, 100) >= 50);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::RandRange(unsigned int min, unsigned int max)
{
	return (unsigned int)(min + (rand()) % ((max - min) + 1));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::GetRandomNumber(unsigned int min, unsigned int max)
{
	if (bUseInternalRNG)
	{
		return HardwareRandRange(min, max);
	}
	else
	{
		return RandRange(min, max);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int CSecureKeyExchange::ModPow(unsigned __int64 base, unsigned __int64 exponent, unsigned int modulus)
{
	__int64 result = 1;
	while (exponent > 0)
	{
		if (exponent % 2 == 1)
		{
			result = (result * base) % modulus;
		}
		exponent = exponent >> 1;
		base = (base * base) % modulus;
	}
	return (unsigned int)result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../CSecureKeyExchange.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void main()
{
	int iKeySz = 0;
	char *sKey = (char *)calloc(10000, 1);
	unsigned int max = 0;
	int iWPos = 0;

	unsigned int iPreviousKey = 0;

	CSecureKeyExchange *local = new CSecureKeyExchange(GetTickCount(), false);
	CSecureKeyExchange *remote = new CSecureKeyExchange(GetTickCount(), false);

	for (unsigned int iAttempts = 0; iAttempts < 1000000; iAttempts++)
	{
		NEGOTIATIONTOKEN negotiationToken;
		NEGOTIATIONREPLYTOKEN negotiationReplyToken;

		local->GenerateNegotiationToken(&negotiationToken);

		remote->ApplyNegotiationToken(&negotiationToken, &negotiationReplyToken);

		local->ApplyNegotiationResponseToken(&negotiationReplyToken);

		if (remote->SharedSecret() != local->SharedSecret())
		{
			printf("Public Prime %u\n", local->PublicPrime());
			printf("Public Generator %u\n", local->PublicGenerator());
			printf("Public Number %u\n", local->PublicNumber());
			printf("Private Number %u\n", local->PrivateNumber());
			printf("Shared Secret >>%u<<\n", local->SharedSecret());
			printf("\n");

			printf("Public Prime %u\n", remote->PublicPrime());
			printf("Public Generator %u\n", remote->PublicGenerator());
			printf("Public Number %u\n", remote->PublicNumber());
			printf("Private Number %u\n", remote->PrivateNumber());
			printf("Shared Secret >>%u<<\n", remote->SharedSecret());
			
			system("pause");
		}

		printf("Itt: %d Shared Secret %u == %u\n", iAttempts, local->SharedSecret(), remote->SharedSecret());
	}

	delete local;
	delete remote;

	printf("\nComplete.\n");
	system("pause");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

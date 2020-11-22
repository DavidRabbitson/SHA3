#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const uint32_t RC[24] = {	0x00000001, 0x00008082, 0x0000808a,
							0x80008000, 0x0000808b, 0x80000001,
							0x80008081, 0x00008009, 0x0000008a,
							0x00000088, 0x80008009, 0x8000000a,
							0x8000808b, 0x0000008b, 0x00008089,
							0x00008003, 0x00008002, 0x00000080,
							0x0000800a, 0x8000000a, 0x80008081,
							0x00008080, 0x80000001, 0x80008008};


const uint32_t r[5][5] = {  {0,	  36,  3,   105, 210},
							{1,   300, 10,  45,  66 },
							{190, 6,   171, 15,  253},
							{28,  55,  153, 21,  120},
							{91,  276, 231, 136, 78 }  };


uint32_t ROTL32(uint32_t x, uint8_t y)
{
	return (((x) << (y)) | ((x) >> ((sizeof(uint32_t)*8) - (y))));
}

void keccak_round(uint32_t A[5][5], uint32_t RC)
{
	int i = 0;
	int j = 0;

	uint32_t B[5][5];
	uint32_t C[5];
	uint32_t D[5];
	
	for(i = 0; i < 5; i++)
		C[i] = A[i][0] ^ A[i][1] ^ A[i][2] ^ A[i][3] ^ A[i][4];
	
	for(i = 0; i < 5; i++)
		D[i] = C[(i - 1) % 5] ^ ROTL32(C[(i + 1) % 5], 1);

	for(i = 0; i < 5; i++)
		for(j = 0; j < 5; j++)
			A[i][j] = A[i][j] ^ D[i];

	for(i = 0; i < 5; i++)
		for(j = 0; j < 5; j++)
			B[j][(2*i + 3*j) % 5] = ROTL32(A[i][j], r[i][j]);

	for(i = 0; i < 5; i++)
		for(j = 0; j < 5; j++)
			A[i][j] = B[i][j] ^ ((B[(i + 1) % 5][j] ^ 1) & B[(i + 2) % 5][j]);

	A[0][0] = A[0][0] ^ RC;
}

void keccak_f800(uint32_t A[5][5])
{
	int i = 0;
	for(i = 0; i < 22; i++)
		keccak_round(A, RC[i]);
}

int number_of_bytes_to_pad(int rate, int msg_size_in_bytes)
{
	return (rate / 8) - (msg_size_in_bytes % (rate / 8));
}

void update_state(uint32_t state[5][5], char *P, int rate, int offset)
{
	int i = 0;
	int j = 0;
	int k = 0;
	int l = 0;

	for(i = 0; i < 5; i++)
		for(j = 0; j < 5; j++)
			for(k = 3; k >= 0; k--)
				if(l < rate)
				{
					state[j][i] = state[j][i] ^ (P[l + offset] << (8*k));
					l++;
				}
}

void SHA3(char* M, int d, uint32_t buffer[d / 32])
{
	int i = 0;
	int j = 0;

	int capacity = 2 * d;
	int rate = 800 - capacity;

	int len = strlen(M);
	int pad = number_of_bytes_to_pad(rate, len);

	char P[len + pad];

	for(i = 0; i < len; i++)
		P[i] = M[i];

	P[len] = (char)(0x60);

	for(i = len + 1; i < len + pad; i++)
		P[i] = (char)(0x00);

	P[len + pad - 1] = 0x01;

	int rate_bytes = rate / 8;
	int n = (len + pad) / rate_bytes;

	uint32_t S[5][5] = {{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0}};

	for(i = 0; i < n; i++)
	{
		update_state(S, P, rate_bytes, i * rate_bytes);
		keccak_f800(S);
	}

	buffer[0] = S[0][0];
	buffer[1] = S[1][0];
	buffer[2] = S[2][0];
	buffer[3] = S[3][0];
	buffer[4] = S[4][0];
	buffer[5] = S[0][1];
	buffer[6] = S[1][1];
	buffer[7] = S[2][1];
}

int main(int argc, char *argv[])
{
	char msg[100] = "";
	if(argv[1])
		strcpy(msg, argv[1]);

	uint32_t buffer[8];
	SHA3(msg, 256, buffer);

	int i = 0;
	for(i = 0; i < 8; i++)
		printf("%08x\n", buffer[i]);

	return 0;
}

/*This code below was used to generate RC matrix

uint16_t rc(int t)
{
	int tmp = t % 255;
	if(tmp == 0)
		return 1;
	
	uint16_t rc = 0x80;

	int i = 0;
	for(i = 1; i <= tmp; i++)
	{
		rc = ((rc & 1) << 8) ^ rc;
		rc = ((rc & 1) << 4) ^ rc;
		rc = ((rc & 1) << 3) ^ rc;
		rc = ((rc & 1) << 2) ^ rc;
		rc  = rc >> 1;
	}

	printf("rc = 0x%x\n", rc);
	return (rc >> 7);
}

uint32_t create_rc(int round)
{
	uint32_t RC = 0;

	int power = 1;
	int i = 0;
	for(i = 0; i < 6; i++)
	{
		RC += (rc(i + 7 * round)) << (power - 1);
		power = power * 2;
	}

	return RC;
}
*/


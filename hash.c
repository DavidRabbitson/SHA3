#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//Performs cyclic left shift of x for y bits
uint32_t ROTL32(uint32_t x, uint8_t y)
{
	return (((x) << (y)) | ((x) >> ((sizeof(uint32_t)*8) - (y))));
}

/* Function keccak_round()
****														 ****
* @brief: Performs one round of keccak800 (described in NIST).	*
*		  State matrix A[5][5] changes after each round.		*
****														 ****
* @params: A[5][5] - State matrix. Each element is 32 bit long.	*
*																*
* @params: RC - Round constant. Number of round is provided by	*
*				keccak_f800() function below.					*
****														 ****/
void keccak_round(uint32_t A[5][5], uint32_t RC)
{
	int i = 0;
	int j = 0;

	uint32_t B[5][5];
	uint32_t C[5];
	uint32_t D[5];

	//Array of constants for roh step of keccak
	const uint32_t r[5][5] = {  {0,	  36,  3,   105, 210},
								{1,   300, 10,  45,  66 },
								{190, 6,   171, 15,  253},
								{28,  55,  153, 21,  120},
								{91,  276, 231, 136, 78 }  };

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

/* Function keccak_f800()
****														 ****
* @brief: Performs 22 rounds of keccak800. 22 rounds comes from	*
*		  formula 12 + 2*l, where 2^l = 32.						*
****														 ****
* @params: A[5][5] - State matrix. A changes its state after	*
*					 this function.								*
****														 ****/
void keccak_f800(uint32_t A[5][5])
{
	//Array of round constants for final step of keccak
	const uint32_t RC[22] = {	0x00000001, 0x00008082, 0x0000808a,
								0x80008000, 0x0000808b, 0x80000001,
								0x80008081, 0x00008009, 0x0000008a,
								0x00000088, 0x80008009, 0x8000000a,
								0x8000808b, 0x0000008b, 0x00008089,
								0x00008003, 0x00008002, 0x00000080,
								0x0000800a, 0x8000000a, 0x80008081,
								0x00008080};

	int i = 0;
	for(i = 0; i < 22; i++)
		keccak_round(A, RC[i]);
}

/* Function number_of_bytes_to_pad()
****														 ****
* @brief: Calculates number of bytes needed to pad input message*
*		  of SHA3() function.*
****														 ****
* @params: rate - Rate in bytes (rate described in NIST).		*
*																*
* @params: msg_size_in_bytes - Size of initial message in bytes.*
****														 ****
* @return: Number of bytes to pad initial message.				*
****														 ****/
int number_of_bytes_to_pad(int rate, int msg_size_in_bytes)
{
	return rate - (msg_size_in_bytes % rate);
}

/* Function update_state()
****														 ****
* @brief: Auxiliary function that sums state with padded message*
****														 ****
* @params: A[5][5] - State matrix. A[5][5] is changed after this*
*					 function.									*
*																*
* @params: P - Padded message.									*
*																*
* @params: rate - Rate in bytes.								*
*																*
* @params: offset - Sets the offset to reads padded message.	*
****														 ****/
void update_state(uint32_t A[5][5], char *P, int rate, int offset)
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
					A[j][i] = A[j][i] ^ (P[l + offset] << (8*k));
					l++;
				}
}

/* Function SHA3()
****														 ****
* @brief: Generates d-bit hash based on input message M. Stores	*
*		  result in buffer[d / 32].								*
****														 ****
* @params: M - Input message. Calculation of hash is based on it*
*																*
* @params: d - Size of generated hash. Could be set to 224, 256,*
*			   384.												*
*																*
* @params: buffer - Buffer to store generated hash.				*
****														 ****/
void SHA3(char* M, int d, uint32_t buffer[d / 32])
{
	if(d % 32 != 0)
		return;

	int i = 0;
	int j = 0;

	int capacity = 2 * d;
	int rate = (800 - capacity) / 8;

	int len = strlen(M);
	int pad = number_of_bytes_to_pad(rate, len);

	char P[len + pad];

	for(i = 0; i < len; i++)
		P[i] = M[i];

	P[len] = (char)(0x60);

	for(i = len + 1; i < len + pad; i++)
		P[i] = (char)(0x00);

	P[len + pad - 1] = 0x01;

	int n = (len + pad) / rate;

	uint32_t S[5][5] = {{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0},
						{0, 0, 0, 0, 0}};

	for(i = 0; i < n; i++)
	{
		update_state(S, P, rate, i * rate);
		keccak_f800(S);
	}

	for(i = 0; i < d / 32; i++)
	{
		if((i % rate == 0) && i)
			keccak_f800(S);

		buffer[i] = S[i % 5][i / 5];
	}
}

int main(int argc, char *argv[])
{
	char msg[100] = "You didn't enter message so here's my hash";
	if(argv[1])
		strcpy(msg, argv[1]);

	int hash_length = 256;

	uint32_t buffer[hash_length / 32];
	SHA3(msg, hash_length, buffer);

	printf("SHA3-%d for \"%s\":\n", hash_length, msg);

	int i = 0;
	for(i = 0; i < hash_length / 32; i++)
		printf("%08x\n", buffer[i]);

	return 0;
}


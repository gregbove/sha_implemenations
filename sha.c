#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h> 

/* ==================================================================
 * GLOBAL CONSTANTS
 * ================================================================== */ 

const unsigned int INT_BITS = 32;
const unsigned int BITS_PER_BYTE = 8;
const unsigned int BYTES_PER_BLOCK = 512 / BITS_PER_BYTE;

/* ==================================================================
 * UTILITY FUNCTIONS
 * ================================================================== */

/**
 * Right rotates a number by a specified number of bits.
 * @param original		the number to rotate
 * @param bits			number of bits to rotate (0 < bits < 32)
 * @return right-rotated number
 */
uint32_t rotr(uint32_t original, uint8_t bits) {
	return (original >> bits) | (original << (INT_BITS - bits));
}

/**
 * Adds two unsigned integers modulo 2^32 without overflow/undefined behavior.
 * @param first		first integer to add
 * @param second	second integer to add
 * @return sum modulo 2^32
 */
uint32_t add_mod_2_32(uint32_t first, uint32_t second) {
	uint32_t max_first_no_overflow = UINT32_MAX - second;
	if (first > max_first_no_overflow) {
		return first - max_first_no_overflow - 1;
	}

	return first + second;
}

/**
 * Adds three unsigned integers modulo 2^32 without overflow/undefined
 * behavior.
 * @param first		first integer to add
 * @param second	second integer to add
 * @param third		third integer to add
 * @return sum modulo 2^32
 */
uint32_t add_three_mod_2_32(uint32_t first, uint32_t second, uint32_t third) {
	return add_mod_2_32(add_mod_2_32(first, second), third);
}

/**
 * Adds four unsigned integers modulo 2^32 without overflow/undefined behavior.
 * @param first		first integer to add
 * @param second	second integer to add
 * @param third		third integer to add
 * @param fourth	fourth integer to add
 * @return sum modulo 2^32
 */
uint32_t add_four_mod_2_32(uint32_t first, uint32_t second, uint32_t third,
		uint32_t fourth) {
	return add_mod_2_32(add_mod_2_32(first, second),
			add_mod_2_32(third, fourth));
}

/**
 * Calculates the length of a null-terminated string
 * @param str	string to calculate length of
 * @return length of the string
 */
uint64_t strlength(const char *str) {
	uint64_t length = 0;
	while (str[length] != 0) {
		length++;
	}
	return length;
}

/**
 * Copies a 64-bit integer into a buffer in big-endian format.
 * @param dest		buffer to copy number into
 * @param num		number to copy
 */
void copy_big_endian(char *dest, uint64_t num) {
	for (int offset = 0; offset < 8; offset++) {
#pragma HLS unroll
		dest[offset] = (num >> ((7 - offset) * BITS_PER_BYTE)) & 0xff;
	}
}

/* ==================================================================
 * PREPROCESSING
 * ================================================================== */

// Holds results of the preprocessing step
typedef struct preprocessed_msg_t {

	/* We need an overflow buffer since we can't create a dynamically-allocated
	 * buffer for the full message + padding. We need two blocks since the
	 * remainder of the message + 64 bits for the message length may be larger
	 * than 512 bits. */
	char overflow[BYTES_PER_BLOCK * 2];

	uint64_t regular_blocks; // Number of full 512-bit blocks in original message
	uint64_t overflow_blocks; // Number of overflow blocks (1 or 2)
} preprocessed_msg_t;

/**
 * Performs the preprocessing step in the SHA-224/256 algorithms.
 * @param message		message to process
 * @param msg_bytes		length of the message
 * @param out			pointer to preprocessing output. The overflow
 * 						buffer in the output is assumed to already be
 * 						initialized to all 0's.
 */
void preprocess(const char *message, const uint64_t msg_bytes,
		preprocessed_msg_t *out) {

	// Copy bytes that do not fit evenly into 512-bit block into the overflow
	uint64_t msg_bytes_in_overflow = msg_bytes % BYTES_PER_BLOCK;
	uint64_t msg_bytes_in_reg_blocks = msg_bytes - msg_bytes_in_overflow;
	memcpy(out->overflow, message + msg_bytes_in_reg_blocks,
			msg_bytes_in_overflow);

	/* Add the padding byte immediately after the end of the string in the
	 * overflow buffer. Since the message and length at the end fit evenly
	 * into bytes, we can simply assign a whole byte to add the '1' bit
	 * required by SHA. */
	out->overflow[msg_bytes_in_overflow] = '\x80'; // 0b10000000

	/* Determine if the 64-bit length fits in the first overflow block or if
	 * the second overflow block is needed. Copy the length at the end of the
	 * last overflow block in big endian format. */
	uint64_t msg_bits = msg_bytes * BITS_PER_BYTE;
	const unsigned int LENGTH_BYTES = 64 / BITS_PER_BYTE;

	if (BYTES_PER_BLOCK - (msg_bytes_in_overflow + 1) >= LENGTH_BYTES) {
		copy_big_endian(out->overflow + BYTES_PER_BLOCK - LENGTH_BYTES,
				msg_bits);
		out->overflow_blocks = 1;
	} else {
		copy_big_endian(out->overflow + BYTES_PER_BLOCK * 2 - LENGTH_BYTES,
				msg_bits);
		out->overflow_blocks = 2;
	}

	// Determine how many full 512-bit blocks are in the original message
	out->regular_blocks = msg_bytes_in_reg_blocks / BYTES_PER_BLOCK;

}

/* ==================================================================
 * INITIALIZE HASH VALUES
 * ================================================================== */

/**
 * Assigns the initial hash values of SHA-256 or SHA-224 to the hash variables.
 * @param sha_256	bool to tell whether or not SHA-256 is being used -
 * 					if false, we assume SHA-224 will be used
 * @param h0		pointer to first digest variable
 * @param h1		pointer to second digest variable
 * @param h2		pointer to third digest variable
 * @param h3		pointer to fourth digest variable
 * @param h4		pointer to fifth digest variable
 * @param h5		pointer to sixth digest variable
 * @param h6		pointer to seventh digest variable
 * @param h7		pointer to eighth digest variable
 */
void sha_choice(bool sha_256, uint32_t* h0, uint32_t* h1, uint32_t* h2,
		uint32_t* h3, uint32_t* h4, uint32_t* h5, uint32_t* h6, uint32_t* h7) {
	if (sha_256) {
		*h0 = 0x6a09e667;
		*h1 = 0xbb67ae85;
		*h2 = 0x3c6ef372;
		*h3 = 0xa54ff53a;
		*h4 = 0x510e527f;
		*h5 = 0x9b05688c;
		*h6 = 0x1f83d9ab;
		*h7 = 0x5be0cd19;
	} else {
		*h0 = 0xc1059ed8;
		*h1 = 0x367cd507;
		*h2 = 0x3070dd17;
		*h3 = 0xf70e5939;
		*h4 = 0xffc00b31;
		*h5 = 0x68581511;
		*h6 = 0x64f98fa7;
		*h7 = 0xbefa4fa4;
	}
}

/* ==================================================================
 * ROUND CONSTANTS
 * ================================================================== */

const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
		0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
		0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
		0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

/* ==================================================================
 * CREATE MESSAGE SCHEDULE
 * ================================================================== */

/**
 * Creates a message schedule of 32-bit words given a 512-bit input.
 * @param input			input array of at least 512 bits (64 bytes)
 * @param w				output array that can fit 64 32-bit words
 */
void create_message_schedule(const char *input, uint32_t *w) {

	// Copy message data to the schedule array
	for (int y = 0; y < 16; y++) {
		int base = y * 4;
		w[y] = ((input[base] & 0xff) << 24) | ((input[base + 1] & 0xff) << 16)
				| ((input[base + 2] & 0xff) << 8) | (input[base + 3] & 0xff);
	}

	// Actual SHA2 message schedule algorithm
	uint32_t s0;
	uint32_t s1;
	for (int i = 16; i < 64; i++) {
		s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
		s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = add_four_mod_2_32(w[i - 16], s0, w[i - 7], s1);
	}

}

/* ==================================================================
 * COMPRESSION
 * ================================================================== */

/**
 * Updates the eight working variables based on the current
 * block of data (within the message schedule).
 * @param h0			pointer to first digest variable
 * @param h1			pointer to second digest variable
 * @param h2			pointer to third digest variable
 * @param h3			pointer to fourth digest variable
 * @param h4			pointer to fifth digest variable
 * @param h5			pointer to sixth digest variable
 * @param h6			pointer to seventh digest variable
 * @param h7			pointer to eighth digest variable
 * @param w				message schedule array
 * @param k				round constants
 * @param shift_buffer	buffer of size 6 that will hold At-3, Et-3, At-2,
 * 						Et-2, At-1, Et-1 after the function completes
 */
void compress(uint32_t* h0, const uint32_t* h1, const uint32_t* h2,
		const uint32_t* h3, uint32_t* h4, const uint32_t* h5,
		const uint32_t* h6, const uint32_t* h7, const uint32_t *w,
		const uint32_t *k, uint32_t *shift_buffer) {

	// Initialize hash values
	uint32_t a = *h0;
	uint32_t b = *h1;
	uint32_t c = *h2;
	uint32_t d = *h3;
	uint32_t e = *h4;
	uint32_t f = *h5;
	uint32_t g = *h6;
	uint32_t h = *h7;

	// Calculate delta for the first iteration
	uint32_t delta = add_three_mod_2_32(h, k[0], w[0]);

	int buffer_index = 4;

	// Perform 64 rounds of compression
	for (int t = 0; t < 64; t++) {
		uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
		uint32_t ch = (e & f) ^ (~(e) & g);
		uint32_t temp1 = add_three_mod_2_32(s1, ch, delta);

		uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = add_mod_2_32(s0, maj);

		// Precalculate delta for the next round as described in paper two
		if (t < 63) delta = add_three_mod_2_32(g, k[t + 1], w[t + 1]);

		h = g;
		g = f;
		f = e;
		e = add_mod_2_32(d, temp1);
		d = c;
		c = b;
		b = a;
		a = add_mod_2_32(temp1, temp2);

		shift_buffer[buffer_index] = b;
		shift_buffer[buffer_index + 1] = f;
		buffer_index = (buffer_index + 2) % 6;
	}

	*h0 = add_mod_2_32(a, *h0);
	*h4 = add_mod_2_32(e, *h4);

}

/* ==================================================================
 * MODIFY FINAL VALUES
 * ================================================================== */

/**
 * Compute the final values of the 1st-3rd and 5th-8th pieces of the
 * digest message.
 * @param h1			pointer to second digest variable
 * @param h2			pointer to third digest variable
 * @param h3			pointer to fourth digest variable
 * @param h5			pointer to sixth digest variable
 * @param h6			pointer to seventh digest variable
 * @param h7			pointer to eighth digest variable
 * @param shift_buffer	buffer of size 6 that holds At-3, Et-3, At-2,
 * 						Et-2, At-1, Et-1 in that order
 */
void modify_final_vals(uint32_t* h1, uint32_t* h2, uint32_t* h3, uint32_t* h5,
		uint32_t* h6, uint32_t* h7, const uint32_t *shift_buffer) {
	uint32_t first_digests[3] = {*h1, *h2, *h3};
	uint32_t second_digests[3] = {*h5, *h6, *h7};

	for (int j = 0; j < 3; j++) {
		int base_index = 4 - j * 2;
		first_digests[j] += shift_buffer[base_index];
		second_digests[j] += shift_buffer[base_index + 1];
	}

	*h1 = first_digests[0];
	*h2 = first_digests[1];
	*h3 = first_digests[2];
	*h5 = second_digests[0];
	*h6 = second_digests[1];
	*h7 = second_digests[2];
}

/* ==================================================================
 * CONCATENATION
 * ================================================================== */

/**
 * Copies an integer to the start of a character array.
 * @param n			the integer to copy
 * @param dest		destination array (must be at least size 4)
 */
void copy_int_to_char_arr(const uint32_t n, char* dest) {
	dest[0] = (n >> 24) & 0xff;
	dest[1] = (n >> 16) & 0xff;
	dest[2] = (n >> 8) & 0xff;
	dest[3] = n & 0xff;
}

/**
 * Concatenates digests into a character array of data.
 * @param h0			first digest variable
 * @param h1			second digest variable
 * @param h2			third digest variable
 * @param h3			fourth digest variable
 * @param h4			fifth digest variable
 * @param h5			sixth digest variable
 * @param h6			seventh digest variable
 * @param h7			eighth digest variable
 * @param output		output buffer at least 256 or
 * 						224 bits in size depending on the
 * 						SHA algorithm
 */
void concat_digests(const uint32_t h0, const uint32_t h1, const uint32_t h2,
		const uint32_t h3, const uint32_t h4, const uint32_t h5,
		const uint32_t h6, const uint32_t h7, bool sha_256, char *output) {
	const unsigned int INT_BYTES = INT_BITS / BITS_PER_BYTE;

	// We always need the first six digests
	copy_int_to_char_arr(h0, output + (INT_BYTES * 0));
	copy_int_to_char_arr(h1, output + (INT_BYTES * 1));
	copy_int_to_char_arr(h2, output + (INT_BYTES * 2));
	copy_int_to_char_arr(h3, output + (INT_BYTES * 3));
	copy_int_to_char_arr(h4, output + (INT_BYTES * 4));
	copy_int_to_char_arr(h5, output + (INT_BYTES * 5));
	copy_int_to_char_arr(h6, output + (INT_BYTES * 6));

	// Copy the last digest if using SHA-256
	if (sha_256) {
		copy_int_to_char_arr(h7, output + (INT_BYTES * 7));
	}

}

/* ==================================================================
 * TOP-LEVEL FUNCTION
 * ================================================================== */

/**
 * Hashes a message with either SHA-256 or SHA-224.
 * @param message		message to hash
 * @param msg_length	length of the message in bytes
 * @param sha_256		true if SHA-256 should be used, false for SHA-224
 * @param hash_out		array that will contain the bytes of the hash. Must
 * 						have at least 32 bytes for SHA-256 or 28 bytes for
 * 						SHA-224.
 */
void hash_sha(char *message, const uint64_t msg_length, bool sha_256,
		char *hash_out) {
	preprocessed_msg_t preproc = { .overflow = { 0 } };
	preprocess(message, msg_length, &preproc);

	// Initialize hash values, depending on sha_choice
	uint32_t h0, h1, h2, h3, h4, h5, h6, h7;
	sha_choice(sha_256, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7);

	uint64_t reg_blocks = preproc.regular_blocks;
	uint64_t overflow_blocks = preproc.overflow_blocks;
	uint64_t total_blocks = reg_blocks + overflow_blocks;

	// shift buffer of size 6
	uint32_t shift_buffer_final[6];

	// Big loop of total blocks
	for (uint64_t block_index = 0; block_index < total_blocks; block_index++) {
		char *block;

		// Determine where the block is (in original message or overflow buf)
		if (block_index >= reg_blocks) {
			block = preproc.overflow
					+ (block_index - reg_blocks) * BYTES_PER_BLOCK;
		} else {
			block = message + block_index * BYTES_PER_BLOCK;
		}

		// Create message schedule
		uint32_t w[64];
		create_message_schedule(block, w);

		// Compress (loop of 64 rounds is within the compress() function)
		compress(&h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7,
				w, k, shift_buffer_final);

#pragma HLS pipeline II=131
		// Modify final values
		modify_final_vals(&h1, &h2, &h3, &h5, &h6, &h7, shift_buffer_final);

	}

	// Creating output string for final hash
	concat_digests(h0, h1, h2, h3, h4, h5, h6, h7, sha_256, hash_out);

}

/**
 * Hashes a specific message with either SHA-256 or SHA-224. The message is
 * fixed to test the performance of this function with synthesis, as the
 * regular function without a fixed message takes a variable number of cycles
 * based on the message length.
 * @param sha_256		true if SHA-256 should be used, false for SHA-224
 * @param hash_out		array that will contain the bytes of the hash. Must
 * 						have at least 32 bytes for SHA-256 or 28 bytes for
 * 						SHA-224.
 */
void hash_sha_fixed_msg(bool sha_256, char *hash_out) {
	// 64 bytes
	/*char* msg = "kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrx"
			"nadgbkan";*/

	// 511 bytes
	/*char* msg =
			"86GvnEzUEuIi0flmVu1mrOxFhHWYY5nFGZiBHwoWwp2rOBHHKtF59taXbeyj1nb1em"
			"8HUxC2pfvLsvvdGwjMQu15AJUuYQfQD5Uc92XN2SzDJAfe9o8Uu0IyuIURycbX5wQE"
			"ExosGohMxJUOtzHFHgoD865FQOMqJQnsNC9COMdTDURN9KpwBesL9oqfJi3B03ZHhV"
			"uF56kN2Xi3N2Q3BXhTQ88icB8fN6mO0YbHuVG0yIh9fBIUcoUGDwA1aCtuW2InNNZs"
			"xfEMPqLfuBxEtedaoP9QvEwwCDbi2sGtCx0dQq5EHqlQyYYbY3X5GvxL9HoykwCQpb"
			"6EZ3SCwWMpA2nDs0YSQqiCCjK2fIXgFC6QfO4mAQVQ0RFio0aP5WAmWSuoInBewz36"
			"9ZkA4B2r3GuR963GKLDHack4FXpmfq14WpewNfDrh1vo1KuyE9Hm9AxouI455Vnww6"
			"JUKiVu4REKfwGHPDgrAJDyeER1FF9r2wPTatkDLMI4okra5pc";*/

	// 1022 bytes
	char* msg =
				"86GvnEzUEuIi0flmVu1mrOxFhHWYY5nFGZiBHwoWwp2rOBHHKtF59taXbeyj1nb1em"
				"8HUxC2pfvLsvvdGwjMQu15AJUuYQfQD5Uc92XN2SzDJAfe9o8Uu0IyuIURycbX5wQE"
				"ExosGohMxJUOtzHFHgoD865FQOMqJQnsNC9COMdTDURN9KpwBesL9oqfJi3B03ZHhV"
				"uF56kN2Xi3N2Q3BXhTQ88icB8fN6mO0YbHuVG0yIh9fBIUcoUGDwA1aCtuW2InNNZs"
				"xfEMPqLfuBxEtedaoP9QvEwwCDbi2sGtCx0dQq5EHqlQyYYbY3X5GvxL9HoykwCQpb"
				"6EZ3SCwWMpA2nDs0YSQqiCCjK2fIXgFC6QfO4mAQVQ0RFio0aP5WAmWSuoInBewz36"
				"9ZkA4B2r3GuR963GKLDHack4FXpmfq14WpewNfDrh1vo1KuyE9Hm9AxouI455Vnww6"
				"JUKiVu4REKfwGHPDgrAJDyeER1FF9r2wPTatkDLMI4okra5pc"
				"86GvnEzUEuIi0flmVu1mrOxFhHWYY5nFGZiBHwoWwp2rOBHHKtF59taXbeyj1nb1em"
				"8HUxC2pfvLsvvdGwjMQu15AJUuYQfQD5Uc92XN2SzDJAfe9o8Uu0IyuIURycbX5wQE"
				"ExosGohMxJUOtzHFHgoD865FQOMqJQnsNC9COMdTDURN9KpwBesL9oqfJi3B03ZHhV"
				"uF56kN2Xi3N2Q3BXhTQ88icB8fN6mO0YbHuVG0yIh9fBIUcoUGDwA1aCtuW2InNNZs"
				"xfEMPqLfuBxEtedaoP9QvEwwCDbi2sGtCx0dQq5EHqlQyYYbY3X5GvxL9HoykwCQpb"
				"6EZ3SCwWMpA2nDs0YSQqiCCjK2fIXgFC6QfO4mAQVQ0RFio0aP5WAmWSuoInBewz36"
				"9ZkA4B2r3GuR963GKLDHack4FXpmfq14WpewNfDrh1vo1KuyE9Hm9AxouI455Vnww6"
				"JUKiVu4REKfwGHPDgrAJDyeER1FF9r2wPTatkDLMI4okra5pc";

	hash_sha(msg, strlength(msg), sha_256, hash_out);
}

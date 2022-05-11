#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

uint64_t strlength(const char *str);

void hash_sha(char *message, const uint64_t msg_length, bool sha_256,
		char *hash_out);

void print_char_in_hex_224(char *str) {
	for (int i = 0; i < 28; i++) { //up to the 64th index in w
		printf("%02x", str[i] & 0xff);
	}
}

void print_char_in_hex_256(char *str) {
	for (int i = 0; i < 32; i++) { //up to the 64th index in w
		printf("%02x", str[i] & 0xff);
	}
}

void test_full_hash(char *msg, bool sha_256, const char *expected) {
	char results224[28];
	char results256[32];

	if (sha_256) {
		printf("Message Before HASH_SHA: ");
		printf("%s\n", msg);

		printf("HASH_SHA Actual Result:   ");
		hash_sha(msg, strlength(msg), sha_256, results256);
		print_char_in_hex_256(results256);
		printf("\n");

		printf("HASH_SHA Expected Result: ");
		printf("%s\n", expected);
	} else {
		printf("Message Before HASH_SHA: ");
		printf("%s\n", msg);

		printf("HASH_SHA Actual Result:   ");
		hash_sha(msg, strlength(msg), sha_256, results224);
		print_char_in_hex_224(results224);
		printf("\n");

		printf("HASH_SHA Expected Result: ");
		printf("%s\n", expected);
	}

	printf("\n");

}

int main_final_hash() {
	//expected found on hash calculator on https://www.pelock.com/products/hash-calculator

	printf(
			"\n"
			"===============================================================\n"
			"SHA-224\n"
			"===============================================================\n");
	bool SHA_256 = false;
	char *expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
	test_full_hash("abc", SHA_256, expected);

	expected = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";
	test_full_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			SHA_256, expected);

	expected = "84def85d77488325a9e99d425d4e6b1d2abdc2e5764768d3604e84de";
	test_full_hash(
			"kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan",
			SHA_256, expected);

	expected =
			"4a7d3c1824eb87a00b3180a9f00311ade0b8828ca68cce2d2ed1b39b";
	test_full_hash(
			"uSDq4J5XeKYKIseRZ1H0UBEz1s9wTMI8NXQ4QQGYNnSe81sv5un5F6KjJgx9ckY1XQ"
			"xSpm9TcOx3glEHLeI9PwT6wQz7VH853DUr1yOKopf90lLzyuW2GZK9KZZt0OTFcGwy"
			"65yTHQqqUIat9elbklQjYCA7opX8nUIsnuzjTeSPPRJaw0VGvjSUHKKruXKUTE26Cb"
			"oV8SoMWXIPdk6svEEiUIdWPwCuLVluZMDlL2NO99E5rsKNUpeYmqc0vGzrBE7ilRxc"
			"zkJmghWY7yeafS9SJl7CXBYVKkFdHeOv7JWXilLJIJSlJZl1NT3PHF7FYAUlMRQbCw"
			"0u5X1HIx7mSOnAI9vlXoAQBq260pU5pIpa658PKLDisCTql5WrVOmnEgvlVrnd8xzK"
			"C1FkpbzOxQrjYSLUwlZw4XPxDfylPQomeAbCiJ6HF4sVHldtePiX1gqlKs8VjFcdGo"
			"PzfqEDEXjpaPA58aFM2I2Q5JBZZucBwdHL17RE3pPe40ToNnSy",
			SHA_256, expected);

	expected =
			"40b173a1d3b2e629b89bdfc1cc5fb8ff12c78be0db5b1b546057caa9";
	test_full_hash(
			"86GvnEzUEuIi0flmVu1mrOxFhHWYY5nFGZiBHwoWwp2rOBHHKtF59taXbeyj1nb1em"
			"8HUxC2pfvLsvvdGwjMQu15AJUuYQfQD5Uc92XN2SzDJAfe9o8Uu0IyuIURycbX5wQE"
			"ExosGohMxJUOtzHFHgoD865FQOMqJQnsNC9COMdTDURN9KpwBesL9oqfJi3B03ZHhV"
			"uF56kN2Xi3N2Q3BXhTQ88icB8fN6mO0YbHuVG0yIh9fBIUcoUGDwA1aCtuW2InNNZs"
			"xfEMPqLfuBxEtedaoP9QvEwwCDbi2sGtCx0dQq5EHqlQyYYbY3X5GvxL9HoykwCQpb"
			"6EZ3SCwWMpA2nDs0YSQqiCCjK2fIXgFC6QfO4mAQVQ0RFio0aP5WAmWSuoInBewz36"
			"9ZkA4B2r3GuR963GKLDHack4FXpmfq14WpewNfDrh1vo1KuyE9Hm9AxouI455Vnww6"
			"JUKiVu4REKfwGHPDgrAJDyeER1FF9r2wPTatkDLMI4okra5pc",
			SHA_256, expected);

	expected =
			"5d01ab0104fbc0dd2e979af9062eabe17e88274323ad0f11f3679c21";
	test_full_hash(
			"rtEf1OVfIRnXocSHmFbGBO7RPCUKrfBVF0CZTEcko2gi7u5vhNntFk0R1YIxMVuoTi"
			"dZ0ujXN1RDbRlDhiXzvdWdPAqeDGGGyDHmNYRn0RSd0g6Y4zyQ3Ny8y5NZpHX3pFEW"
			"5QEjBVcoAUaBqIwbpToIDPtHOUHHm1Rd5e35X9grhRwdQdo8IzaGCklA8EcB0Lql8G"
			"tiglSWPZUp5TbvM1lgsKrnt7Co6r8hXeHtf3SbE5FgAGnxqueDpdms9T9LpyU5ILOw"
			"C6Ynwoi3FINlD48A7C9h9tqVN4qZras8qETrFtdZIfohzA5J12wOSwIjc4qB3leRo1"
			"vpUrEX9j0ROIbKmhJmhwL56UrDMz20MrmxpgG6i9WBTJ6fcIexZga0owzYOERM3fYC"
			"4srprCDnTfwIeU22z0POIIRutb7snGMhwWc72SFqUpeWgscfWCkFPq8eQKLPUdRuli"
			"PUt2lLBV8PlRaMGvfDDu5O5GEA9MNO0k76D2oVUXGvJLITQv",
			SHA_256, expected);

	expected =
			"66369ebc569625fa664db6a440080afe39f67832b887dd1a8a21fbcf";
	test_full_hash(
			"KSsDDwq2ILpBXYzidBgTy31bGw0P4hm7skjAyz1vBrfPp72Fx26I2SaJnEtr7mMr30"
			"X0aVREmUXYlTUxXROhRmv4SeqEfvijLYyj43iRRUw90OVK4kWGyka5FFl7TRCWW85E"
			"FFs1D3iW0M9jtRVaSHfbjZkRi0n2CQjFO6AtChupq4KRSgMGoc2RuGVAG1jvZqZ0TK"
			"mbXjjVYp8VtO7rSaVf2aWaCiCjJqCtQ1RsFqgzVBBLj4dKgIegKB7xzBDdxij63Ujc"
			"1pPmNCn5ndyrg8sAMAxfsCj0E86XCxLDgrsqeLN7MgMtzdK2ER33vqoqguwxIGuo3u"
			"DmgJUHmgf8TadzWwh2XNFA3L6X0bOUmIySe7gXlQQde8RlsKzVppymaexQas6QgChv"
			"Vln0KndquCQ2cPXBpR6YhBam1pCeyBMhxBgexIbAzpIKNJcryi39YcdQGzGhFsrDvP"
			"lMR3RLuTGUEUwRu5349UrPbdGr7prJiy7GmT9jL7E",
			SHA_256, expected);

	printf(
			"\n"
			"===============================================================\n"
			"SHA-256\n"
			"===============================================================\n");
	SHA_256 = true;

	expected =
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	test_full_hash("abc", SHA_256, expected);

	expected =
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
	test_full_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			SHA_256, expected);

	expected =
			"78f5e33df6d6de6e7410ea0ed24c99fcea3ef7a509025fc45b0dafafaf641e5b";
	test_full_hash(
			"kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan",
			SHA_256, expected);

	expected =
			"121837c3e2b047948c3968faad5c18bbb8fb34fcd40b83f27571fcadc3270d39";
	test_full_hash(
			"uSDq4J5XeKYKIseRZ1H0UBEz1s9wTMI8NXQ4QQGYNnSe81sv5un5F6KjJgx9ckY1XQ"
			"xSpm9TcOx3glEHLeI9PwT6wQz7VH853DUr1yOKopf90lLzyuW2GZK9KZZt0OTFcGwy"
			"65yTHQqqUIat9elbklQjYCA7opX8nUIsnuzjTeSPPRJaw0VGvjSUHKKruXKUTE26Cb"
			"oV8SoMWXIPdk6svEEiUIdWPwCuLVluZMDlL2NO99E5rsKNUpeYmqc0vGzrBE7ilRxc"
			"zkJmghWY7yeafS9SJl7CXBYVKkFdHeOv7JWXilLJIJSlJZl1NT3PHF7FYAUlMRQbCw"
			"0u5X1HIx7mSOnAI9vlXoAQBq260pU5pIpa658PKLDisCTql5WrVOmnEgvlVrnd8xzK"
			"C1FkpbzOxQrjYSLUwlZw4XPxDfylPQomeAbCiJ6HF4sVHldtePiX1gqlKs8VjFcdGo"
			"PzfqEDEXjpaPA58aFM2I2Q5JBZZucBwdHL17RE3pPe40ToNnSy",
			SHA_256, expected);

	expected =
			"58d49406cb0d7cf127136051db93578e7152359db66d7c6875df5e098657a27f";
	test_full_hash(
			"86GvnEzUEuIi0flmVu1mrOxFhHWYY5nFGZiBHwoWwp2rOBHHKtF59taXbeyj1nb1em"
			"8HUxC2pfvLsvvdGwjMQu15AJUuYQfQD5Uc92XN2SzDJAfe9o8Uu0IyuIURycbX5wQE"
			"ExosGohMxJUOtzHFHgoD865FQOMqJQnsNC9COMdTDURN9KpwBesL9oqfJi3B03ZHhV"
			"uF56kN2Xi3N2Q3BXhTQ88icB8fN6mO0YbHuVG0yIh9fBIUcoUGDwA1aCtuW2InNNZs"
			"xfEMPqLfuBxEtedaoP9QvEwwCDbi2sGtCx0dQq5EHqlQyYYbY3X5GvxL9HoykwCQpb"
			"6EZ3SCwWMpA2nDs0YSQqiCCjK2fIXgFC6QfO4mAQVQ0RFio0aP5WAmWSuoInBewz36"
			"9ZkA4B2r3GuR963GKLDHack4FXpmfq14WpewNfDrh1vo1KuyE9Hm9AxouI455Vnww6"
			"JUKiVu4REKfwGHPDgrAJDyeER1FF9r2wPTatkDLMI4okra5pc",
			SHA_256, expected);

	expected =
			"8850102a117437b7615f63a70209a03a49c7c60f45c653f29f95f6d3ee57a82e";
	test_full_hash(
			"rtEf1OVfIRnXocSHmFbGBO7RPCUKrfBVF0CZTEcko2gi7u5vhNntFk0R1YIxMVuoTi"
			"dZ0ujXN1RDbRlDhiXzvdWdPAqeDGGGyDHmNYRn0RSd0g6Y4zyQ3Ny8y5NZpHX3pFEW"
			"5QEjBVcoAUaBqIwbpToIDPtHOUHHm1Rd5e35X9grhRwdQdo8IzaGCklA8EcB0Lql8G"
			"tiglSWPZUp5TbvM1lgsKrnt7Co6r8hXeHtf3SbE5FgAGnxqueDpdms9T9LpyU5ILOw"
			"C6Ynwoi3FINlD48A7C9h9tqVN4qZras8qETrFtdZIfohzA5J12wOSwIjc4qB3leRo1"
			"vpUrEX9j0ROIbKmhJmhwL56UrDMz20MrmxpgG6i9WBTJ6fcIexZga0owzYOERM3fYC"
			"4srprCDnTfwIeU22z0POIIRutb7snGMhwWc72SFqUpeWgscfWCkFPq8eQKLPUdRuli"
			"PUt2lLBV8PlRaMGvfDDu5O5GEA9MNO0k76D2oVUXGvJLITQv",
			SHA_256, expected);

	expected =
			"e2d3459ba006c1de9577ebc92b30213140a1ecaa44e724df73cfed5d135ed165";
	test_full_hash(
			"KSsDDwq2ILpBXYzidBgTy31bGw0P4hm7skjAyz1vBrfPp72Fx26I2SaJnEtr7mMr30"
			"X0aVREmUXYlTUxXROhRmv4SeqEfvijLYyj43iRRUw90OVK4kWGyka5FFl7TRCWW85E"
			"FFs1D3iW0M9jtRVaSHfbjZkRi0n2CQjFO6AtChupq4KRSgMGoc2RuGVAG1jvZqZ0TK"
			"mbXjjVYp8VtO7rSaVf2aWaCiCjJqCtQ1RsFqgzVBBLj4dKgIegKB7xzBDdxij63Ujc"
			"1pPmNCn5ndyrg8sAMAxfsCj0E86XCxLDgrsqeLN7MgMtzdK2ER33vqoqguwxIGuo3u"
			"DmgJUHmgf8TadzWwh2XNFA3L6X0bOUmIySe7gXlQQde8RlsKzVppymaexQas6QgChv"
			"Vln0KndquCQ2cPXBpR6YhBam1pCeyBMhxBgexIbAzpIKNJcryi39YcdQGzGhFsrDvP"
			"lMR3RLuTGUEUwRu5349UrPbdGr7prJiy7GmT9jL7E",
			SHA_256, expected);

	return 0;
}

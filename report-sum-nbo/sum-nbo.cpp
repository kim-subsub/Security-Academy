#include <stdint.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <netinet/in.h> 

uint32_t read_file(char* file_name) {
	FILE* fp = fopen(file_name, "rb");
	if (fp == NULL) {
		printf("file open error: %s\n", file_name);
		exit(1);
	}

	uint32_t n;
	size_t read_size = fread(&n, 1, sizeof(n), fp);
	fclose(fp);

	if (read_size != sizeof(n)) {
		printf("file read error: %s\n", file_name);
		exit(1);
	}

	return ntohl(n);
}

void print_number(uint32_t n) {
	printf("%u(0x%08x)", n, n);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("syntax : sum-nbo <file1> [<file2>...]\n");
		return -1;
	}

	uint32_t sum = 0;

	for (int i = 1; i < argc; i++) {
		uint32_t n = read_file(argv[i]);

		if (i != 1) printf(" + ");
		print_number(n);

		sum += n;
	}

	printf(" = ");
	print_number(sum);
	printf("\n");
}

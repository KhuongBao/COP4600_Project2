#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>   // added: needed for threading (Person A)

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define MAX_THREADS 11 // Person A: 11 workers + 1 main = 12 total, the assignment's cap

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

// Kept from the original — still useful if you compare hex strings anywhere,
// but Person B's byte-based lookup below is meant to replace the need for
// converting every computed hash to hex just to compare it.
int compare_hashes(char *a, char *b) {
	for(int i=0; i < 2*KEEP; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

// ============================================================
// PERSON B: faster lookups
// Goal: convert the target hashes to raw bytes ONCE (not per
// password), then let worker threads look up a freshly computed
// raw hash (straight from fn[i](), no hex conversion needed)
// against the target set in better than linear time.
//
// Keep each entry's ORIGINAL index into cracked_hashes[] —
// results must still be written out in the original file order,
// not sorted order.
// ============================================================
struct hash_entry {
	unsigned char bytes[KEEP];   // target hash, as raw bytes instead of hex text
	int original_index;          // index into cracked_hashes[] this came from
};

// TODO (Person B): build this once, right after cracked_hashes[] is loaded.
//      - convert each cracked_hashes[i].hash (hex string) into raw bytes
//      - store it alongside i as the original_index
//      - sort the array (e.g. qsort with a byte-array comparator) for
//        binary search, OR build a simple hash table keyed on the bytes —
//        your call, binary search is simpler to get right first
struct hash_entry *build_lookup_structure(struct cracked_hash *cracked_hashes, int n_hashed) {
	// TODO (Person B)
	return NULL;
}

// TODO (Person B): given a raw hash (KEEP bytes, straight from fn[i]()),
//      return the matching original_index, or -1 if no match.
//      This is what worker threads (Person A's crack_chunk) will call
//      instead of the old linear scan over cracked_hashes[].
int lookup_hash(struct hash_entry *lookup, int n_hashed, unsigned char *raw_hash) {
	// TODO (Person B)
	return -1;
}

// ============================================================
// PERSON C: file I/O — load the whole password list into memory
// once, instead of reading it one password at a time with fscanf.
// This is what lets Person A hand out chunks by index instead of
// fighting over a shared file pointer across threads.
// ============================================================
// TODO (Person C): read password_list fully into memory (e.g. an array
//      of char*, one per line) and return it, with *count set to the
//      number of passwords read.
char **load_passwords(char *password_list, int *count) {
	// TODO (Person C)
	*count = 0;
	return NULL;
}

// Person C also owns, separately from this file:
//   - a test script that runs the program on ALL THREE real Gradescope
//     test cases (data1: ~1M passwords / 16 hashes, data2: ~1M passwords /
//     250 hashes, data3: ~5.2M passwords / 250 hashes), diffs the output
//     against each expected.txt, and records the time printed by main.c
//     for each — data3 is the best stress test for threading bugs since
//     it has the most work happening at once
//   - the header comment block below (group, authors, NetIDs, description)
//   - making sure `make` produces zero compiler warnings
//   - comments and 4-space indentation throughout

// ============================================================
// PERSON A: threading
// ============================================================
struct thread_args {
	char **passwords;             // from Person C's load_passwords()
	int start_idx, end_idx;       // this thread's slice (exclusive end)
	struct hash_entry *lookup;    // from Person B's build_lookup_structure()
	int n_hashed;
	struct cracked_hash *local_results; // this thread's PRIVATE results, size n_hashed
};

// TODO (Person A): worker function run by each thread.
//      - loop password index from start_idx to end_idx
//      - for each password, for each of the 4 algorithms:
//          compute raw_hash = fn[i](password, strlen(password))
//          idx = lookup_hash(args->lookup, args->n_hashed, raw_hash)
//          if idx != -1 and args->local_results[idx].password == NULL:
//              record password + alg into args->local_results[idx]
//          free(raw_hash)
//      - write ONLY into args->local_results — never into a shared array,
//        and never lock anything here; that's the point of thread-local results
void *crack_chunk(void *arg) {
	// TODO (Person A)
	return NULL;
}

// Function name: crack_hashed_passwords
// Description:   Computes different hashes for each password in the password list,
//                then compare them to the hashed passwords to decide whether if
//                any of them matches this password. When multiple passwords match
//                the same hash, only the first one in the list is printed.
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
	FILE *fp;
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

	// load hashed passwords (unchanged)
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);
	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%s", cracked_hashes[i].hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
	}
	fclose(fp);

	// ============================================================
	// PERSON B: build the fast lookup structure, once, here
	// ============================================================
	// TODO (Person B): struct hash_entry *lookup = build_lookup_structure(cracked_hashes, n_hashed);

	// ============================================================
	// PERSON C: load all passwords into memory, once, here
	// ============================================================
	// TODO (Person C): int n_passwords; char **passwords = load_passwords(password_list, &n_passwords);

	// ============================================================
	// PERSON A: decide thread count, split passwords into chunks,
	// allocate each thread's private results, create + join threads
	// ============================================================
	// TODO (Person A): pthread_t threads[MAX_THREADS];
	// TODO (Person A): struct thread_args args[MAX_THREADS];
	// TODO (Person A): compute how many threads to use and each one's
	//      [start_idx, end_idx) range over the `passwords` array from Person C
	// TODO (Person A): for each thread: allocate args[i].local_results
	//      (size n_hashed, all passwords/algs NULL), fill in the rest of
	//      args[i], then pthread_create(&threads[i], NULL, crack_chunk, &args[i]);
	// TODO (Person A): for each thread: pthread_join(threads[i], NULL);

	// ============================================================
	// PERSON A: merge — for each hash, keep the match from whichever
	// thread owns the EARLIEST chunk (lower start_idx) that found one.
	// This is what preserves "first match in the password list wins"
	// even though threads don't finish in file order.
	// ============================================================
	// TODO (Person A): for j in 0..n_hashed: walk args[0..nthreads) in
	//      thread/chunk order (not finish order) and take the first
	//      non-NULL local_results[j] you find; copy it into cracked_hashes[j]

	// print results (unchanged)
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashed; i++) {
		if(cracked_hashes[i].password ==  NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// release stuff
	// TODO (Person B): free the lookup structure
	// TODO (Person C): free the passwords array
	// TODO (Person A): free each thread's local_results array
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);
}

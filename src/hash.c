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
	struct cracked_hash *cracked_hashes; // TEMP: direct read-only access so Person A
	                               // can test end-to-end before Person B's lookup_hash()
	                               // exists. Once it's ready, swap this field for
	                               // `struct hash_entry *lookup` and update crack_chunk
	                               // below to call lookup_hash() instead of scanning.
	int n_hashed;
	struct cracked_hash *local_results; // this thread's PRIVATE results, size n_hashed
};

// Worker function run by each thread. Processes only its assigned chunk
// (start_idx to end_idx) and writes matches ONLY into its own local_results —
// never into a shared array, and no locking needed because of that.
void *crack_chunk(void *arg) {
	struct thread_args *a = (struct thread_args *) arg;
	unsigned char *raw_hash;
	char hex_hash[2*KEEP+1];

	for (int idx = a->start_idx; idx < a->end_idx; idx++) {
		char *password = a->passwords[idx];

		for (int alg = 0; alg < n_algs; alg++) {
			raw_hash = fn[alg]((unsigned char *) password, strlen(password));
			for (int k = 0; k < KEEP; k++)
				sprintf(hex_hash + 2*k, "%02x", raw_hash[k]);

			// TEMP linear scan (same approach as the original single-threaded
			// code) — replace this inner loop with a single call to
			// Person B's lookup_hash(a->lookup, a->n_hashed, raw_hash)
			// once it's ready; everything else here stays the same.
			for (int j = 0; j < a->n_hashed; j++) {
				if (a->local_results[j].password != NULL)
					continue; // this chunk already found an earlier match for hash j
				if (compare_hashes(hex_hash, a->cracked_hashes[j].hash)) {
					a->local_results[j].password = strdup(password);
					a->local_results[j].alg = algs[alg];
				}
			}
			free(raw_hash);
		}
	}
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
	// TEMP (Person A testing only) — load passwords into memory here.
	// Delete this block and replace with Person C's version once ready:
	//     int n_passwords;
	//     char **passwords = load_passwords(password_list, &n_passwords);
	// ============================================================
	int n_passwords = 0;
	int capacity = 1024;
	char **passwords = (char **) malloc(capacity * sizeof(char *));
	assert(passwords != NULL);
	{
		char buf[256];
		fp = fopen(password_list, "r");
		assert(fp != NULL);
		while (fscanf(fp, "%s", buf) == 1) {
			if (n_passwords == capacity) {
				capacity *= 2;
				passwords = (char **) realloc(passwords, capacity * sizeof(char *));
				assert(passwords != NULL);
			}
			passwords[n_passwords++] = strdup(buf);
		}
		fclose(fp);
	}

	// ============================================================
	// PERSON A: decide thread count, split passwords into chunks,
	// allocate each thread's private results, create + join threads
	// ============================================================
	int nthreads = MAX_THREADS;
	if (n_passwords < nthreads)
		nthreads = (n_passwords > 0) ? n_passwords : 1;

	pthread_t threads[MAX_THREADS];
	struct thread_args args[MAX_THREADS];

	int base = n_passwords / nthreads;
	int remainder = n_passwords % nthreads;
	int start = 0;
	for (int t = 0; t < nthreads; t++) {
		int count = base + (t < remainder ? 1 : 0);

		args[t].passwords = passwords;
		args[t].start_idx = start;
		args[t].end_idx = start + count;
		args[t].cracked_hashes = cracked_hashes; // TEMP — see struct thread_args note
		args[t].n_hashed = n_hashed;
		args[t].local_results = (struct cracked_hash *) malloc(n_hashed * sizeof(struct cracked_hash));
		assert(args[t].local_results != NULL);
		for (int j = 0; j < n_hashed; j++) {
			args[t].local_results[j].password = NULL;
			args[t].local_results[j].alg = NULL;
		}

		start += count;
		pthread_create(&threads[t], NULL, crack_chunk, &args[t]);
	}

	for (int t = 0; t < nthreads; t++)
		pthread_join(threads[t], NULL);

	// ============================================================
	// PERSON A: merge — threads were created in ascending start_idx
	// order, so scanning args[0..nthreads) in that same order and
	// taking the FIRST non-NULL match per hash preserves "earliest
	// password in the original list wins," regardless of which
	// thread actually finished first.
	// ============================================================
	for (int j = 0; j < n_hashed; j++) {
		for (int t = 0; t < nthreads; t++) {
			if (args[t].local_results[j].password != NULL) {
				cracked_hashes[j].password = args[t].local_results[j].password;
				cracked_hashes[j].alg = args[t].local_results[j].alg;
				break;
			}
		}
	}

	// free every local_results string EXCEPT the ones that won the merge
	// (those are now owned by cracked_hashes[] and freed in the final cleanup below)
	for (int t = 0; t < nthreads; t++) {
		for (int j = 0; j < n_hashed; j++) {
			if (args[t].local_results[j].password != NULL
			    && args[t].local_results[j].password != cracked_hashes[j].password)
				free(args[t].local_results[j].password);
		}
		free(args[t].local_results);
	}

	for (int i = 0; i < n_passwords; i++)
		free(passwords[i]);
	free(passwords);

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

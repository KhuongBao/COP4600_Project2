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

// PERSON B: faster lookups
//
// The baseline compared a freshly computed hash against EVERY target
// by first turning it into a 32-char hex string and then scanning all
// n_hashed targets one by one (O(n_hashed) per password/alg). That
// scan is the real bottleneck once data3's 5.2M passwords x 4 algs are
// in play.
//
// This replaces that with:
//   1. convert each target hash from hex text to KEEP raw bytes ONCE,
//      at load time, keeping its original index into cracked_hashes[]
//   2. sort those entries by their raw bytes
//   3. look each computed hash up with binary search -> O(log n_hashed)
//
// Threads only READ the sorted array (built once, before any thread
// starts), so no locking is needed inside lookup_hash.
// ============================================================

// Convert one hex character ('0'-'9','a'-'f') to its 0-15 value.
static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0; // inputs are well-formed lowercase hex, so this is unreachable
}

// qsort comparator: order two entries by their KEEP raw bytes.
// memcmp gives a total order over the fixed-length byte arrays, which is
// exactly what binary search needs.
static int entry_cmp(const void *a, const void *b) {
    const struct hash_entry *ea = (const struct hash_entry *)a;
    const struct hash_entry *eb = (const struct hash_entry *)b;
    return memcmp(ea->bytes, eb->bytes, KEEP);
}

// Build the sorted lookup array once, right after cracked_hashes[] is loaded.
struct hash_entry *build_lookup_structure(struct cracked_hash *cracked_hashes, int n_hashed) {
    struct hash_entry *lookup = malloc(n_hashed * sizeof(struct hash_entry));
    assert(lookup != NULL);

    for (int i = 0; i < n_hashed; i++) {
        // Each target is 2*KEEP hex chars; fold every pair into one byte.
        for (int j = 0; j < KEEP; j++) {
            int hi = hex_val(cracked_hashes[i].hash[2*j]);
            int lo = hex_val(cracked_hashes[i].hash[2*j + 1]);
            lookup[i].bytes[j] = (unsigned char)((hi << 4) | lo);
        }
        lookup[i].original_index = i; // remember where this came from
    }

    // Sort by raw bytes so lookup_hash can binary search.
    qsort(lookup, n_hashed, sizeof(struct hash_entry), entry_cmp);
    return lookup;
}

// Binary search the sorted array for a computed raw hash (KEEP bytes,
// straight from fn[i]()). Returns the matching original index into
// cracked_hashes[], or -1 if no target matches. Read-only: safe to call
// from every worker thread at once.
int lookup_hash(struct hash_entry *lookup, int n_hashed, unsigned char *raw_hash) {
    int lo = 0, hi = n_hashed - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int c = memcmp(raw_hash, lookup[mid].bytes, KEEP);
        if (c == 0)
            return lookup[mid].original_index;
        else if (c < 0)
            hi = mid - 1;
        else
            lo = mid + 1;
    }
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
	struct hash_entry *lookup;    // from build_lookup_structure() (Person B)
	int n_hashed;
	struct cracked_hash *local_results; // this thread's PRIVATE results, size n_hashed
};

// Worker function run by each thread. Processes only its assigned chunk
// (start_idx to end_idx) and writes matches ONLY into its own local_results —
// never into a shared array, and no locking needed because of that.
void *crack_chunk(void *arg) {
	struct thread_args *a = (struct thread_args *) arg;
	unsigned char *raw_hash;

	for (int idx = a->start_idx; idx < a->end_idx; idx++) {
		char *password = a->passwords[idx];

		for (int alg = 0; alg < n_algs; alg++) {
			raw_hash = fn[alg]((unsigned char *) password, strlen(password));

			// Person B's O(log n) binary search over the raw target bytes,
			// replacing the old per-password hex conversion + linear scan.
			int j = lookup_hash(a->lookup, a->n_hashed, raw_hash);
			if (j != -1 && a->local_results[j].password == NULL) {
				// first (earliest) password in THIS chunk to match hash j wins
				a->local_results[j].password = strdup(password);
				a->local_results[j].alg = algs[alg];
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
	struct hash_entry *lookup = build_lookup_structure(cracked_hashes, n_hashed);

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
		args[t].lookup = lookup;
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
	free(lookup);
	// TODO (Person C): free the passwords array
	// TODO (Person A): free each thread's local_results array
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);
}

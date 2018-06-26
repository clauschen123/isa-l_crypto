/**********************************************************************
  Copyright(c) 2011-2017 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "sha256_mb.h"
#include <openssl/sha.h>
#include <sys/time.h>

#define TEST_LEN  		(1024*1024ull)	//1M
#define TEST_BUFS 		SHA256_MIN_LANES
#define ROTATION_TIMES 	1 //10000	//total length processing = TEST_LEN * ROTATION_TIMES
#define UPDATE_SIZE		(13*SHA256_BLOCK_SIZE)
#define LEN_TOTAL		(TEST_LEN * ROTATION_TIMES)

/* Reference digest global to reduce stack usage */
static uint8_t digest_ref_upd[4 * SHA256_DIGEST_NWORDS];

static inline unsigned int byteswap32(unsigned int x)
{
	return (x >> 24) | (x >> 8 & 0xff00) | (x << 8 & 0xff0000) | (x << 24);
}

struct user_data {
	int idx;
	int64_t processed;
};



static void printhex8(const uint8_t* buf, size_t len)
{
    printf("   ");
    for (size_t i = 0; i < len; ++i)
        printf("%08x", byteswap32(((uint32_t *)buf)[i]));
    printf("\n");
}

static void printhex32(const uint32_t* buf, size_t len)
{
    printf("   ");
    for (size_t i = 0; i < len; ++i)
        printf("%08x", buf[i]);
    printf("\n");
}

static uint32_t get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    uint32_t msec = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
    return msec;
}

typedef enum {
    SHA_OPENSSL = 0,
    SHA_NONE,
    SHA_SSE,
    SHA_SSE_NI,
    SHA_AVX1,
    SHA_AVX2,
    SHA_AVX512,
    SHA_AVX512_NI,
    SHA_METHOD_NUM
}method_t;

struct sha256_method_def {
    void (*func_init)(SHA256_HASH_CTX_MGR* mgr);
    SHA256_HASH_CTX* (*func_submit)(SHA256_HASH_CTX_MGR* mgr, SHA256_HASH_CTX* ctx, const void* buffer, uint32_t len, HASH_CTX_FLAG flags);
    SHA256_HASH_CTX* (*func_flush)(SHA256_HASH_CTX_MGR* mgr);
};

struct sha256_method_def method_def[SHA_METHOD_NUM] = {
    { NULL, NULL, NULL },
    { sha256_ctx_mgr_init,              sha256_ctx_mgr_submit,              sha256_ctx_mgr_flush            },
    { sha256_ctx_mgr_init_sse,          sha256_ctx_mgr_submit_sse,          sha256_ctx_mgr_flush_sse        },

    { NULL, NULL, NULL },
//  { sha256_ctx_mgr_init_sse_ni,       sha256_ctx_mgr_submit_sse_ni,       sha256_ctx_mgr_flush_sse_ni     },
    { sha256_ctx_mgr_init_avx,          sha256_ctx_mgr_submit_avx,          sha256_ctx_mgr_flush_avx        },
    { sha256_ctx_mgr_init_avx2,         sha256_ctx_mgr_submit_avx2,         sha256_ctx_mgr_flush_avx2       },

    { NULL, NULL, NULL },
//  { sha256_ctx_mgr_init_avx512,       sha256_ctx_mgr_submit_avx512,       sha256_ctx_mgr_flush_avx512     },
    { NULL, NULL, NULL },
//  { sha256_ctx_mgr_init_avx512_ni,    sha256_ctx_mgr_submit_avx512_ni,    sha256_ctx_mgr_flush_avx512_ni  },
};

void sha256_ssl(int64_t index, const uint8_t* buf, int size)
{
    SHA256_CTX o_ctx;	//openSSL
    SHA256_Init(&o_ctx);
    SHA256_Update(&o_ctx, buf, size);
    SHA256_Final(digest_ref_upd, &o_ctx);
    
    if(index < 3)
        printhex8(digest_ref_upd, SHA256_DIGEST_NWORDS);
}

void sha256_isa(int64_t index, method_t method, const uint8_t* buf, int size)
{
    SHA256_HASH_CTX_MGR *mgr = NULL;
    SHA256_HASH_CTX ctxpool[1], *ctx = NULL;

    struct user_data udata[1];

    posix_memalign((void *)&mgr, 16, sizeof(SHA256_HASH_CTX_MGR));
    method_def[method].func_init(mgr);

    // Init ctx contents
    hash_ctx_init(&ctxpool[0]);
    ctxpool[0].user_data = (void *)&udata[0];
    udata[0].idx = 0;
    udata[0].processed = 0;

    int highest_pool_idx = 0;
    ctx = &ctxpool[highest_pool_idx++];

    while (ctx) {
        int len = size < UPDATE_SIZE ? size : UPDATE_SIZE;
        int update_type = HASH_UPDATE;
        struct user_data *u = (struct user_data *)ctx->user_data;
        int idx = u->idx;

        if (u->processed == 0) {
            update_type = HASH_FIRST;
        }
        else if (hash_ctx_complete(ctx)) {
            if (highest_pool_idx < 1)
                ctx = &ctxpool[highest_pool_idx++];
            else
                ctx = method_def[method].func_flush(mgr);
            continue;
        }
        else if (u->processed >= (size - UPDATE_SIZE)) {
            len = (size - u->processed);
            update_type = HASH_LAST;
        }
        u->processed += len;
        ctx = method_def[method].func_submit(mgr, ctx, buf, len, update_type);

        if (NULL == ctx) {
            if (highest_pool_idx < 1) {
                ctx = &ctxpool[highest_pool_idx++];
            }
            else {
                ctx = method_def[method].func_flush(mgr);
            }
        }
    }
    if (index < 3)
        printhex32(ctxpool[0].job.result_digest, SHA256_DIGEST_NWORDS);
}

void test_perf(method_t method, int64_t count, const uint8_t* buf, int size)
{
    uint32_t start = get_time_ms();
    for (int64_t i = 0; i < count; ++i)
    {
        switch (method)
        {
        case SHA_OPENSSL:
            sha256_ssl(i, buf, size);
            break;
        case SHA_AVX1:
        case SHA_AVX2:
        case SHA_SSE:
            sha256_isa(i, method, buf, size);
            break;
        }
    }
    uint32_t time = get_time_ms() - start;
    double sec = time / 1000.0;
    double rate = count / sec;
    printf("   Time: %lf sec, hashrate: %lf\n", sec, rate);

}
int main(void)
{
	SHA256_CTX o_ctx;	//openSSL
	SHA256_HASH_CTX_MGR *mgr = NULL;
	SHA256_HASH_CTX ctxpool[TEST_BUFS], *ctx = NULL;
	uint32_t i, j, k, fail = 0;
	unsigned char *bufs[TEST_BUFS];
	struct user_data udata[TEST_BUFS];

// 	posix_memalign((void *)&mgr, 16, sizeof(SHA256_HASH_CTX_MGR));
// 	sha256_ctx_mgr_init(mgr);


	// Init ctx contents
	for (i = 0; i < TEST_BUFS; i++) {
		bufs[i] = (unsigned char *)calloc((size_t) TEST_LEN, 1);
		if (bufs[i] == NULL) {
			printf("malloc failed test aborted\n");
			return 1;
        }
        else {
//             memcpy(bufs[i], "abc", TEST_LEN);
        }
// 		hash_ctx_init(&ctxpool[i]);
// 		ctxpool[i].user_data = (void *)&udata[i];
	}
    int count = 5;

    printf("openssl\n");
    test_perf(SHA_OPENSSL, count, bufs[0], TEST_LEN);

    printf("sse\n");
    test_perf(SHA_SSE, count, bufs[0], TEST_LEN);

    printf("avx1\n");
    test_perf(SHA_AVX1, count, bufs[0], TEST_LEN);

    printf("avx2\n");
    test_perf(SHA_AVX2, count, bufs[0], TEST_LEN);

    return 0;

	//Openssl SHA256 update test
// 	SHA256_Init(&o_ctx);
// 	for (k = 0; k < ROTATION_TIMES; k++) {
// 		SHA256_Update(&o_ctx, bufs[k % TEST_BUFS], TEST_LEN);
// 	}
// 	SHA256_Final(digest_ref_upd, &o_ctx);

	// Initialize pool
// 	for (i = 0; i < TEST_BUFS; i++) {
// 		struct user_data *u = (struct user_data *)ctxpool[i].user_data;
// 		u->idx = i;
// 		u->processed = 0;
// 	}

	printf("Starting updates\n");
	int highest_pool_idx = 0;
	ctx = &ctxpool[highest_pool_idx++];
	while (ctx) {
		int len = UPDATE_SIZE;
		int update_type = HASH_UPDATE;
		struct user_data *u = (struct user_data *)ctx->user_data;
		int idx = u->idx;

		if (u->processed == 0)
			update_type = HASH_FIRST;

		else if (hash_ctx_complete(ctx)) {
			if (highest_pool_idx < TEST_BUFS)
				ctx = &ctxpool[highest_pool_idx++];
			else
				ctx = sha256_ctx_mgr_flush(mgr);
			continue;
		} else if (u->processed >= (LEN_TOTAL - UPDATE_SIZE)) {
			len = (LEN_TOTAL - u->processed);
			update_type = HASH_LAST;
		}
		u->processed += len;
		ctx = sha256_ctx_mgr_submit(mgr, ctx, bufs[idx], len, update_type);

		if (NULL == ctx) {
			if (highest_pool_idx < TEST_BUFS)
				ctx = &ctxpool[highest_pool_idx++];
			else
				ctx = sha256_ctx_mgr_flush(mgr);
		}
	}

	printf("multibuffer SHA256 digest: \n");
	for (i = 0; i < TEST_BUFS; i++) {
		printf("Total processing size of buf[%d] is %ld \n", i,
		       ctxpool[i].total_length);
		for (j = 0; j < SHA256_DIGEST_NWORDS; j++) {
			printf("digest%d : %08X\n", j, ctxpool[i].job.result_digest[j]);
		}
	}
	printf("\n");

	printf("openssl SHA256 update digest: \n");
	for (i = 0; i < SHA256_DIGEST_NWORDS; i++)
		printf("%08X - ", byteswap32(((uint32_t *) digest_ref_upd)[i]));
	printf("\n");

	for (i = 0; i < TEST_BUFS; i++) {
		for (j = 0; j < SHA256_DIGEST_NWORDS; j++) {
			if (ctxpool[i].job.result_digest[j] !=
			    byteswap32(((uint32_t *) digest_ref_upd)[j])) {
				fail++;
			}
		}
	}

	if (fail)
		printf("Test failed SHA256 hash large file check %d\n", fail);
	else
		printf(" SHA256_hash_large_test: Pass\n");
	return fail;
}

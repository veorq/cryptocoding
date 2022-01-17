# Cryptocoding

This page lists "coding rules" for implementations of cryptographic operations, and more generally for operations involving secret or sensitive values.

The rules on this page are general recommendations and best practices to write safer code, but may not apply to all languages, may not be up-to-date with respect to the latest version of a language, OS, or library, and of course aren't sufficient to write secure code.
It's focused on low-level (read: C) implementations—although we recommend against writing your own C cryptography components. 
Pull requests to improve the current content or to add new "rules" are welcome.

Most of the content comes from the "Crypto coding standard", originally set up by @veorq at cryptocoding.net, and created thanks to many contributors.


Table of Contents
=================

   * [Cryptocoding](#cryptocoding)
      * [Compare secret strings in constant time](#compare-secret-strings-in-constant-time)
         * [Problem](#problem)
         * [Solution](#solution)
      * [Avoid branchings controlled by secret data](#avoid-branchings-controlled-by-secret-data)
         * [Problem](#problem-1)
         * [Solution](#solution-1)
      * [Avoid table look-ups indexed by secret data](#avoid-table-look-ups-indexed-by-secret-data)
         * [Problem](#problem-2)
         * [Solution](#solution-2)
      * [Avoid secret-dependent loop bounds](#avoid-secret-dependent-loop-bounds)
         * [Problem](#problem-3)
         * [Solution](#solution-3)
      * [Prevent compiler interference with security-critical operations](#prevent-compiler-interference-with-security-critical-operations)
         * [Problem](#problem-4)
         * [Solution](#solution-4)
      * [Prevent confusion between secure and insecure APIs](#prevent-confusion-between-secure-and-insecure-apis)
         * [Problem](#problem-5)
         * [Bad Solutions](#bad-solutions)
         * [Solution](#solution-5)
      * [Avoid mixing security and abstraction levels of cryptographic primitives in the same API layer](#avoid-mixing-security-and-abstraction-levels-of-cryptographic-primitives-in-the-same-api-layer)
         * [Problem](#problem-6)
         * [Solution](#solution-6)
            * [Provide high-level APIs](#provide-high-level-apis)
            * [When possible, avoid low-level APIs](#when-possible-avoid-low-level-apis)
            * [Clearly distinguish high-level APIs and low-level APIs](#clearly-distinguish-high-level-apis-and-low-level-apis)
      * [Use unsigned bytes to represent binary data](#use-unsigned-bytes-to-represent-binary-data)
         * [Problem](#problem-7)
         * [Solution](#solution-7)
      * [Clean memory of secret data](#clean-memory-of-secret-data)
         * [Problem](#problem-8)
         * [Solution](#solution-8)
      * [Use strong randomness](#use-strong-randomness)
         * [Problem](#problem-9)
         * [Bad solutions](#bad-solutions-1)
         * [Solution](#solution-9)
      * [Always typecast shifted values](#always-typecast-shifted-values)
         * [Problem](#problem-10)
         * [Solution](#solution-10)




## Compare secret strings in constant time

### Problem

String comparisons performed byte-per-byte may be exploited in timing attacks, for example in order to forge MACs (see [this](http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/) and [this vulnerability](http://codahale.com/a-lesson-in-timing-attacks/) in Google's [Keyczar crypto library](https://code.google.com/p/keyczar/)).

Built-in comparison functions such as C's `memcmp`, Java's `Arrays.equals`, or Python's `==` test may not execute in constant time.

For example, this is [OpenBSD libc](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libc/string/memcmp.c?rev=1.6&content-type=text/x-cvsweb-markup) implementation of `memcmp`:
<!-- http://stackoverflow.com/questions/5017659/implementing-memcmp -->
```C
int
memcmp(const void *s1, const void *s2, size_t n)
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;

		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return (0);
}
```

The risk is greater on legacy platforms and on embedded platform, as they are more likely to perform byte-wise comparisons.

### Solution

Use a constant-time comparison function:

* With OpenSSL, use `CRYPTO_memcmp`
* In Python 2.7.7+, use `hmac.compare_digest`
* In Java, use `java.security.MessageDigest.isEqual`
* In Go, use package `crypto/subtle`

If one is not available, add your own, as used for example by [NaCl](https://nacl.cr.yp.to/verify.html):

```C
int crypto_verify_16(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  return (1 & ((differentbits - 1) >> 8)) - 1; /* returns 0 if equal, 0xFF..FF otherwise */
}
```

A more general version of the same technique can be found below:

```C
int util_cmp_const(const void * a, const void *b, const size_t size) 
{
  const unsigned char *_a = (const unsigned char *) a;
  const unsigned char *_b = (const unsigned char *) b;
  unsigned char result = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    result |= _a[i] ^ _b[i];
  }

  return result; /* returns 0 if equal, nonzero otherwise */
}
```

Examples of constant-time tests and comparisons for 32-bit values, [by @sneves](https://gist.github.com/sneves/10845247):

```C
#include <stdint.h>

/* Unsigned comparisons */
/* Return 1 if condition is true, 0 otherwise */
int ct_isnonzero_u32(uint32_t x)
{
    return (x|-x)>>31;
}

int ct_iszero_u32(uint32_t x)
{
    return 1 ^ ct_isnonzero_u32(x);
}

int ct_neq_u32(uint32_t x, uint32_t y)
{
    return ((x-y)|(y-x))>>31;
}

int ct_eq_u32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_neq_u32(x, y);
}

int ct_lt_u32(uint32_t x, uint32_t y)
{
    return (x^((x^y)|((x-y)^y)))>>31;
}

int ct_gt_u32(uint32_t x, uint32_t y)
{
    return ct_lt_u32(y, x);
}

int ct_le_u32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_gt_u32(x, y);
}

int ct_ge_u32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_lt_u32(x, y);
}

/* Signed comparisons */
/* Return 1 if condition is true, 0 otherwise */
int ct_isnonzero_s32(uint32_t x)
{
    return (x|-x)>>31;
}

int ct_iszero_s32(uint32_t x)
{
    return 1 ^ ct_isnonzero_s32(x);
}

int ct_neq_s32(uint32_t x, uint32_t y)
{
    return ((x-y)|(y-x))>>31;
}

int ct_eq_s32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_neq_s32(x, y);
}

int ct_lt_s32(uint32_t x, uint32_t y)
{
    return (x^((x^(x-y))&(y^(x-y))))>>31;
}

int ct_gt_s32(uint32_t x, uint32_t y)
{
    return ct_lt_s32(y, x);
}

int ct_le_s32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_gt_s32(x, y);
}

int ct_ge_s32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_lt_s32(x, y);
}

/* Generate a mask: 0xFFFFFFFF if bit != 0, 0 otherwise */
uint32_t ct_mask_u32(uint32_t bit)
{
    return -(uint32_t)ct_isnonzero_u32(bit);
}

/* Conditionally return x or y depending on whether bit is set */
/* Equivalent to: return bit ? x : y */
uint32_t ct_select_u32(uint32_t x, uint32_t y, uint32_t bit)
{
    uint32_t m = ct_mask_u32(bit);
    return (x&m) | (y&~m);
    /* return ((x^y)&m)^y; */
}
```

**Note**: The above measures are best effort: C and C++ have the [as-if rule](http://en.cppreference.com/w/cpp/language/as_if), which gives the compiler freedom to implement operations in any arbitrary manner, provided the observable behavior (timing is not considered observable behavior in such languages) remains unchanged. Other languages such as [Rust](https://github.com/klutzy/nadeko#why) have similar semantics, and thus similar caveats apply. For example, consider the following variant of the above `ct_select_u32`:

```C
uint32_t ct_select_u32(uint32_t x, uint32_t y, _Bool bit)
{
    uint32_t m = ct_mask_u32(bit);
    return (x&m) | (y&~m);
}
```

When compiled with `clang-3.5 -O2 -m32 -march=i386`, the result is 

```asm
ct_select_u32:                          
    mov    al, byte ptr [esp + 12]
    test    al, al
    jne    .LBB0_1
    lea    eax, dword ptr [esp + 8]
    mov    eax, dword ptr [eax]
    ret
.LBB0_1:
    lea    eax, dword ptr [esp + 4]
    mov    eax, dword ptr [eax]
    ret
```

Due to branch predictor stalls, this potentially reveals the chosen value via a timing side-channel. Since compilers have essentially unlimited freedom to generate variable-time code, it is important to check the output assembly to verify that it is, indeed, constant-time.

Another example of constant-time source code compiling to variable-time execution was observed with [Curve25519 built with MSCV 2015](https://infoscience.epfl.ch/record/223794/files/32_1.pdf).

## Avoid branchings controlled by secret data

### Problem

If a conditional branching (`if`, `switch`, `while`, `for`) depends on secret data then the code executed as well as its execution time depend on the secret data as well.

A classical example is the [timing attack on square-and-multiply](http://users.belgacom.net/dhem/papers/CG1998_1.pdf) exponentiation algorithms (or double-and-add for multiplication in elliptic curve-based cryptosystems).

Secret-dependent loop bounds are a special case of this problem.

### Solution

Timing leaks may be mitigated by introducing dummy operations in branches of the program in order to ensure a constant execution time. It is however more reliable to avoid branchings altogether, for example by implementing the conditional operation as a straight-line program. To select between two inputs `a` and `b` depending on a selection bit `bit`, this can be achieved with the following code:
<!-- from E. Kasper's ECC code, listing 1 in http://static.googleusercontent.com/external_content/untrusted_dlcp/research.google.com/en//pubs/archive/37376.pdf -->
<!-- Changed int to unsigned. The C standard guarantees that negation of an n-bit unsigned x is 2^n - x; signed integers may have other interpretations, e.g. one's complement -->
<!-- Changed to return a when bit is non-zero, b otherwise. -->


```C
/* Conditionally return a or b depending on whether bit is set */
/* Equivalent to: return bit ? a : b */
unsigned select (unsigned a, unsigned b, unsigned bit)
{
        unsigned isnonzero = (bit | -bit) >> (sizeof(unsigned) * CHAR_BIT - 1);
        /* -0 = 0, -1 = 0xff....ff */
        unsigned mask = -isnonzero;
        unsigned ret = mask & (b^a);
        ret = ret ^ b;
        return ret;
}
```

A possibly faster solution on Intel processors involves the [CMOV](http://www.jaist.ac.jp/iscenter-new/mpc/altix/altixdata/opt/intel/vtune/doc/users_guide/mergedProjects/analyzer_ec/mergedProjects/reference_olh/mergedProjects/instructions/instruct32_hh/vc35.htm) conditional move instructions.

## Avoid table look-ups indexed by secret data

### Problem

The access time of a table element can vary with its index (depending for example on whether a cache-miss has occured). This has for example been exploited in a series of cache-timing attacks on AES.

### Solution

Replace table look-up with sequences of constant-time logical operations, for example by bitslicing look-ups (as used in [NaCl's](http://nacl.cr.yp.to/) [implementation](http://eprint.iacr.org/2009/129.pdf) of AES-CTR, or in [Serpent](https://www.ii.uib.no/~osvik/serpent/).
For AES, constant-time non-bitsliced implementations are also [possible](http://crypto.stackexchange.com/questions/55/known-methods-for-constant-time-table-free-aes-implementation-using-standard/92#92), but are much slower. 


## Avoid secret-dependent loop bounds

### Problem

Loops with a bound derived from a secret value directly expose a program to timing attacks. For example, a Montgomery ladder implementation in OpenSSL 0.9.8o leaked the logarithm of the (secret) ECDSA nonce, which could be used to [steal the private key](https://eprint.iacr.org/2011/232.pdf) of a TLS server. The relevant code is copied below, where `scalar` is the secret nonce, and `scalar->d` a pointer to an array of its bits:

```C
/* find top most bit and go one past it */
i = scalar -> top - 1; j = BN_BITS2 - 1;
mask = BN_TBIT ;
while (!( scalar -> d[i] & mask )) { mask >>= 1; j --; }
mask >>= 1; j - -;
/* if top most bit was at word break , go to next word */
if (! mask )
{
  i - -; j = BN_BITS2 - 1;
  mask = BN_TBIT ;
}
for (; i >= 0; i - -)
{
  for (; j >= 0; j - -)
  {
    if ( scalar ->d[ i] & mask )
    {
      if (! gf2m_Madd ( group , & point ->X , x1 , z1 , x2 , z2 , ctx )) goto err ;
      if (! gf2m_Mdouble ( group , x2 , z2 , ctx )) goto err ;
    }
    else
    {
      if (! gf2m_Madd ( group , & point ->X , x2 , z2 , x1 , z1 , ctx )) goto err ;
      if (! gf2m_Mdouble ( group , x1 , z1 , ctx )) goto err ;
    }
    mask >>= 1;
  }
  j = BN_BITS2 - 1;
  mask = BN_TBIT;
}
```

### Solution

Make sure that all loops are bounded by a constant (or at least a non-secret variable).

In particular, make sure, as far as possible, that loop bounds and their potential underflow or overflow are independent of user-controlled input (you may have heard of the [Heartbleed bug](http://heartbleed.com/)).

## Prevent compiler interference with security-critical operations

### Problem

Some compilers will optimize out operations they deem useless. For example, MS Visual C++ 2010 suppressed the `memset` in the following code fragment from the [Tor](https://www.torproject.org/) anonymity network:

```C
int
crypto_pk_private_sign_digest(...)
{
  char digest[DIGEST_LEN];
  (...)
  memset(digest, 0, sizeof(digest));
  return r;
}
```

However the role of this `memset` is to clear the buffer `digest` off of [secret data](http://www.viva64.com/en/b/0178/) so that any subsequent (erroneous, undefined!) reads of uninitialized stack will learn no secret information.

Some compilers infer that they can eliminate checks based on erroneous code elsewhere in the program.

For example, when encountering

```C
  call_fn(ptr); // always dereferences ptr.

  // many lines here

  if (ptr == NULL) { error("ptr must not be NULL"); }
``` 

some compilers will decide that `ptr == NULL` must always be false, since otherwise it would be incorrect to dereference it in `call_fn()`.

### Solution

Look at the assembly code produced and check that all instructions are there. (This will not be possible for typical application sizes, but should be considered for security-sensitive code.)

Know what optimizations your compiler can do, and carefully consider the effect of each one on security programming patterns. In particular, be careful of optimizations that can remove code or branches, and code that prevents errors which "should be impossible" if the rest of the program is correct.

When possible, consider disabling compiler optimizations that can eliminate or weaken security checks.

To prevent the compiler from "optimizing out" instructions by eliminating them, a function may be redefined as a volatile pointer to force the function pointer dereference. This is for example used in [libottery](https://github.com/nmathewson/libottery/) by redefining `memset` to

```C
void * (*volatile memset_volatile)(void *, int, size_t) = memset;
```

Note that such workarounds [may not be sufficient](https://www.daemonology.net/blog/2014-09-05-erratum.html) and can still be optimized out.

C11 introduced `memset_s` with a requirement that it is not optimized out. It's an optional feature that can be requested when including string.h.

```
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
...
memset_s(secret, sizeof(secret), 0, sizeof(secret));
```


## Prevent confusion between secure and insecure APIs

### Problem
Many programming environments provide multiple implementations of the same API whose functionality is superficially similar, but whose security properties are radically different.

Pseudorandom number generators frequently have this problem: OpenSSL has `RAND_bytes()` and `RAND_pseudo_bytes()`; many BSD C libraries have `random()` and `arc4random()`; Java has `Random` and `SecureRandom`.

For another example, even on systems that provide a constant-time function to compare two byte strings of a given length, there invariably exist fast-exit variants.

### Bad Solutions
Sometimes a function is safe on some platforms but dangerous on others. In these cases, some programmers use the function, believing that their code will only run on platforms where it is safe. This is a bad idea, since when the code is ported to a different platform, it may become insecure without anyone realizing.

On systems that permit applications to override platform-provided functions, some programmers override insecure functions with secure ones, and then write their programs to use the API that would ordinarily be insecure. This is a questionable idea on its own, since it results in the programmer writing insecure-looking code. Further, if the overriding method ever fails (or is itself re-overridden), the program will become insecure without the new insecurity being detected. Finally, it can result in programs whose pieces become insecure if they are ever copied into another program.

### Solution
When possible, do not include insecure variants of secure functions. For example, a PRNG based on a well-seeded secure stream cipher is generally fast enough for most applications. A data-independent memcmp replacement is fast enough to replace nearly all uses of `memcmp`.

If you can't remove an insecure function, override it with a variant that produces a compile-time error, or use a code-scanning tool to detect and warn about its use. If you can override a insecure function with a secure variant, you may do so, but for safety in depth, never call the insecure API, and make sure that you can detect its use.

If you must retain both a secure and an insecure version of a given function, make sure that the names of the functions are distinctive in a way that makes it hard to accidentally use an insecure variant. For example, if you must have a secure and an insecure PRNG, don't name the insecure one "Random" or "FastRandom" or "MersenneTwister" or "LCGRand" -- instead, name it something like "InsecureRandom." The spelling for "Insecure" should never be ""; design your APIs so that using an insecure function is always a bit scary.

When your platform provides an insecure function variant without a name that implies it is insecure, and you can't remove the function, give it a wrapper with a safe name, then use a code-scanning tool to detect and warn about all calls to the unsafe name.

When a function is secure on some platforms but insecure on others, do not use the function directly: instead, provide a wrapper that is secure everywhere, and use that wrapper instead.


## Avoid mixing security and abstraction levels of cryptographic primitives in the same API layer

### Problem
When it's not clear which parts of an API require how much expertise, it's easy for a programmer to make mistakes about which functionality is safe for them to use.

Consider the following (invented, but not unusual) RSA API:

```C
enum rsa_padding_t { no_padding, pkcs1v15_padding, oaep_sha1_padding, pss_padding };
int do_rsa(struct rsa_key *key, int encrypt, int public, enum rsa_padding_t padding_type, uint8_t *input, uint8_t *output);
```

Assuming that "key" contains the requisite components, this function can be invoked in 16 ways, many of them nonsensical, and several insecure.


| encrypt | public | padding_type | notes |
| -- | -- | -- | -- |
| 0 | 0 | none | ☠: Unpadded decryption. Malleable. |
| 0 | 0 | pkcs1v15 | ☠: PKCS1 v1.5 decryption. Probably falls to Bleichenbacher’s attack. | 
| 0 | 0 | oaep | 🔒: OAEP decryption. Just fine. |
| 0 | 0 | pss | ⚠️: PSS decryption. Eccentric; probably accidental. (secure?) |
| 0 | 1 | none | ☠: Unpadded signature. Malleable. |
| 0 | 1 | pkcs1v15 | ⚠️: PKCS1 v1.5 signature. Okay for some applications, but should use PSS instead. | 
| 0 | 1 | oaep | ⚠️: OAEP signature. May be okay for some applications, but should use PSS instead.  |
| 0 | 1 | pss | 🔒️: PSS signature. Great. |

Note that only 4 of the 16 ways to call this function are a good idea, 6 of the 16 ways are downright insecure, and the remaining 6 are in some way problematic.  This API is only suitable for use by implementors who understand the ramifications of different RSA padding modes.

Now imagine that we add APIs for block cipher encryption in various modes, for random key generation, and for a wide variety of digest functions and MACs.  Any programmer attempting to construct a correct hybrid authenticate-and-encrypt-this-data function from these will have his or her options grow exponentially, as the safe portion of the decision space dwindles.

### Solution

#### Provide high-level APIs
For example, provide a set of hybrid-encrypt-and-authenticate functions that use only safe algorithms, safely. If writing a function that allows multiple combinations of public-key and secret-key algorithms and modes, ensure that it rejects insecure algorithms and insecure combinations of algorithms.

#### When possible, avoid low-level APIs
For nearly all users, there is no need to ever use unpadded RSA, or to use a block cipher in ECB mode, or to perform a DSA signature with a user-selected nonce. These functions ''can'' be used as building-blocks to make something secure -- for example, by doing OAEP padding before calling  unpadded RSA, or doing ECB on the sequence of blocks [1, 2, 3] in order to produce a counter mode stream, or by using a random or unpredictable byte-sequence to produce the DSA nonce -- but experience suggest that they will be misused more frequently than they are used correctly.

Some other primitives are necessary for implementing certain protocols, but unlikely to be a good first choice for implementing new protocols. For example, you can't implement browser-compatible TLS nowadays without CBC, PKCS1 v1.5, and RC4, but none of these would be a great.

If you are providing a crypto implementation for use by inexperienced programmers, it may be best to omit these functions entirely, and choose only functions that implement well-specified, high-level, secure operations. But if you must provide an implementation for use by experienced and inexperienced programmers alike...

#### Clearly distinguish high-level APIs and low-level APIs
"Encrypt securely" should not be the same function as "encrypt incorrectly" with slightly different arguments. In languages that divide functions and types into packages or headers, safe and unsafe crypto should not occupy the same packages/headers. In languages with subtyping, there should be a separate type for safe crypto.

<!-- give example of AES-CBC in OpenSSL: low-level vs EVP API... -->


## Use unsigned bytes to represent binary data

### Problem
Some languages in the C family have separate signed and unsigned integer types. For C in particular, the signedness of the type `char` is implementation-defined. This can lead to problematic code such as:

```C
int decrypt_data(const char *key, char *bytes, size_t len);

void fn(...) {
    //...
    char *name;
    char buf[257];
    decrypt_data(key, buf, 257);

    int name_len = buf[0];
    name = malloc(name_len + 1);
    memcpy(name, buf+1, name_len);
    name[name_len] = 0;
    //...
}
```

If the `char` type is unsigned, this code behaves as expected. But when `char` is signed, `buf[0]` may be negative, leading to a very large argument for `malloc` and `memcpy`, and a heap corruption opportunity when we try to set the last character of name to `0`. Worse, if `buf[0]` is `255`, then `name_len` will be `-1`. So we will allocate a 0-byte buffer, but then perform a `(size_t)-1 memcpy` into that buffer, thus stomping the heap.

### Solution

In languages with signed and unsigned byte types, implementations should always use the unsigned byte type to represent bytestrings in their APIs.


## Clean memory of secret data

### Problem

Process memory can be unintentionally accessed by another process when — process is crashed and core dumped (by accessing the [core dump file](https://wiki.archlinux.org/title/Core_dump)), process memory is swapped (by accessing swap partition), by exploiting a kernel bug or a [bug in the process itself](https://en.wikipedia.org/wiki/Heartbleed), or by some legitimate methods — such as process tracing, or other debugging facilities. Also, hardware methods such as [DMA attack](https://en.wikipedia.org/wiki/DMA_attack), [cold boot attack](https://en.wikipedia.org/wiki/Cold_boot_attack), [Spectre vulnerability](https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)), etc.

### Solution

Clear all variables containing secret data before they go out of scope. Worry about `mmap()`: executing `munmap()` causes memory to go out of scope immediately, while erasing while the mapping exists will destroy the file.

For clearing memory or destroying objects that are about to go out of scope, use a platform-specific memory-wipe function where available, for example:

- `memset_s`: part of C11 (see above);
- `explicit_bzero`: [OpenBSD](https://man.openbsd.org/explicit_bzero) extension, also on [FreeBSD](https://www.freebsd.org/cgi/man.cgi?explicit_bzero) and [glibc](http://man7.org/linux/man-pages/man3/bzero.3.html);
- `SecureZeroMemory()` on [Windows](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366877(v=vs.85));
- `sodium_memzero()` in [libsodium](https://download.libsodium.org/doc/memory_management);
- `OPENSSL_cleanse()` in OpenSSL.

A portable C solution, for non-buggy compilers, follows:

```C
void burn( void *v, size_t n )
{
  volatile unsigned char *p = ( volatile unsigned char * )v;
  while( n-- ) *p++ = 0;
}
```

Unfortunately, there's virtually no way to reliably clean secret data in garbage-collected languages (such as Go, Java, or JavaScript), nor in language with immutable strings (such as Swift or Objective-C).
Let's see for example why it's preferable to use `bytes` for secrets in Objective-C:

```objc
// NSDictionary <passwordUniqueIdentifier, passwordKey>
@property (nonatomic, strong) NSMutableDictionary <NSString *, NSMutableData *> *passwordsCache;

...

// clean up values
[self.passwordsCache enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, NSMutableData * _Nonnull data, BOOL * _Nonnull stop) {
    [data resetBytesInRange:NSMakeRange(0, [data length])];
}];
[self.passwordsCache removeAllObjects];
```

## Use strong randomness

### Problem
Many cryptographic systems require sources of random numbers, and fail with even slight deviations from randomness. For example, leaking just one bit of each random number in the DSA will reveal a private key astonishingly quickly. Lack of randomness can be surprisingly hard to diagnose: the Debian random number generator [failure](http://www.debian.org/security/2008/dsa-1571) in OpenSSL went unnoticed for 2 years, compromising a vast number of keys. The requirements on random numbers for cryptographic purposes are very stringent: most pseudorandom number generators (PRNG) fail to meet them.

### Bad solutions

For cryptographic applications,

* Do not rely only on predictable entropy source like timestamps, PIDs, temperature sensors, etc.
* Do not rely only on general-purpose pseudorandom functions like `stdlib`'s `rand()`, `srand()`, `random()`, or Python's `random` module.
* Do not use [Mersenne Twister](http://crypto.di.uoa.gr/CRYPTO.SEC/Randomness_Attacks.html).
* Do not use things like http://www.random.org/ (the random data may be shared with and available to other parties).
* Do not design your own PRNG, even if it's based on a secure cryptographic primitive (unless you know what you're doing).
* Do not reuse the same randomness accross applications to "save" random numbers.
* Do not conclude that a PRNG is secure just because it passes the [Diehard](http://www.stat.fsu.edu/pub/diehard/) tests or [NIST's tests](http://csrc.nist.gov/groups/ST/toolkit/rng/stats_tests.html).
* Do not assume that a cryptographically secure PRNG necessarily provides forward or backward secrecy (aka [backtracking resistance and prediction resistance](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf), would the internal state leak to an attacker.
* Do not directly use "entropy" as pseudorandom data (entropy from analog sources is often biased, that is, N bits from an entropy pool often provide less than N bits of entropy).

### Solution
Minimize the need for randomness through design and choice of primitives (for example [Ed25519](http://ed25519.cr.yp.to/) produces signatures deterministically).

On Linux, use the [`getrandom()`](http://man7.org/linux/man-pages/man2/getrandom.2.html) system call, which ensures that the underlying PRNG has a high enough level entropy but will not "block" afterwards.
On OpenBSD, use [`arc4random()`](https://man.openbsd.org/arc4random.3), which is a ChaCha20-based PRNG that calls `getentropy()` for its initial seed. Use this for large amounts of cryptographically-secure randomness. [`getentropy()`](https://man.openbsd.org/getentropy.2) has a 256-byte limit per call and is suitable for scenarios such as seeding PRNGs.
On FreeBSD 12 and newer, both [`getrandom()`](https://www.freebsd.org/cgi/man.cgi?getrandom) and [`getentropy()`](https://www.freebsd.org/cgi/man.cgi?query=getentropy&sektion=3&apropos=0&manpath=FreeBSD+12.0-RELEASE+and+Ports) are available. Older versions only have the `KERN_ARND` `sysctl`.	

The OpenSSL API offers [`RAND_bytes()`](https://www.openssl.org/docs/man1.0.2/man3/RAND_bytes.html), which behaves differently depending on the platform and attempts to use reliable source of entropy when available. For example, on a Unix platform it would use `/dev/urandom` and the RDRAND/RDSEED instructions, if available, among others.

When generating random bytes use operating-system provided sources guaranteed to meet cryptographic requirements like `/dev/random`. On constrained platforms consider adding analog sources of noise and mixing them well.

Do [check the return values](http://jbp.io/2014/01/16/openssl-rand-api) of your RNG, to make sure that the random bytes are as strong as they should be, and they have been written successfully.

Follow the recommendations from Nadia Heninger et al. in Section 7 of their [Mining Your Ps and Qs](https://factorable.net/weakkeys12.extended.pdf) paper.

On Intel CPUs based on the Ivy Bridge microarchitecture (and future generations), the [built-in PRNG](http://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide) guarantees high entropy and throughput.

On Unix systems, if no reliable syscall is available, you should generally use `/dev/random` or `/dev/urandom`. However on Linux, the former is "blocking", meaning that it won't return any data when it deems that its entropy pool contains insufficient entropy. This feature limits its usability, and is the reason why `/dev/urandom` is more often used. Extracting a random number from `/dev/urandom` can be as simple as

```C
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
  int randint;
  int bytes_read;
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd != -1) {
    bytes_read = read(fd, &randint, sizeof(randint));
    if (bytes_read != sizeof(randint)) {
      fprintf(stderr, "read() failed (%d bytes read)\n", bytes_read);
      return -1;
    }
  }
  else {
    fprintf(stderr, "open() failed\n");
    return -2;
  }
  printf("%08x\n", randint); /* assumes sizeof(int) <= 4 */
  close(fd);
  return 0;
}
```

However, this simple program may not be sufficient for secure randomness generation in your environment: it is safer to perform additional error checks, as found in [LibreSSL](http://libressl.org)'s `getentropy_urandom` function:

```C
static int
getentropy_urandom(void *buf, size_t len)
{
    struct stat st;
    size_t i;
    int fd, cnt, flags;
    int save_errno = errno;

start:

    flags = O_RDONLY;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open("/dev/urandom", flags, 0);
    if (fd == -1) {
        if (errno == EINTR)
            goto start;
        goto nodevrandom;
    }
#ifndef O_CLOEXEC
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

    /* Lightly verify that the device node looks sane */
    if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode)) {
        close(fd);
        goto nodevrandom;
    }
    if (ioctl(fd, RNDGETENTCNT, &cnt) == -1) {
        close(fd);
        goto nodevrandom;
    }
    for (i = 0; i < len; ) {
        size_t wanted = len - i;
        ssize_t ret = read(fd, (char *)buf + i, wanted);

        if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            close(fd);
            goto nodevrandom;
        }
        i += ret;
    }
    close(fd);
    if (gotdata(buf, len) == 0) {
        errno = save_errno;
        return 0;        /* satisfied */
    }
nodevrandom:
    errno = EIO;
    return -1;
}
```

On Windows, when using the Microsoft C compiler, [rand_s](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/rand-s?view=vs-2019) can be used to generate 32 bits of cryptographically secure data:

```C
#include <string.h>

#define _CRT_RAND_S
#include <stdlib.h>

int randombytes(unsigned char *out, size_t outlen) {
    size_t wordlen = sizeof(unsigned int);
    size_t fullwordslen = (outlen / wordlen) * wordlen;
    size_t taillen = outlen - fullwordslen;

    for (size_t i = 0; i < fullwordslen; i += wordlen) {
        unsigned int randword;

        if (rand_s(&randword))
            return -1;

	memcpy(&out[i], &randword, wordlen);
    }

    if (taillen) {
        unsigned int randword;

        if (rand_s(&randword))
            return -1;

        memcpy(&out[fullwordslen], &randword, taillen);
    }

    return 0;
}
```

On recent Windows platforms, [BCryptGenRandom](https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/nf-bcrypt-bcryptgenrandom) (nothing to do with the password hash bcrypt) should be used to generate cryptographically secure data. Its interface is straightforward:

```C
NTSTATUS BCryptGenRandom(
  BCRYPT_ALG_HANDLE hAlgorithm,
  PUCHAR            pbBuffer,
  ULONG             cbBuffer,
  ULONG             dwFlags
);
```

On legacy Windows platforms, [CryptGenRandom](http://msdn.microsoft.com/en-us/library/aa379942.aspx) from the legacy Win32 CryptoAPI provides cryptographically secure pseudorandom bytes. Microsoft provides the following usage example:

```C
#include <stddef.h>
#include <stdint.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")

int randombytes(unsigned char *out, size_t outlen)
{
  static HCRYPTPROV handle = 0; /* only freed when program ends */
  if(!handle) {
    if(!CryptAcquireContext(&handle, 0, 0, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
      return -1;
    }
  }
  while(outlen > 0) {
    const DWORD len = outlen > 1048576UL ? 1048576UL : outlen;
    if(!CryptGenRandom(handle, len, out)) {
      return -2;
    }
    out    += len;
    outlen -= len;
  }
  return 0;
}
```

When targeting Windows XP or above, the CryptoAPI above can be bypassed in favor of [RtlGenRandom](http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694%28v=vs.85%29.aspx):

```C
#include <stdint.h>
#include <stdio.h>

#include <Windows.h>

#define RtlGenRandom SystemFunction036
#if defined(__cplusplus)
extern "C"
#endif
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

#pragma comment(lib, "advapi32.lib")

int main()
{
    uint8_t buffer[32] = { 0 };
    
    if (FALSE == RtlGenRandom(buffer, sizeof buffer))
        return -1;

    for (size_t i = 0; i < sizeof buffer; ++i)
        printf("%02X ", buffer[i]);
    printf("\n");

    return 0;
}
```

## Always typecast shifted values

### Problem

Most cryptographic hash functions, such as SHA-1 and the SHA-2 family, combine
their input bytes into larger "word-sized" integers before processing. In C it
is usually done with the bitwise-left shift operator `<<`.

The left-shift behaviour can be undefined when the shifted value is signed.
Because of the integer promotion rule, unsigned operand like `uint8_t` may be
promoted to `signed int` and trigger the problem.

Here is a simple example where the `combine` function create a 32-bit unsigned
integer given four bytes:

```C
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

uint32_t
combine(uint8_t hh, uint8_t h, uint8_t l, uint8_t ll)
{
	return (hh << 24) | (h << 16) | (l << 8) | ll;
}

int
main(void)
{
	uint32_t combined = combine(/* 128 */0x80, 0xaa, 0xbb, 0xcc);
	printf("combined=0x%x\n", combined);
	printf("INT_MAX=%d\n", INT_MAX);
	return 0;
}
```

When compiled with `clang-4.0 -fsanitize=undefined shift.c` the resulting
program's output is:

```
shift.c:8:13: runtime error: left shift of 128 by 24 places cannot be represented in type 'int'
combined=0x80aabbcc
INT_MAX=2147483647
```

Here `hh`, an `uint8_t`, is promoted to `signed int` in the expression
`hh << 24`. Because `128 * (2 ^ 24) = 2147483648` is greater than `INT_MAX`,
the result cannot be represented as a `signed int` and the behaviour is undefined.

This exact problem can be found in the
[demonstration implementation of SHA-1 in rfc3174](https://tools.ietf.org/html/rfc3174).

### Solution

Explicitly cast the shifted operand to the resulting type. For example, the
`combine` function can be rewritten as:

```C
uint32_t
combine(uint8_t hh, uint8_t h, uint8_t l, uint8_t ll)
{
	return ((uint32_t)hh << 24) | ((uint32_t)h << 16) | ((uint32_t)l << 8) | ll;
}
```

Note that even `l` (shifted from 8 bits) need to be cast, as the minimum
requirement for `INT_MAX` is `32767`.

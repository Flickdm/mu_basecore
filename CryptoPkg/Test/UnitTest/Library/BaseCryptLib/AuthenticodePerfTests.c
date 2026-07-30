/** @file
  Authenticode performance benchmarks: compare a plain AuthenticodeVerify()
  (verify only) against AuthenticodeVerifyEx() (verify AND return the signer
  certificate chain), for both the "root is the trust anchor" and "signer is
  the trust anchor" cases.

  Motivation: AuthenticodeVerifyEx() returns the verified signer chain that
  falls out of the single verification OpenSSL already performs. This suite
  quantifies its incremental cost over AuthenticodeVerify(), confirming the
  chain is nearly free versus a second, independent chain-building pass.

  The generic timing loop and reporting helpers live in the shared harness
  PerfBenchmark.{h,c}; this file supplies only the Authenticode work callbacks
  and the suite table. New per-area benchmarks (e.g. hashing, RSA) follow the
  same shape and register into the same "CryptoPkg.BaseCryptLib.Perf" suite.

  Disabled by default. Define ENABLE_PERF_BENCHMARKS to build and register the
  suite (the application INF does this in [BuildOptions]).

  These benchmarks never assert on timing (hardware / emulator dependent);
  they assert only that each underlying call still succeeds, and always report
  their measurements.

  Copyright (c) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "TestBaseCryptLib.h"

#ifdef ENABLE_PERF_BENCHMARKS

#include "PerfBenchmark.h"

//
// Authenticode sample (SignedData, trust anchor, PE/COFF image hash),
// exported by AuthenticodeTests.c.
//
extern CONST UINT8  *mPerfAuthData;
extern CONST UINTN  mPerfAuthDataSize;
extern CONST UINT8  *mPerfAuthAnchor;
extern CONST UINTN  mPerfAuthAnchorSize;
extern CONST UINT8  *mPerfAuthImageHash;
extern CONST UINTN  mPerfAuthImageHashSize;

//
// Minimum per-call nanoseconds captured by each benchmark, consumed by the
// summary for the ratios.
//
STATIC UINT64  mNsVerify     = 0;
STATIC UINT64  mNsVerifyExRt = 0;
STATIC UINT64  mNsVerifyExSg = 0;

//
// Context for the AuthenticodeVerifyEx work callback: which trust anchor to
// verify against (the rest of the inputs are the fixed sample above).
//
typedef struct {
  CONST UINT8    *Anchor;
  UINTN          AnchorSize;
} VERIFY_EX_CTX;

/**
  One AuthenticodeVerify() call (verify only, no chain returned).
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
WorkAuthenticodeVerify (
  IN VOID  *Context
  )
{
  BOOLEAN  Ok;

  Ok = AuthenticodeVerify (
         mPerfAuthData,
         mPerfAuthDataSize,
         mPerfAuthAnchor,
         mPerfAuthAnchorSize,
         mPerfAuthImageHash,
         mPerfAuthImageHashSize
         );
  UT_ASSERT_TRUE (Ok);
  return UNIT_TEST_PASSED;
}

/**
  One AuthenticodeVerifyEx() call against Context->Anchor, freeing the
  returned chain each iteration.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
WorkAuthenticodeVerifyEx (
  IN VOID  *Context
  )
{
  VERIFY_EX_CTX  *Ctx;
  EFI_STATUS     Status;
  UINT8          *Chain;
  UINTN          ChainSize;

  Ctx       = (VERIFY_EX_CTX *)Context;
  Chain     = NULL;
  ChainSize = 0;
  Status    = AuthenticodeVerifyEx (
                mPerfAuthData,
                mPerfAuthDataSize,
                Ctx->Anchor,
                Ctx->AnchorSize,
                mPerfAuthImageHash,
                mPerfAuthImageHashSize,
                &Chain,
                &ChainSize
                );
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Chain);
  FreePool (Chain);
  return UNIT_TEST_PASSED;
}

/**
  Baseline: AuthenticodeVerify() (verify only, no chain).
**/
UNIT_TEST_STATUS
EFIAPI
BenchAuthenticodeVerify (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UNIT_TEST_STATUS  TestStatus;
  UINT64            MeanNs;

  MeanNs     = 0;
  TestStatus = PerfMeasure (WorkAuthenticodeVerify, NULL, &mNsVerify, &MeanNs);
  if (TestStatus == UNIT_TEST_PASSED) {
    PerfEmit ("AuthenticodeVerify (verify only)", mNsVerify, MeanNs);
  }

  return TestStatus;
}

/**
  AuthenticodeVerifyEx with the root as the trust anchor: one call that
  verifies the image AND returns the full signer..root chain. Should cost
  about the same as AuthenticodeVerify alone (the chain falls out of the
  verify OpenSSL already did).
**/
UNIT_TEST_STATUS
EFIAPI
BenchAuthenticodeVerifyExRoot (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VERIFY_EX_CTX     Ctx;
  UNIT_TEST_STATUS  TestStatus;
  UINT64            MeanNs;

  Ctx.Anchor     = mPerfAuthAnchor;
  Ctx.AnchorSize = mPerfAuthAnchorSize;
  MeanNs         = 0;
  TestStatus     = PerfMeasure (WorkAuthenticodeVerifyEx, &Ctx, &mNsVerifyExRt, &MeanNs);
  if (TestStatus == UNIT_TEST_PASSED) {
    PerfEmit ("AuthenticodeVerifyEx (verify + chain)", mNsVerifyExRt, MeanNs);
  }

  return TestStatus;
}

/**
  AuthenticodeVerifyEx with the signer itself as the trust anchor: the trust
  path is a single certificate (the chain is trimmed at the anchor). Exposes
  the cost of the trim path relative to the full-chain case.
**/
UNIT_TEST_STATUS
EFIAPI
BenchAuthenticodeVerifyExSignerIsAnchor (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS        Status;
  UINT8             *Chain;
  UINTN             ChainSize;
  UINT8             *SignerCert;
  UINT32            SignerLen;
  VERIFY_EX_CTX     Ctx;
  UINT64            MeanNs;
  UNIT_TEST_STATUS  TestStatus;

  //
  // Obtain the signer (leaf) certificate from a normal (root-anchored)
  // verification: it is entry 0 of the returned chain.
  //
  Chain     = NULL;
  ChainSize = 0;
  Status    = AuthenticodeVerifyEx (
                mPerfAuthData,
                mPerfAuthDataSize,
                mPerfAuthAnchor,
                mPerfAuthAnchorSize,
                mPerfAuthImageHash,
                mPerfAuthImageHashSize,
                &Chain,
                &ChainSize
                );
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_NOT_NULL (Chain);
  UT_ASSERT_TRUE (1 + sizeof (UINT32) <= ChainSize);

  SignerLen = ReadUnaligned32 ((CONST UINT32 *)(Chain + 1));
  UT_ASSERT_TRUE ((UINTN)(1 + sizeof (UINT32) + SignerLen) <= ChainSize);
  SignerCert = AllocatePool (SignerLen);
  UT_ASSERT_NOT_NULL (SignerCert);
  CopyMem (SignerCert, Chain + 1 + sizeof (UINT32), SignerLen);
  FreePool (Chain);

  Ctx.Anchor     = SignerCert;
  Ctx.AnchorSize = SignerLen;
  MeanNs         = 0;
  TestStatus     = PerfMeasure (WorkAuthenticodeVerifyEx, &Ctx, &mNsVerifyExSg, &MeanNs);
  FreePool (SignerCert);
  if (TestStatus == UNIT_TEST_PASSED) {
    PerfEmit ("AuthenticodeVerifyEx (signer==anchor)", mNsVerifyExSg, MeanNs);
  }

  return TestStatus;
}

/**
  Summary: report each AuthenticodeVerifyEx case as a percentage of a full
  AuthenticodeVerify(), quantifying how nearly free the returned chain is.
  All ratios use the minimum (best-case) per-call times.
**/
UNIT_TEST_STATUS
EFIAPI
BenchSummary (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  DEBUG ((DEBUG_ERROR, "PERF: ===== SUMMARY (min-of-%d) =====\n", PERF_ITERATIONS));
  PerfRatio ("VerifyEx root   (verify + chain)", "AuthenticodeVerify", mNsVerifyExRt, mNsVerify);
  PerfRatio ("VerifyEx signer (single-cert)", "AuthenticodeVerify", mNsVerifyExSg, mNsVerify);
  DEBUG ((DEBUG_ERROR, "PERF: ===================================\n"));
  return UNIT_TEST_PASSED;
}

TEST_DESC  mAuthenticodePerfTest[] = {
  //
  // -----Description---------------------------Class--------------------------Function-------------------------------Pre--Post-Context
  //
  { "AuthenticodeVerify baseline",          "CryptoPkg.BaseCryptLib.Perf", BenchAuthenticodeVerify,                 NULL, NULL, NULL },
  { "AuthenticodeVerifyEx (root anchor)",   "CryptoPkg.BaseCryptLib.Perf", BenchAuthenticodeVerifyExRoot,           NULL, NULL, NULL },
  { "AuthenticodeVerifyEx (signer anchor)", "CryptoPkg.BaseCryptLib.Perf", BenchAuthenticodeVerifyExSignerIsAnchor, NULL, NULL, NULL },
  { "Summary and ratios",                   "CryptoPkg.BaseCryptLib.Perf", BenchSummary,                            NULL, NULL, NULL },
};

UINTN  mAuthenticodePerfTestNum = ARRAY_SIZE (mAuthenticodePerfTest);

#endif // ENABLE_PERF_BENCHMARKS

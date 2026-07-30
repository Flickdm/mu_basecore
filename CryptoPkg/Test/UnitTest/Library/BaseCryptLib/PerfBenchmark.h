/** @file
  Shared timing harness for opt-in BaseCryptLib performance benchmarks.

  Provides a wrap-aware performance-counter timing loop (PerfMeasure) plus
  reporting helpers (PerfEmit / PerfRatio), so each area's benchmark file
  (e.g. AuthenticodePerfTests.c) supplies only the per-iteration work and its
  labels. Reusable across benchmark files that register into the shared
  "CryptoPkg.BaseCryptLib.Perf" suite.

  Compiled only when ENABLE_PERF_BENCHMARKS is defined (the application INF
  sets it in [BuildOptions]); otherwise this header is empty.

  Copyright (c) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef PERF_BENCHMARK_H_
#define PERF_BENCHMARK_H_

#ifdef ENABLE_PERF_BENCHMARKS

#include <Uefi.h>
#include <Library/UnitTestLib.h>

//
// Default timed iterations per benchmark. A benchmark file may #define
// PERF_ITERATIONS before including this header to override it. Each crypto
// call crosses into MM and, in a DEBUG/emulated build, costs hundreds of
// milliseconds; the counter still resolves a single call to sub-microsecond
// precision, so a handful of iterations finds a stable minimum while keeping
// the run short.
//
#ifndef PERF_ITERATIONS
#define PERF_ITERATIONS  8
#endif

/**
  Per-iteration work callback: perform exactly one instance of the operation
  being benchmarked (plus any per-call setup/teardown, such as freeing an
  output buffer) and assert that it succeeded with the UT_ASSERT_* macros.

  Keep non-operation overhead minimal: PerfMeasure() times the whole callback.

  @param[in]  Context  Caller-provided context (may be NULL).

  @retval UNIT_TEST_PASSED  The operation succeeded.
  @retval other             A UT_ASSERT_* macro failed.
**/
typedef
UNIT_TEST_STATUS
(EFIAPI *PERF_WORK_FN)(
  IN VOID  *Context
  );

/**
  Run Work once untimed (warm-up: page-in, first-touch allocations, MM
  connect), then PERF_ITERATIONS times under the performance counter,
  reporting the minimum and mean per-call time in nanoseconds. Deltas are
  computed wrap-aware, so a single wrap of a narrow (e.g. 24-bit) counter is
  tolerated as long as each call stays under the counter period.

  @param[in]   Work     Per-iteration work callback.
  @param[in]   Context  Passed to Work (may be NULL).
  @param[out]  MinNs    Minimum per-call time, nanoseconds.
  @param[out]  MeanNs   Mean per-call time, nanoseconds.

  @return  The first non-pass status returned by Work, or UNIT_TEST_PASSED if
           every call succeeded.
**/
UNIT_TEST_STATUS
PerfMeasure (
  IN  PERF_WORK_FN  Work,
  IN  VOID          *Context,
  OUT UINT64        *MinNs,
  OUT UINT64        *MeanNs
  );

/**
  Emit a "min / mean microseconds per call" measurement line to both the
  debug log (DEBUG_ERROR, so it prints regardless of platform debug level)
  and the unit-test log.

  @param[in]  Label   Human-readable benchmark name.
  @param[in]  MinNs   Best-case (minimum) per-call time, nanoseconds.
  @param[in]  MeanNs  Mean per-call time, nanoseconds.
**/
VOID
PerfEmit (
  IN CONST CHAR8  *Label,
  IN UINT64       MinNs,
  IN UINT64       MeanNs
  );

/**
  Emit a "Value is N% of Baseline" ratio line to both logs, using the
  (minimum) nanosecond figures. Does nothing if BaselineNs is zero.

  @param[in]  Label          Human-readable name of the measured value.
  @param[in]  BaselineLabel  Human-readable name of the baseline.
  @param[in]  ValueNs        Measured value, nanoseconds.
  @param[in]  BaselineNs     Baseline to divide by, nanoseconds.
**/
VOID
PerfRatio (
  IN CONST CHAR8  *Label,
  IN CONST CHAR8  *BaselineLabel,
  IN UINT64       ValueNs,
  IN UINT64       BaselineNs
  );

#endif // ENABLE_PERF_BENCHMARKS
#endif // PERF_BENCHMARK_H_

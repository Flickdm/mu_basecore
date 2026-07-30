/** @file
  Shared timing harness implementation for opt-in BaseCryptLib performance
  benchmarks. See PerfBenchmark.h for the API contract.

  Compiled only when ENABLE_PERF_BENCHMARKS is defined; otherwise this file is
  an empty translation unit.

  Copyright (c) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "PerfBenchmark.h"

#ifdef ENABLE_PERF_BENCHMARKS

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/TimerLib.h>

//
// Cached performance-counter range/direction for wrap-aware delta math.
//
STATIC UINT64   mCounterStart       = 0;
STATIC UINT64   mCounterEnd         = 0;
STATIC BOOLEAN  mCounterCountsUp    = TRUE;
STATIC BOOLEAN  mCounterInitialized = FALSE;

/**
  Cache the performance-counter range/direction once (idempotent).
**/
STATIC
VOID
PerfInitCounter (
  VOID
  )
{
  if (!mCounterInitialized) {
    GetPerformanceCounterProperties (&mCounterStart, &mCounterEnd);
    mCounterCountsUp    = (BOOLEAN)(mCounterEnd >= mCounterStart);
    mCounterInitialized = TRUE;
  }
}

/**
  Wrap-aware elapsed ticks between an earlier read (First) and a later read
  (Second). Handles a single wrap of the (possibly 24-bit) counter in either
  direction; callers keep each measured interval shorter than the counter
  period so at most one wrap can occur.

  @param[in]  First   Counter value read before the work.
  @param[in]  Second  Counter value read after the work.

  @return  Elapsed ticks.
**/
STATIC
UINT64
ElapsedTicks (
  IN UINT64  First,
  IN UINT64  Second
  )
{
  if (mCounterCountsUp) {
    if (Second >= First) {
      return Second - First;
    }

    return (mCounterEnd - First) + (Second - mCounterStart) + 1;
  } else {
    if (First >= Second) {
      return First - Second;
    }

    return (First - mCounterEnd) + (mCounterStart - Second) + 1;
  }
}

/**
  Run Work once untimed, then PERF_ITERATIONS timed. See PerfBenchmark.h.
**/
UNIT_TEST_STATUS
PerfMeasure (
  IN  PERF_WORK_FN  Work,
  IN  VOID          *Context,
  OUT UINT64        *MinNs,
  OUT UINT64        *MeanNs
  )
{
  UNIT_TEST_STATUS  Status;
  UINT64            Start;
  UINT64            End;
  UINT64            Delta;
  UINT64            MinTicks;
  UINT64            TotalTicks;
  UINTN             Index;

  PerfInitCounter ();

  //
  // Untimed warm-up (page-in, first-touch allocations, MM connect). Also
  // surfaces a failing operation before the timed loop.
  //
  Status = Work (Context);
  if (Status != UNIT_TEST_PASSED) {
    return Status;
  }

  MinTicks   = MAX_UINT64;
  TotalTicks = 0;
  for (Index = 0; Index < PERF_ITERATIONS; Index++) {
    Start  = GetPerformanceCounter ();
    Status = Work (Context);
    End    = GetPerformanceCounter ();

    if (Status != UNIT_TEST_PASSED) {
      return Status;
    }

    Delta       = ElapsedTicks (Start, End);
    TotalTicks += Delta;
    if (Delta < MinTicks) {
      MinTicks = Delta;
    }
  }

  *MinNs  = GetTimeInNanoSecond (MinTicks);
  *MeanNs = DivU64x32 (GetTimeInNanoSecond (TotalTicks), (UINT32)PERF_ITERATIONS);
  return UNIT_TEST_PASSED;
}

/**
  Emit a "min / mean microseconds per call" line. See PerfBenchmark.h.
**/
VOID
PerfEmit (
  IN CONST CHAR8  *Label,
  IN UINT64       MinNs,
  IN UINT64       MeanNs
  )
{
  UINT64  MinUs;
  UINT64  MeanUs;

  MinUs  = DivU64x32 (MinNs, 1000);
  MeanUs = DivU64x32 (MeanNs, 1000);

  DEBUG ((DEBUG_ERROR, "PERF: %-40a min %7Lu us  mean %7Lu us/call\n", Label, MinUs, MeanUs));
  UT_LOG_INFO ("%a: min %Lu us, mean %Lu us/call\n", Label, MinUs, MeanUs);
}

/**
  Emit a "Value is N% of Baseline" ratio line. See PerfBenchmark.h.
**/
VOID
PerfRatio (
  IN CONST CHAR8  *Label,
  IN CONST CHAR8  *BaselineLabel,
  IN UINT64       ValueNs,
  IN UINT64       BaselineNs
  )
{
  UINT64  Pct;

  if (BaselineNs == 0) {
    return;
  }

  Pct = DivU64x64Remainder (MultU64x32 (ValueNs, 100), BaselineNs, NULL);
  DEBUG ((DEBUG_ERROR, "PERF:   %-38a %4Lu %% of %a\n", Label, Pct, BaselineLabel));
  UT_LOG_INFO ("%a: %Lu%% of %a\n", Label, Pct, BaselineLabel);
}

#endif // ENABLE_PERF_BENCHMARKS

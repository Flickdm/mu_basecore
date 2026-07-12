/** @file
  Public LZMA decompression interfaces.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __LZMA_DECOMPRESS_LIB_H__
#define __LZMA_DECOMPRESS_LIB_H__

#include <Base.h>

RETURN_STATUS
EFIAPI
LzmaUefiDecompressGetInfo (
  IN  CONST VOID  *Source,
  IN  UINT32      SourceSize,
  OUT UINT32      *DestinationSize,
  OUT UINT32      *ScratchSize
  );

RETURN_STATUS
EFIAPI
LzmaUefiDecompress (
  IN CONST VOID  *Source,
  IN UINTN       SourceSize,
  IN OUT VOID    *Destination,
  IN OUT VOID    *Scratch
  );

#endif

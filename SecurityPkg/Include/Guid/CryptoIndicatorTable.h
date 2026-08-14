/** @file
  Definitions for the EFI Crypto Indicator Table (ECIT).

  The ECIT declares, per UEFI feature, which cryptographic algorithms the
  platform firmware supports, so UEFI applications and the OS can select a
  compatible algorithm. It is published as an EFI_CONFIGURATION_TABLE and, on
  ACPI-capable firmware, as an ACPI table backed by the same memory (its
  leading fields form a common ACPI SDT header).

  Each entry pairs a feature GUID with an opaque, feature-typed data block. The
  collector never interprets the data; it only accumulates entries and publishes
  the table. This header defines the full entry layout (common header + data) for
  each well-known feature; a vendor defines its own entry type alongside its
  feature GUID.

  Data-block conventions: image-verification, authenticated-variable, and
  firmware-update features carry a NUL-terminated CSV of algorithm OIDs (from
  BaseCryptLib GetCryptoOpCapability()); Secure Boot authorization, servicing, and
  revocation features carry an array of EFI_SIGNATURE_LIST type GUIDs.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef CRYPTO_INDICATOR_TABLE_H_
#define CRYPTO_INDICATOR_TABLE_H_

//
// EFI_CONFIGURATION_TABLE GUID for the ECIT.
// {1768b8b1-1605-401a-bc49-d612d2b98c4e}
//
#define EFI_CRYPTO_INDICATOR_TABLE_GUID \
  { 0x1768b8b1, 0x1605, 0x401a, { 0xbc, 0x49, 0xd6, 0x12, 0xd2, 0xb9, 0x8c, 0x4e } }

//
// ACPI-style signature ("ECIT") and the current table/entry version.
//
#define EFI_CRYPTO_INDICATOR_TABLE_SIGNATURE  SIGNATURE_32 ('E', 'C', 'I', 'T')
#define EFI_CRYPTO_INDICATOR_TABLE_VERSION    1

// Start of packed structure definitions.
#pragma pack(1)

///
/// ECIT header. The leading fields mirror the common ACPI SDT header so the
/// exact same memory can be published as both an EFI_CONFIGURATION_TABLE and an
/// ACPI table.
///
typedef struct {
  UINT8     Signature[4];      ///< "ECIT".
  UINT32    Length;            ///< Length of the entire table (header + all entries), in bytes.
  UINT8     Version;           ///< EFI_CRYPTO_INDICATOR_TABLE_VERSION.
  UINT8     Checksum;          ///< 8-bit checksum: the whole table must sum to zero.
  UINT8     OemId[6];          ///< ACPI OEM ID.
  UINT8     OemTableId[8];     ///< ACPI OEM Table ID.
  UINT32    OemRevision;       ///< ACPI OEM revision.
  UINT32    CreatorId;         ///< ACPI creator ID.
  UINT32    CreatorRevision;   ///< ACPI creator revision.
  //
  // ECIT-specific fields.
  //
  UINT8     NumberOfEntries;   ///< Number of EFI_CRYPTO_INDICATOR_ENTRY records that follow.
  UINT8     Reserved[3];       ///< Reserved for future use; must be zero.
  // EFI_CRYPTO_INDICATOR_ENTRY  Entries[];
} EFI_CRYPTO_INDICATOR_TABLE;

///
/// Common header shared by every ECIT entry. It is followed by EntryLength -
/// sizeof (EFI_CRYPTO_INDICATOR_ENTRY) bytes of feature-typed data, opaque to
/// the collector and interpreted by FeatureIdentifier. Each well-known feature
/// below wraps this header in a full entry type that names its data.
///
typedef struct {
  EFI_GUID    FeatureIdentifier;  ///< The feature this entry describes.
  UINT16      EntryLength;        ///< sizeof (EFI_CRYPTO_INDICATOR_ENTRY) + sizeof (feature data).
  UINT8       Reserved[6];        ///< Reserved for future use; must be zero.
  // UINT8    EntryData[];
} EFI_CRYPTO_INDICATOR_ENTRY;

//
// ============================================================================
// Well-known feature identifiers and their entry types.
//
// Every EFI_CIE_*_ENTRY below is a full entry: the common
// EFI_CRYPTO_INDICATOR_ENTRY header followed by the feature's data, which is one
// of two shapes:
//   - SupportedAlgorithmOids[] - a NUL-terminated, comma-separated CHAR8 list of
//     algorithm OIDs, produced at runtime by BaseCryptLib GetCryptoOpCapability().
//   - SignatureListTypes[]     - an array of EFI_SIGNATURE_LIST type GUIDs (the
//     EFI_CERT_* GUIDs from MdePkg <Guid/ImageAuthentication.h>).
//
// A variable-length field's element count is
// (EntryLength - sizeof (EFI_CRYPTO_INDICATOR_ENTRY)) / element size. Vendors
// define their own feature GUID and matching entry type for custom features.
// ============================================================================
//

///
/// Secure Boot image verification (Authenticode): OIDs of the signature
/// algorithms accepted when verifying signed images.
/// {08324cfc-efe6-4211-a858-d4cac8915aef}
///
#define EFI_ECIT_FEATURE_IMAGE_VERIFICATION_GUID \
  { 0x08324cfc, 0xefe6, 0x4211, { 0xa8, 0x58, 0xd4, 0xca, 0xc8, 0x91, 0x5a, 0xef } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  CHAR8                         SupportedAlgorithmOids[];   ///< Algorithm OIDs (see above).
} EFI_CIE_IMAGE_VERIFICATION_ENTRY;

///
/// Secure Boot Authorization (db): EFI_SIGNATURE_LIST types matched against a
/// code-signing authority during image verification.
/// {335f880f-180f-43d9-8ed9-ce584ed9b6f0}
///
#define EFI_ECIT_FEATURE_SECURE_BOOT_AUTHORIZATION_GUID \
  { 0x335f880f, 0x180f, 0x43d9, { 0x8e, 0xd9, 0xce, 0x58, 0x4e, 0xd9, 0xb6, 0xf0 } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  EFI_GUID                      SignatureListTypes[];   ///< Signature-list type GUIDs (see above).
} EFI_CIE_SECURE_BOOT_AUTHORIZATION_ENTRY;

///
/// Secure Boot Servicing Authorization (PK/KEK): EFI_SIGNATURE_LIST types
/// accepted when authorizing a signed db/dbx update.
/// {304b3849-4906-40ea-8ade-751d6da7d4f9}
///
#define EFI_ECIT_FEATURE_SECURE_BOOT_SERVICING_AUTHORIZATION_GUID \
  { 0x304b3849, 0x4906, 0x40ea, { 0x8a, 0xde, 0x75, 0x1d, 0x6d, 0xa7, 0xd4, 0xf9 } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  EFI_GUID                      SignatureListTypes[];   ///< Signature-list type GUIDs (see above).
} EFI_CIE_SECURE_BOOT_SERVICING_AUTHORIZATION_ENTRY;

///
/// Secure Boot Image Revocation (dbx): EFI_SIGNATURE_LIST types evaluated for
/// revocation.
/// {02913331-2f71-43db-8277-7be88ecc651c}
///
#define EFI_ECIT_FEATURE_IMAGE_REVOCATION_GUID \
  { 0x02913331, 0x2f71, 0x43db, { 0x82, 0x77, 0x7b, 0xe8, 0x8e, 0xcc, 0x65, 0x1c } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  EFI_GUID                      SignatureListTypes[];   ///< Signature-list type GUIDs (see above).
} EFI_CIE_IMAGE_REVOCATION_ENTRY;

///
/// Authenticated Variable signed update: OIDs of the signature algorithms
/// accepted for authenticated-variable updates.
/// {03092d2c-9a52-4c5c-8bf5-eaf04f45229d}
///
#define EFI_ECIT_FEATURE_AUTHENTICATED_VARIABLE_GUID \
  { 0x03092d2c, 0x9a52, 0x4c5c, { 0x8b, 0xf5, 0xea, 0xf0, 0x4f, 0x45, 0x22, 0x9d } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  CHAR8                         SupportedAlgorithmOids[];   ///< Algorithm OIDs (see above).
} EFI_CIE_AUTHENTICATED_VARIABLE_ENTRY;

///
/// System Firmware Update: OIDs of the supported signature algorithms.
/// {8417f337-8e42-4657-aeae-9b21a4b90258}
///
#define EFI_ECIT_FEATURE_SYSTEM_FIRMWARE_UPDATE_GUID \
  { 0x8417f337, 0x8e42, 0x4657, { 0xae, 0xae, 0x9b, 0x21, 0xa4, 0xb9, 0x02, 0x58 } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  CHAR8                         SupportedAlgorithmOids[];   ///< Algorithm OIDs (see above).
} EFI_CIE_SYSTEM_FIRMWARE_UPDATE_ENTRY;

///
/// ESRT device firmware update: the target ESRT GUID plus OIDs of the supported
/// signature algorithms (System Firmware Update scoped to one ESRT entry).
/// {41c7bd17-6bd4-4df5-aaad-8987164ead4c}
///
#define EFI_ECIT_FEATURE_ESRT_FIRMWARE_UPDATE_GUID \
  { 0x41c7bd17, 0x6bd4, 0x4df5, { 0xaa, 0xad, 0x89, 0x87, 0x16, 0x4e, 0xad, 0x4c } }

typedef struct {
  EFI_CRYPTO_INDICATOR_ENTRY    Header;
  EFI_GUID                      EsrtGuid;                   ///< ESRT entry this record applies to.
  CHAR8                         SupportedAlgorithmOids[];   ///< Algorithm OIDs (see above).
} EFI_CIE_ESRT_FIRMWARE_UPDATE_ENTRY;

// End of packed structure definitions.
#pragma pack()

extern EFI_GUID  gEfiCryptoIndicatorTableGuid;
extern EFI_GUID  gEfiEcitFeatureImageVerificationGuid;
extern EFI_GUID  gEfiEcitFeatureSecureBootAuthorizationGuid;
extern EFI_GUID  gEfiEcitFeatureSecureBootServicingAuthorizationGuid;
extern EFI_GUID  gEfiEcitFeatureImageRevocationGuid;
extern EFI_GUID  gEfiEcitFeatureAuthenticatedVariableGuid;
extern EFI_GUID  gEfiEcitFeatureSystemFirmwareUpdateGuid;
extern EFI_GUID  gEfiEcitFeatureEsrtFirmwareUpdateGuid;

#endif // CRYPTO_INDICATOR_TABLE_H_

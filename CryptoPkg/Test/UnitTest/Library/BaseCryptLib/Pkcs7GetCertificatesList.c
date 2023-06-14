/** @file
  Test for Pkcs7GetSigners

  One implementation of Pkcs7GetSigners may be found here CryptoPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c

// TODO add Microsoft License
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"
#include "Pkcs7GetCertificatesList.h"
#include <openssl/x509.h>

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesList (
  UINT8 *Signature,
  UINTN SignatureSize,
  CHAR8 *ExpectedCertCommonName
  ) 
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;
  BOOLEAN Result = FALSE;

  UINT8 *SignerCertChainPtr = NULL;
  UINTN SignerCertChainSize = 0;
  UINT8 *UnchainCertsPtr = NULL;
  UINTN UnchainCertsSize = 0;
  CHAR8 CertCommonName[128];
  UINTN CertCommonNameSize = sizeof (CertCommonName);
  UINT8 *TrustedCert = NULL;
  UINTN TrustedCertSize = 0;

  Result = Pkcs7GetCertificatesList(
    Signature,
    SignatureSize,
    &SignerCertChainPtr,
    &SignerCertChainSize,
    &UnchainCertsPtr,
    &UnchainCertsSize
    );

  UT_ASSERT_TRUE(Result);
  UT_ASSERT_NOT_NULL(SignerCertChainPtr);

  Result = Pkcs7GetCertificateByIndex(
    SignerCertChainPtr,
    SignerCertChainSize,
    0,
    &TrustedCert,
    &TrustedCertSize
    );

  UT_ASSERT_TRUE(Result);
  UT_ASSERT_NOT_NULL(TrustedCert);

  //
  // Get SignerCert CommonName
  //
  RETURN_STATUS Status2 = X509GetCommonName (TrustedCert, TrustedCertSize, CertCommonName, &CertCommonNameSize);
  UT_ASSERT_EQUAL (Status2, RETURN_SUCCESS);

  // Compare CertCommonName to expected value
  UT_ASSERT_MEM_EQUAL (CertCommonName, ExpectedCertCommonName, CertCommonNameSize);

  Status = UNIT_TEST_PASSED;

  if (SignerCertChainPtr != NULL) {
    Pkcs7FreeSigners (SignerCertChainPtr);
  }

  if (UnchainCertsPtr != NULL) {
    Pkcs7FreeSigners (UnchainCertsPtr);
  }

  return Status;
}

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesListRunner(
  IN UNIT_TEST_CONTEXT           Context
  )
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;

  Status = TestPkcs7GetCertificatesList(m1AdditionalCertificatesMockVar, sizeof m1AdditionalCertificatesMockVar, m1CommonName);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  Status = TestPkcs7GetCertificatesList(m2AdditionalCertificatesMockVar, sizeof m2AdditionalCertificatesMockVar, m2CommonName);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  Status = TestPkcs7GetCertificatesList(m3AdditionalCertificatesMockVar, sizeof m3AdditionalCertificatesMockVar, m3CommonName);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  return Status;
}

TEST_DESC mPkcs7GetCertificatesListTest[] = {
  //
  // -----Description--------------------------------Class--------------------Function----------------Pre---Post--Context
  //
  { "TestPkcs7GetCertificatesList()", "CryptoPkg.BaseCryptLib.TestPkcs7GetCertificatesList", TestPkcs7GetCertificatesListRunner, NULL, NULL, NULL },
};

UINTN  mPkcs7GetCertificatesListTestNum = ARRAY_SIZE (mPkcs7GetCertificatesListTest);

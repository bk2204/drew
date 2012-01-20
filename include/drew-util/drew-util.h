#ifndef DREW_UTIL_DREW_UTIL_H
#define DREW_UTIL_DREW_UTIL_H

/* An incorrect ASN.1 tag was found. */
#define DREW_UTIL_ERR_TAG_MISMATCH			0x50001
/* An incorrect ASN.1 class was found. */
#define DREW_UTIL_ERR_CLASS_MISMATCH		0x50002
/* An unsupported version of some structure was encountered. */
#define DREW_UTIL_ERR_UNSUPPORTED_VERSION	0x50003
/* A corrupt or invalid integral value was encountered. */
#define DREW_UTIL_ERR_BAD_INTEGER			0x50004
/* A corrupt or invalid time value was encountered. */
#define DREW_UTIL_ERR_BAD_TIME				0x50005
/* A corrupt or invalid sequence was encountered. */
#define DREW_UTIL_ERR_BAD_SEQUENCE			0x50005
/* An incorrect ASN.1 constructed bit was found. */
#define DREW_UTIL_ERR_CONSTRUCTED_MISMATCH	0x50006
/* A corrupt or invalid string was encountered. */
#define DREW_UTIL_ERR_BAD_STRING			0x50007

#endif

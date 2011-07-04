#ifndef DREW_OPGP_H
#define DREW_OPGP_H

// The header information is corrupt.
#define DREW_OPGP_ERR_INVALID_HEADER	0x20001
#define DREW_OPGP_ERR_INVALID			0x20001
// More data is needed to continue.
#define DREW_OPGP_ERR_MORE_DATA			0x20002
// That functionality is not implemented.
#define DREW_OPGP_ERR_NOT_IMPL			0x20003
// A given algorithm is needed but has not been loaded.
#define DREW_OPGP_ERR_NO_SUCH_ALGO		0x20004

// The data is not in compliance with the versions specified.
#define DREW_OPGP_ERR_WRONG_VERSION		0x20101

#endif

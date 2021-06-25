#pragma once

#define NTFS_EX_ATTR_LXUID "$LXUID"
#define NTFS_EX_ATTR_LXGID "$LXGID"
#define NTFS_EX_ATTR_LXMOD "$LXMOD"
#define NTFS_EX_ATTR_LXDEV "$LXDEV"

#ifndef IO_REPARSE_TAG_LX_SYMLINK
#define IO_REPARSE_TAG_LX_SYMLINK (0xA000001D)
#define IO_REPARSE_TAG_LX_FIFO    (0x80000024)
#define IO_REPARSE_TAG_LX_CHR     (0x80000025)
#define IO_REPARSE_TAG_LX_BLK     (0x80000026)
#endif // !IO_REPARSE_TAG_LX_SYMLINK

#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX    (0x80000023)
#endif // !IO_REPARSE_TAG_AF_UNIX

void PrintLxuid(PFILE_FULL_EA_INFORMATION buffer);
void PrintLxgid(PFILE_FULL_EA_INFORMATION buffer);
void PrintLxmod(PFILE_FULL_EA_INFORMATION buffer);
void PrintLxdev(PFILE_FULL_EA_INFORMATION buffer);

void PrintReparseTag(ULONG reparseTag);

NTSTATUS ReadLxSymlink(HANDLE fileHandle, CHAR* buf, DWORD bufSize, CHAR** linkName);

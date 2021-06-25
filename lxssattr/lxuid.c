#include "main.h"

void PrintLxuid(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG st_uid = 0;
    RtlCopyMemory(&st_uid, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    _tprintf(_T("%S:                    Uid: (%lu / %s)\n"),
        NTFS_EX_ATTR_LXUID, st_uid, GetUserNameFromUid(st_uid)
    );
}

void PrintLxgid(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG st_gid = 0;
    RtlCopyMemory(&st_gid, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    _tprintf(_T("%S:                    Gid: (%lu / %s)\n"),
        NTFS_EX_ATTR_LXGID, st_gid, GetGroupNameFromGid(st_gid)
    );
}

void PrintLxmod(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG st_mode = 0;
    RtlCopyMemory(&st_mode, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    _tprintf(_T("%S:                    Mode: %o (octal) Access: (0%o) %hs\n"),
        NTFS_EX_ATTR_LXMOD, st_mode, st_mode & (S_IRWXU | S_IRWXG | S_IRWXO), lsperms(st_mode)
    );
}

void PrintLxdev(PFILE_FULL_EA_INFORMATION buffer)
{
    ULONG type_major = 0;
    RtlCopyMemory(&type_major, buffer->EaName + (buffer->EaNameLength + 1), sizeof(ULONG));

    ULONG type_minor = 0;
    RtlCopyMemory(&type_minor, buffer->EaName + (buffer->EaNameLength + 1) + sizeof(ULONG), sizeof(ULONG));

    _tprintf(_T("%S:                    Device type: %#lx, %#lx\n"),
        NTFS_EX_ATTR_LXDEV, type_major, type_minor
    );
}

void PrintReparseTag(ULONG reparseTag)
{
    PSTR tag_type = NULL;
    switch (reparseTag) {
    case IO_REPARSE_TAG_LX_SYMLINK: tag_type = "SYMLINK"; break;
    case IO_REPARSE_TAG_LX_FIFO: tag_type = "FIFO"; break;
    case IO_REPARSE_TAG_LX_CHR: tag_type = "CHR"; break;
    case IO_REPARSE_TAG_LX_BLK: tag_type = "BLK"; break;
    case IO_REPARSE_TAG_AF_UNIX: tag_type = "AF_UNIX"; break;
    default: tag_type = "UNKNOWN"; break;
    }
    _tprintf(_T("WslFS reparse point:       %S\n"), tag_type);
}


NTSTATUS ReadLxSymlink(HANDLE fileHandle, CHAR* buf, DWORD bufSize, CHAR** linkName)
{
    ULONG junk = 0;
    if (!DeviceIoControl(fileHandle, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, bufSize, &junk, NULL))
    {
        DWORD errorno = GetLastError();
        _tprintf(_T("[ERROR] DeviceIoControl: 0x%x, Cannot read symlink from reparse_point data\n"), errorno);
        return errorno;
    }

    PREPARSE_GUID_DATA_BUFFER reparse_buf = (PREPARSE_GUID_DATA_BUFFER)buf;
    CHAR* reparse_data = (CHAR*)&reparse_buf->ReparseGuid;
    if (reparse_buf->ReparseDataLength > 4 && reparse_buf->ReparseGuid.Data1 == 0x02)
    {
        reparse_data[reparse_buf->ReparseDataLength] = '\0';
        *linkName = reparse_data + 4;
    }
    else
    {
        _tprintf(_T("[ERROR] Invalid reparse_point data, Cannot read symlink from reparse_point data\n"));
        return -1;
    }

    return 0;
}
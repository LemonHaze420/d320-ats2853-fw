# d320-ats2853 firmware extraction

### Prerequisites
- Python 3.10+

### Usage

To extract a firmware sample:

```
extract.py <fw> <output dir>
```

`zephyr.bin` contains the main MIPS code


### Info

```c

#pragma pack(push, 1)

typedef struct {
    char     magic[8];          /* "ACTTEST0" */
    uint32_t unknown_08;
    uint32_t file_count;
    uint32_t unknown_10;
    uint32_t file_length;
    uint32_t payload_crc32;     /* CRC32(file[0x200:]) */
    uint32_t unknown_1c;
} ActtestHeader;                /* 0x20 bytes */

typedef struct {
    char     name[16];
    uint32_t offset;
    uint32_t size;
    uint32_t unknown;
    uint32_t crc32;
} ActtestEntry;                 /* 0x20 bytes; starts at file offset 0x20 */

typedef struct {
    char    outer_magic[12];    /* "100TMFWFSTCA" */
    uint8_t unknown_0c[4];
    char    inner_magic[12];    /* "ACTS-FWT001\0" */
    uint8_t unknown_1c[4];
} AttdfuHeader;                 /* 0x20 bytes */

typedef struct {
    char     name[11];
    uint8_t  attributes;        /* 0x0F indicates a long-name entry */
    uint8_t  metadata_0c[8];
    uint16_t cluster_hi;
    uint8_t  metadata_16[4];
    uint16_t cluster_lo;
    uint32_t size;
} AttdfuShortEntry;             /* 0x20 bytes */

typedef struct {
    uint8_t  magic[16];         /* 112233445566778899AABBCCDDEEFF75 */
    uint32_t total_length;
    uint32_t header_length;     /* 0x200 */
    uint8_t  fixed_18[18];
    uint8_t  encrypted_metadata[0x1C2];
    uint8_t  check[20];
} ModuleWrapperHeader;          /* 0x200 bytes; encrypted body follows */

typedef struct {
    char     magic[8];          /* "sdfs.bin" */
    uint8_t  unknown_08[4];
    uint32_t entry_count;       /* includes this header entry */
    uint32_t total_length;
    uint8_t  unknown_14[12];
} SdfsHeader;                   /* 0x20 bytes */

typedef struct {
    char     name[12];
    uint32_t offset;
    uint32_t size;
    uint8_t  unknown_14[12];
} SdfsEntry;                    /* 0x20 bytes */

#pragma pack(pop)
```

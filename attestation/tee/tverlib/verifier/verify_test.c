#include "teeverifier.c"


// void save_basevalue(const base_value *bv);

/*
VerifyManifest(&report, 1, "basevalue.txt")------------Verification succeeded
*/
int main()
{
    uint8_t buffer1[] = {
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x68, 0x61, 0x6c,
    0x6c, 0x65, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x01, 0x9d, 0xc2,
    0x13, 0xcd, 0x5a, 0x40, 0x99, 0xf9, 0x06, 0x34, 0x3d, 0xfb, 0xe6, 0x91, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x10, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x20,
    0x20, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x00,
    0xd8, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x20,
    0x10, 0x0b, 0x00, 0x00, 0x18, 0x03, 0x00, 0x00, 0x09, 0x0b, 0x10, 0xa2, 0xdf, 0x8c, 0xdb, 0xdb,
    0x10, 0x50, 0x96, 0x15, 0xc8, 0x3f, 0x44, 0x7f, 0x35, 0x57, 0x9d, 0x2f, 0xe1, 0xc6, 0x32, 0xc0,
    0x6b, 0xd8, 0xca, 0x8c, 0x74, 0xd0, 0x69, 0xf5, 0x0f, 0x19, 0x52, 0x58, 0xb8, 0x70, 0x28, 0xa6,
    0x2f, 0xb2, 0x9b, 0x1e, 0x9e, 0xf2, 0x21, 0x89, 0x75, 0x30, 0xdc, 0x09, 0x09, 0x94, 0xe3, 0xb1,
    0x7b, 0x23, 0x50, 0x11, 0x7d, 0x25, 0x94, 0x92, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3b, 0x0e, 0xb0, 0x99, 0x8f, 0x39, 0xa7, 0x37,
    0x04, 0x8f, 0x90, 0xb7, 0x62, 0xa1, 0xfe, 0xe4, 0x55, 0x90, 0xba, 0xe2, 0x59, 0x36, 0x4c, 0xa1,
    0x4e, 0xc9, 0xd8, 0x59, 0x0b, 0xaa, 0x1d, 0xb6, 0x93, 0xe4, 0x68, 0x67, 0xe9, 0x9b, 0xdb, 0x2b,
    0x5c, 0xf7, 0xc7, 0x70, 0xda, 0x91, 0x79, 0x40, 0x44, 0x88, 0x40, 0xd1, 0x8a, 0xb1, 0x74, 0x34,
    0x4f, 0x09, 0x16, 0xeb, 0xfb, 0x81, 0x95, 0xba, 0x04, 0x48, 0xde, 0x6a, 0x00, 0xe9, 0x81, 0x21,
    0x71, 0x69, 0x7a, 0xf1, 0xbf, 0xdb, 0xa8, 0xe0, 0x16, 0x48, 0x3b, 0x7d, 0xa5, 0x9d, 0xe8, 0xfd,
    0x46, 0xca, 0xce, 0x01, 0x2b, 0xd4, 0x17, 0x8b, 0x55, 0xb6, 0x96, 0xcb, 0x6b, 0xd1, 0xc4, 0xa2,
    0x6e, 0x9e, 0x01, 0xdd, 0xc5, 0xa8, 0x78, 0xc2, 0xa2, 0xef, 0x7e, 0x5c, 0xf1, 0x07, 0x06, 0xdd,
    0x76, 0xaf, 0x1d, 0x79, 0xcc, 0xdd, 0x78, 0x8f, 0x10, 0x38, 0xe3, 0x09, 0x9f, 0xe1, 0x83, 0x21,
    0x86, 0x67, 0xec, 0xfd, 0x00, 0x9f, 0x96, 0x60, 0xea, 0xd3, 0x1f, 0xa2, 0x6f, 0x6f, 0x87, 0x5b,
    0x83, 0xf1, 0xc1, 0xe6, 0xc2, 0x5d, 0xc5, 0x68, 0x53, 0xc9, 0x18, 0x15, 0x59, 0xed, 0xf1, 0x01,
    0x8a, 0x6f, 0xef, 0x14, 0x87, 0xdf, 0x08, 0xfd, 0x5e, 0xb1, 0x80, 0x21, 0x1c, 0x5b, 0x3f, 0xd8,
    0x98, 0x6c, 0xfa, 0x11, 0x0f, 0xfd, 0xda, 0xde, 0x5c, 0xc3, 0x1a, 0x14, 0xea, 0xee, 0x09, 0x64,
    0xaf, 0xab, 0xe4, 0x32, 0xe7, 0xf4, 0x5b, 0x66, 0x53, 0xfd, 0xe8, 0xcc, 0xa8, 0x24, 0xa3, 0x1b,
    0xc6, 0xed, 0xd8, 0xd1, 0xba, 0xeb, 0x5f, 0x13, 0xd0, 0xde, 0x15, 0x45, 0xc8, 0x89, 0x44, 0xc6,
    0x47, 0x66, 0xa9, 0x9f, 0x0d, 0x5d, 0x36, 0xd3, 0x7c, 0x71, 0xed, 0xd9, 0xd8, 0xe6, 0x6d, 0x70,
    0xbb, 0x4b, 0xce, 0x0d, 0x97, 0xee, 0xb2, 0x1a, 0x53, 0x8e, 0xe5, 0xbd, 0x5a, 0x9e, 0x8c, 0x93,
    0xb2, 0x9b, 0x2b, 0xec, 0x85, 0x0c, 0x3a, 0x1e, 0x7c, 0xac, 0xa4, 0xe0, 0xd7, 0x27, 0x39, 0xa6,
    0x0c, 0xab, 0x94, 0x73, 0x8c, 0xdc, 0xb9, 0x8c, 0x00, 0x0a, 0x43, 0xd6, 0x94, 0xe5, 0xf1, 0x93,
    0x9b, 0x13, 0x89, 0xba, 0x11, 0x63, 0x03, 0x46, 0x84, 0x76, 0xa8, 0xb9, 0x84, 0x61, 0x30, 0x3e,
    0xfe, 0x23, 0x8d, 0xea, 0x44, 0x99, 0x76, 0x29, 0x36, 0x2d, 0x6f, 0x52, 0x1f, 0x42, 0x54, 0x84,
    0x8e, 0x10, 0xc9, 0xd3, 0x89, 0x19, 0x55, 0x76, 0xb1, 0xb9, 0x92, 0x2d, 0x92, 0xd3, 0xa6, 0x61,
    0xe7, 0x37, 0x6e, 0xd1, 0xe7, 0x7c, 0x04, 0xfc, 0x39, 0xc7, 0x4f, 0xd8, 0x14, 0x80, 0xef, 0xb2,
    0x69, 0xaf, 0x12, 0x29, 0x42, 0x64, 0x8f, 0xdc, 0x82, 0x0f, 0xd6, 0xef, 0x25, 0x30, 0x47, 0x1d,
    0x8c, 0xcf, 0x71, 0xf1, 0xb9, 0xf6, 0x87, 0x04, 0x91, 0xbc, 0x56, 0xd1, 0xc1, 0xd4, 0x24, 0x54,
    0x32, 0xe1, 0x0c, 0xb7, 0x4a, 0x32, 0x3f, 0x71, 0xfe, 0xf7, 0xd8, 0x4d, 0xb1, 0xff, 0x00, 0x35,
    0x8a, 0x72, 0xd3, 0x4d, 0x87, 0x6c, 0x9f, 0x63, 0x6b, 0x67, 0x2b, 0x8c, 0xb8, 0x9c, 0x7c, 0x35,
    0xfb, 0x00, 0xac, 0xcf, 0x40, 0xc6, 0x21, 0x82, 0x36, 0x1c, 0x82, 0x90, 0xca, 0x48, 0x08, 0xfb,
    0x7b, 0x0b, 0xdd, 0xbd, 0xc8, 0x25, 0xb3, 0x37, 0xb2, 0x92, 0x99, 0xb0, 0x66, 0xe0, 0xab, 0xe4,
    0x4e, 0x08, 0x02, 0xf4, 0x08, 0x90, 0x3b, 0xc2, 0xca, 0xd2, 0x0f, 0x94, 0xcc, 0x8e, 0x2d, 0x3d,
    0xb5, 0xd1, 0x49, 0x1c, 0xde, 0xd4, 0x51, 0xc0, 0x5e, 0xc4, 0xe4, 0x90, 0x9f, 0xec, 0xd1, 0xf6,
    0x53, 0x9d, 0x8b, 0xeb, 0xb6, 0x0e, 0xe6, 0x26, 0x5b, 0x16, 0x64, 0xe2, 0xed, 0x46, 0xff, 0x5a,
    0xba, 0xc6, 0x3a, 0xf6, 0xcf, 0x08, 0x5f, 0x63, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x6f,
    0x20, 0x61, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x20,
    0x20, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0xf0, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x20,
    0x20, 0x06, 0x00, 0x00, 0xf0, 0x04, 0x00, 0x00, 0x46, 0x6a, 0x3a, 0x9a, 0xc3, 0x06, 0x1d, 0xae,
    0xe5, 0x71, 0xf9, 0xaa, 0x95, 0x8b, 0x2d, 0x4b, 0xc4, 0xfb, 0xec, 0x7c, 0x96, 0xd4, 0xb5, 0x26,
    0x1f, 0xf4, 0x6a, 0xb5, 0xb1, 0x41, 0x80, 0xb6, 0x80, 0x81, 0xb0, 0xb1, 0x76, 0xdc, 0x0b, 0x8c,
    0xa3, 0x4d, 0xe8, 0x3b, 0xbf, 0x10, 0xf4, 0xb4, 0x1a, 0xd8, 0xdf, 0xdf, 0x76, 0xd7, 0x4a, 0xf7,
    0xbd, 0x9c, 0x5a, 0xe7, 0xde, 0x71, 0xfc, 0xf9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xd7, 0xcd, 0xd5, 0x18, 0x56, 0x19, 0x3e, 0x95,
    0xa3, 0xf2, 0xe5, 0x17, 0x8e, 0x05, 0x40, 0x52, 0x85, 0xf9, 0x9b, 0x5c, 0x6b, 0x45, 0xdf, 0x48,
    0xb6, 0x91, 0xcf, 0x27, 0x98, 0xfa, 0x97, 0x6f, 0x92, 0x20, 0x00, 0x27, 0x23, 0xb4, 0x92, 0x21,
    0x8a, 0xc0, 0xf5, 0xc7, 0x6d, 0x80, 0x47, 0x88, 0x86, 0x44, 0x13, 0x3c, 0x89, 0xec, 0x8c, 0x53,
    0x69, 0xeb, 0xea, 0xbc, 0x35, 0xfb, 0x7b, 0x3c, 0x79, 0x1c, 0xcd, 0x80, 0x75, 0xf0, 0xf1, 0x5b,
    0x0d, 0xb1, 0x3a, 0xd1, 0xf0, 0xc2, 0x62, 0xdc, 0x09, 0x75, 0xb3, 0xb2, 0xc8, 0x3a, 0x2b, 0x5a,
    0x78, 0xe9, 0x08, 0xdd, 0x4c, 0x01, 0xc7, 0xf0, 0xbc, 0x12, 0x34, 0xbf, 0x71, 0x13, 0x23, 0x5c,
    0x2b, 0x99, 0x3d, 0x58, 0xfc, 0x86, 0x7e, 0xe8, 0x6b, 0x66, 0xe6, 0xb3, 0x01, 0xbd, 0xaf, 0x92,
    0xe1, 0x3b, 0x39, 0x50, 0xad, 0x7b, 0x6e, 0x8f, 0xab, 0xce, 0x83, 0x7c, 0x3f, 0x55, 0xed, 0x71,
    0xcd, 0x2b, 0x3a, 0xd7, 0x4d, 0xd5, 0x46, 0x6c, 0x0f, 0xdb, 0xdd, 0x1b, 0x2b, 0x67, 0xe2, 0x44,
    0x87, 0xc3, 0x77, 0xe6, 0x88, 0x6d, 0xd6, 0x3e, 0xe7, 0x7c, 0x24, 0x58, 0xa8, 0x8f, 0xc3, 0x12,
    0xa9, 0xd3, 0x5c, 0xfa, 0x7d, 0x79, 0xde, 0xa7, 0xb9, 0xcc, 0x3b, 0x22, 0xa7, 0xe9, 0xf5, 0x6a,
    0x51, 0x7b, 0xad, 0x32, 0x86, 0x4f, 0x6a, 0x05, 0x30, 0x04, 0x74, 0x9d, 0xd5, 0x48, 0x92, 0x4d,
    0x49, 0xf3, 0x78, 0x8e, 0x04, 0x4c, 0x54, 0x59, 0xfb, 0x0f, 0x61, 0x9e, 0x1a, 0xc4, 0x3d, 0x01,
    0x4e, 0x82, 0x8b, 0x82, 0x0c, 0x8c, 0xf1, 0xe5, 0xc2, 0x14, 0x4f, 0xb9, 0xf7, 0x1c, 0xee, 0x9e,
    0x49, 0x53, 0xd3, 0x34, 0xb1, 0x69, 0x91, 0x68, 0x10, 0x47, 0xda, 0x09, 0x30, 0xdb, 0x90, 0xf1,
    0xd5, 0x51, 0xa2, 0x89, 0x87, 0xb9, 0x9d, 0xc8, 0xf4, 0x9b, 0xec, 0xb6, 0x79, 0xdc, 0x07, 0x02,
    0xaf, 0x78, 0xf5, 0xbe, 0x9e, 0x35, 0x20, 0xdc, 0x91, 0xd2, 0x6c, 0xef, 0xcb, 0x8c, 0xce, 0xd7,
    0x78, 0xc0, 0x76, 0x44, 0x30, 0x90, 0x49, 0x44, 0x66, 0x11, 0xa0, 0xb3, 0x54, 0x18, 0x70, 0x5a,
    0x19, 0xda, 0x5d, 0x50, 0x4a, 0x5b, 0xb1, 0xa6, 0xb0, 0x7f, 0x38, 0x1a, 0x99, 0xbd, 0x25, 0xa0,
    0xc1, 0x92, 0x15, 0x5e, 0x75, 0x34, 0x8f, 0x7d, 0x29, 0x1f, 0x0d, 0xb8, 0x87, 0xb1, 0x9c, 0x5c,
    0x83, 0x55, 0xa1, 0x38, 0xde, 0xd5, 0x81, 0x5a, 0xc4, 0x4e, 0x3a, 0xfe, 0x2c, 0xae, 0x30, 0xd3,
    0x54, 0xb5, 0x35, 0xe8, 0xdd, 0x6d, 0x97, 0x3e, 0x88, 0x62, 0xb6, 0x79, 0xbf, 0x4d, 0xfb, 0xc5,
    0x64, 0x2b, 0xb7, 0x06, 0xc4, 0x71, 0xb3, 0x6f, 0xa4, 0xae, 0x39, 0x56, 0xd7, 0x17, 0x20, 0xde,
    0x7e, 0x45, 0xff, 0x6c, 0x4c, 0x0f, 0xb1, 0x78, 0x57, 0x57, 0x95, 0x4c, 0x9f, 0x6e, 0x1c, 0x14,
    0x68, 0x30, 0x40, 0x55, 0x4b, 0x80, 0x37, 0xa6, 0x2a, 0xd4, 0x51, 0x9d, 0x95, 0x24, 0x6a, 0xda,
    0x88, 0xba, 0xbd, 0x42, 0x9a, 0x47, 0x48, 0xa6, 0x76, 0x2a, 0x24, 0xfc, 0xe9, 0x4b, 0x7c, 0xd9,
    0x3f, 0xdf, 0x29, 0xbe, 0xaa, 0x1a, 0xa9, 0xa8, 0xe8, 0x21, 0xa7, 0x27, 0x07, 0x05, 0x1d, 0x76,
    0x24, 0x3a, 0x7f, 0x5d, 0x98, 0xc8, 0x18, 0x51, 0x12, 0xaf, 0xbf, 0xd1, 0xf5, 0x2b, 0x7f, 0xcb,
    0xfe, 0x3c, 0x79, 0xa6, 0x69, 0x0f, 0xb4, 0xe6, 0x6a, 0x32, 0xc9, 0x2b, 0x1e, 0x6b, 0xce, 0x71,
    0x84, 0x87, 0x37, 0x0e, 0x83, 0x08, 0x8f, 0x1d, 0x6e, 0x28, 0xa3, 0x4e, 0x5b, 0xb6, 0x2b, 0xfe,
    0x6c, 0xbb, 0xf0, 0x21, 0xce, 0x81, 0xd8, 0x2c, 0x9c, 0x39, 0x32, 0x67, 0x08, 0xa7, 0x8c, 0x03,
    0x67, 0x62, 0x88, 0x66, 0xd6, 0x3c, 0x66, 0xcf, 0x28, 0xab, 0x82, 0x74, 0xd0, 0xfb, 0xfa, 0x9f,
    0xd3, 0x05, 0x5f, 0xf5, 0xa2, 0x36, 0x1c, 0x34, 0xe1, 0x98, 0xb0, 0xfb, 0xb5, 0xc8, 0x3f, 0xb1,
    0xb9, 0x96, 0x0a, 0xd3, 0xe4, 0xe7, 0xa8, 0xfd, 0x14, 0x84, 0x32, 0x3d, 0x8c, 0x05, 0xa7, 0x9d,
    0xa6, 0xcb, 0x59, 0x7d, 0x47, 0x61, 0xca, 0x05, 0xd7, 0xdb, 0x20, 0x78, 0xaf, 0xa3, 0x10, 0xb0,
    0xd9, 0x4c, 0xe7, 0x28, 0xa0, 0x10, 0x1f, 0xb8, 0x0e, 0x0e, 0x49, 0x2c, 0xde, 0x64, 0x0e, 0x64,
    0x78, 0x7d, 0x70, 0x31, 0x77, 0x74, 0x9a, 0x39, 0x26, 0xcc, 0x20, 0x0e, 0x88, 0xc8, 0x23, 0xb6,
    0xba, 0xe2, 0x73, 0x77, 0x43, 0xb0, 0xca, 0x8a, 0xb7, 0x17, 0xbe, 0x55, 0x4a, 0xe4, 0x93, 0x38,
    0x06, 0xf8, 0x62, 0x44, 0x43, 0x46, 0xd5, 0x3e, 0x80, 0xb6, 0xf5, 0x4b, 0x69, 0x98, 0x5b, 0x9f,
    0xbe, 0xe9, 0xf0, 0xea, 0xf2, 0x42, 0x0c, 0xf4, 0xe6, 0x28, 0x25, 0x51, 0x6e, 0xa3, 0x53, 0xcc,
    0xbd, 0xec, 0x85, 0x61, 0x7e, 0x4a, 0xab, 0x1c, 0xb4, 0x8e, 0x82, 0x55, 0x97, 0x38, 0xc1, 0xa4,
    0x91, 0x72, 0x5d, 0x69, 0x4c, 0x84, 0x7d, 0xa1, 0x4c, 0xf7, 0x3b, 0x76, 0xce, 0x78, 0x00, 0x10,
    0xaa, 0xbd, 0xa4, 0x2e, 0xc7, 0xb2, 0x41, 0x71, 0xd0, 0xa7, 0xfd, 0x7f, 0x38, 0x5b, 0x4f, 0x86,
    0x9f, 0x8f, 0x6f, 0x20, 0x25, 0x37, 0xe1, 0xb7, 0xc4, 0xe2, 0x64, 0x60, 0x4e, 0x66, 0x2d, 0xec,
    0x93, 0x7b, 0xd9, 0xa8, 0xe8, 0xd8, 0x33, 0xb2, 0x9c, 0x29, 0xe4, 0x9d, 0x2e, 0xe7, 0x32, 0xdd,
    0x2b, 0x85, 0x5d, 0x41, 0x40, 0xd8, 0xe7, 0xb6, 0xa6, 0xe8, 0xfa, 0xe7, 0x16, 0x45, 0x12, 0xe7,
    0xbd, 0x89, 0x47, 0xde, 0xfb, 0x17, 0x0d, 0xa6, 0x48, 0x9f, 0xf3, 0x3e, 0x24, 0x4d, 0xdc, 0xe2,
    0xbf, 0xcf, 0x5d, 0xc7, 0x2e, 0xfa, 0xd6, 0x4c, 0x16, 0x59, 0x52, 0x48, 0xb8, 0x2c, 0x79, 0xe2,
    0xa4, 0x8c, 0x79, 0x08, 0x4e, 0xfc, 0xe3, 0x38, 0x75, 0x70, 0x2e, 0x1a, 0xbe, 0x38, 0x0b, 0x3f,
    0x9f, 0xd7, 0x77, 0x99, 0x95, 0x3a, 0xd7, 0xc1, 0x26, 0x6c, 0x6d, 0x3b, 0x03, 0x8a, 0xcf, 0x8b,
    0x27, 0x2c, 0xf1, 0x14, 0x2f, 0xcc, 0xc6, 0x6f, 0xe9, 0xb0, 0x8f, 0x83, 0xd4, 0x8a, 0x9e, 0xa0,
    0xbb, 0x55, 0x47, 0xc2, 0xe0, 0xe6, 0xfc, 0x10, 0x96, 0x70, 0x94, 0xac, 0x6b, 0xd5, 0xbf, 0xef,
    0xdc, 0x55, 0x2e, 0x93, 0xbd, 0x83, 0xe1, 0xb8, 0x5a, 0x1b, 0xbd, 0x6b, 0xf6, 0xdd, 0xce, 0xf4,
    0xb2, 0x06, 0x69, 0xd7, 0x58, 0x68, 0x9f, 0x10, 0x2d, 0xa4, 0x77, 0x50, 0xe4, 0x24, 0xa9, 0xba,
    0x3c, 0xa2, 0xe3, 0xa1, 0x99, 0x25, 0xe0, 0x46, 0xe5, 0xc7, 0xaa, 0x9a, 0x6a, 0xa2, 0x35, 0x7f,
    0xc5, 0x84, 0xd7, 0x8f, 0x52, 0x8f, 0x39, 0x0f, 0x08, 0xc6, 0xdb, 0x41, 0xd2, 0xc0, 0x24, 0x4f,
    0xd8, 0x40, 0x4e, 0xb1, 0x34, 0x14, 0x21, 0x86, 0xec, 0xb0, 0xd0, 0x1d, 0xf5, 0xac, 0xde, 0xdb,
    0xa3, 0x8f, 0x1e, 0x5a, 0x80, 0xdb, 0x0b, 0x3e, 0x1f, 0xd9, 0xaf, 0x52, 0x7f, 0x91, 0x55, 0x20,
    0x7b, 0xee, 0xb4, 0x9d, 0x70, 0xa9, 0x88, 0x83, 0x22, 0xc7, 0x49, 0x3f, 0x0a, 0xb7, 0xb2, 0xbd,
    0x85, 0xb0, 0x05, 0x7a, 0x11, 0x19, 0xad, 0x57, 0x36, 0xf1, 0xc0, 0x49, 0xea, 0xe5, 0x21, 0x01,
    0x34, 0x0a, 0x94, 0x76, 0xdb, 0x34, 0xf7, 0x10, 0x15, 0x7b, 0xb0, 0x70, 0x39, 0xaf, 0x7d, 0x71,
    0x48, 0x09, 0x88, 0xc0, 0x94, 0xd0, 0xf6, 0xc2, 0xf0, 0xe2, 0xf5, 0xe4, 0x2e, 0xd2, 0x5a, 0x2c,
    0xd9, 0x42, 0x58, 0xf3, 0x5d, 0x85, 0x90, 0x1f, 0x3a, 0x43, 0x7c, 0x58, 0xf6, 0x35, 0x35, 0x1f,
    0x68, 0x1c, 0x0a, 0xd6, 0x6a, 0x8f, 0x8b, 0x64, 0x4d, 0x49, 0x49, 0x45, 0x6b, 0x6a, 0x43, 0x43,
    0x41, 0x33, 0x71, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x52, 0x45, 0x56, 0x4f, 0x47,
    0x74, 0x4c, 0x6a, 0x7a, 0x57, 0x4c, 0x2b, 0x39, 0x36, 0x58, 0x4a, 0x46, 0x79, 0x69, 0x58, 0x49,
    0x51, 0x30, 0x38, 0x77, 0x44, 0x51, 0x59, 0x4a, 0x4b, 0x6f, 0x5a, 0x49, 0x68, 0x76, 0x63, 0x4e,
    0x41, 0x51, 0x45, 0x4c, 0x42, 0x51, 0x41, 0x77, 0x50, 0x54, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47,
    0x41, 0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x51, 0x30, 0x34, 0x78, 0x44, 0x7a, 0x41, 0x4e,
    0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x54, 0x42, 0x6b, 0x68, 0x31, 0x59, 0x58, 0x64, 0x6c,
    0x61, 0x54, 0x45, 0x64, 0x4d, 0x42, 0x73, 0x47, 0x41, 0x31, 0x55, 0x45, 0x41, 0x78, 0x4d, 0x55,
    0x53, 0x48, 0x56, 0x68, 0x64, 0x32, 0x56, 0x70, 0x49, 0x45, 0x6c, 0x55, 0x49, 0x46, 0x42, 0x79,
    0x62, 0x32, 0x52, 0x31, 0x59, 0x33, 0x51, 0x67, 0x51, 0x30, 0x45, 0x77, 0x48, 0x68, 0x63, 0x4e,
    0x4d, 0x6a, 0x49, 0x77, 0x4e, 0x44, 0x45, 0x78, 0x4d, 0x44, 0x59, 0x7a, 0x4e, 0x54, 0x41, 0x79,
    0x57, 0x68, 0x63, 0x4e, 0x4d, 0x7a, 0x63, 0x77, 0x4e, 0x44, 0x41, 0x33, 0x4d, 0x44, 0x59, 0x7a,
    0x4e, 0x54, 0x41, 0x79, 0x57, 0x6a, 0x41, 0x36, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44,
    0x56, 0x51, 0x51, 0x47, 0x45, 0x77, 0x4a, 0x44, 0x54, 0x6a, 0x45, 0x50, 0x4d, 0x41, 0x30, 0x47,
    0x41, 0x31, 0x55, 0x45, 0x43, 0x68, 0x4d, 0x47, 0x53, 0x48, 0x56, 0x68, 0x64, 0x32, 0x56, 0x70,
    0x4d, 0x52, 0x6f, 0x77, 0x47, 0x41, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x45, 0x78, 0x45, 0x77,
    0x4d, 0x6a, 0x5a, 0x51, 0x55, 0x46, 0x59, 0x78, 0x4d, 0x45, 0x74, 0x44, 0x4d, 0x44, 0x41, 0x30,
    0x4d, 0x54, 0x63, 0x35, 0x56, 0x44, 0x43, 0x43, 0x41, 0x69, 0x49, 0x77, 0x44, 0x51, 0x59, 0x4a,
    0x4b, 0x6f, 0x5a, 0x49, 0x68, 0x76, 0x63, 0x4e, 0x41, 0x51, 0x45, 0x42, 0x42, 0x51, 0x41, 0x44,
    0x67, 0x67, 0x49, 0x50, 0x41, 0x44, 0x43, 0x43, 0x41, 0x67, 0x6f, 0x43, 0x67, 0x67, 0x49, 0x42,
    0x41, 0x4e, 0x6e, 0x38, 0x62, 0x7a, 0x49, 0x72, 0x67, 0x78, 0x61, 0x41, 0x34, 0x58, 0x7a, 0x46,
    0x46, 0x58, 0x4b, 0x38, 0x59, 0x61, 0x48, 0x4e, 0x55, 0x4e, 0x48, 0x67, 0x68, 0x68, 0x47, 0x32,
    0x59, 0x78, 0x48, 0x38, 0x66, 0x77, 0x38, 0x6b, 0x49, 0x53, 0x2f, 0x50, 0x5a, 0x63, 0x73, 0x64,
    0x65, 0x7a, 0x36, 0x59, 0x35, 0x4b, 0x67, 0x70, 0x4d, 0x54, 0x32, 0x74, 0x65, 0x34, 0x64, 0x56,
    0x4a, 0x58, 0x6b, 0x61, 0x43, 0x78, 0x55, 0x65, 0x77, 0x52, 0x31, 0x66, 0x6d, 0x55, 0x6f, 0x50,
    0x30, 0x65, 0x2b, 0x6c, 0x69, 0x6b, 0x58, 0x79, 0x59, 0x5a, 0x66, 0x6d, 0x71, 0x78, 0x31, 0x7a,
    0x49, 0x56, 0x68, 0x6b, 0x34, 0x6d, 0x33, 0x6b, 0x6e, 0x2b, 0x49, 0x58, 0x37, 0x78, 0x39, 0x73,
    0x74, 0x4c, 0x7a, 0x2b, 0x6f, 0x47, 0x43, 0x5a, 0x61, 0x78, 0x36, 0x31, 0x73, 0x2b, 0x75, 0x44,
    0x61, 0x36, 0x70, 0x48, 0x4c, 0x63, 0x78, 0x54, 0x35, 0x4a, 0x59, 0x46, 0x59, 0x68, 0x55, 0x47,
    0x67, 0x61, 0x65, 0x6c, 0x4d, 0x70, 0x4b, 0x69, 0x71, 0x6a, 0x61, 0x2f, 0x48, 0x5a, 0x36, 0x68,
    0x74, 0x42, 0x51, 0x6d, 0x68, 0x67, 0x56, 0x2f, 0x34, 0x51, 0x71, 0x4c, 0x79, 0x74, 0x7a, 0x59,
    0x4a, 0x4a, 0x57, 0x36, 0x65, 0x51, 0x68, 0x46, 0x73, 0x2b, 0x41, 0x6f, 0x54, 0x45, 0x4c, 0x79,
    0x46, 0x61, 0x41, 0x6b, 0x42, 0x57, 0x52, 0x59, 0x33, 0x69, 0x51, 0x51, 0x6c, 0x4e, 0x79, 0x36,
    0x68, 0x6c, 0x57, 0x6c, 0x46, 0x6b, 0x4c, 0x54, 0x42, 0x47, 0x58, 0x49, 0x66, 0x2f, 0x67, 0x41,
    0x36, 0x32, 0x68, 0x32, 0x78, 0x4e, 0x70, 0x77, 0x70, 0x4f, 0x56, 0x47, 0x63, 0x46, 0x2f, 0x66,
    0x2f, 0x66, 0x6b, 0x75, 0x30, 0x65, 0x47, 0x72, 0x55, 0x64, 0x75, 0x59, 0x50, 0x6d, 0x38, 0x61,
    0x54, 0x65, 0x36, 0x73, 0x48, 0x4f, 0x36, 0x48, 0x39, 0x57, 0x61, 0x63, 0x4c, 0x70, 0x53, 0x6f,
    0x30, 0x77, 0x53, 0x6a, 0x73, 0x68, 0x68, 0x30, 0x4f, 0x31, 0x53, 0x37, 0x6b, 0x71, 0x65, 0x49,
    0x51, 0x31, 0x4b, 0x75, 0x68, 0x43, 0x63, 0x49, 0x64, 0x42, 0x72, 0x4a, 0x45, 0x63, 0x72, 0x6a,
    0x50, 0x39, 0x44, 0x55, 0x33, 0x42, 0x72, 0x70, 0x78, 0x6c, 0x73, 0x72, 0x4e, 0x49, 0x2b, 0x2b,
    0x47, 0x79, 0x35, 0x74, 0x6b, 0x2b, 0x39, 0x43, 0x74, 0x59, 0x4f, 0x35, 0x6c, 0x4e, 0x4b, 0x55,
    0x6d, 0x32, 0x47, 0x51, 0x5a, 0x43, 0x52, 0x56, 0x4a, 0x68, 0x31, 0x71, 0x51, 0x63, 0x57, 0x6f,
    0x78, 0x50, 0x59, 0x36, 0x54, 0x62, 0x43, 0x49, 0x65, 0x36, 0x62, 0x32, 0x2f, 0x68, 0x68, 0x52,
    0x46, 0x74, 0x75, 0x49, 0x33, 0x65, 0x58, 0x70, 0x67, 0x33, 0x2f, 0x39, 0x66, 0x59, 0x6d, 0x4d,
    0x62, 0x59, 0x4a, 0x6f, 0x76, 0x53, 0x6f, 0x57, 0x71, 0x7a, 0x41, 0x2b, 0x53, 0x36, 0x42, 0x2f,
    0x4f, 0x76, 0x76, 0x67, 0x42, 0x56, 0x31, 0x61, 0x37, 0x33, 0x68, 0x77, 0x69, 0x2f, 0x42, 0x57,
    0x62, 0x5a, 0x38, 0x39, 0x6d, 0x63, 0x37, 0x58, 0x6e, 0x76, 0x4b, 0x72, 0x35, 0x31, 0x50, 0x45,
    0x79, 0x42, 0x2b, 0x4e, 0x73, 0x2b, 0x45, 0x4a, 0x71, 0x73, 0x35, 0x57, 0x59, 0x33, 0x67, 0x57,
    0x2f, 0x77, 0x55, 0x69, 0x66, 0x6a, 0x38, 0x77, 0x55, 0x65, 0x52, 0x4b, 0x65, 0x6a, 0x57, 0x78,
    0x67, 0x43, 0x35, 0x70, 0x4a, 0x42, 0x55, 0x47, 0x39, 0x4f, 0x59, 0x63, 0x72, 0x73, 0x62, 0x59,
    0x68, 0x4c, 0x73, 0x74, 0x50, 0x32, 0x70, 0x77, 0x6f, 0x48, 0x71, 0x5a, 0x2b, 0x64, 0x45, 0x6b,
    0x59, 0x31, 0x6f, 0x2b, 0x4f, 0x63, 0x68, 0x6f, 0x5a, 0x6e, 0x57, 0x61, 0x59, 0x79, 0x64, 0x77,
    0x58, 0x64, 0x38, 0x30, 0x41, 0x63, 0x62, 0x35, 0x63, 0x64, 0x39, 0x4d, 0x51, 0x31, 0x48, 0x32,
    0x73, 0x56, 0x64, 0x31, 0x4c, 0x54, 0x6f, 0x70, 0x57, 0x30, 0x4b, 0x76, 0x48, 0x68, 0x47, 0x51,
    0x51, 0x35, 0x38, 0x4d, 0x6b, 0x4d, 0x51, 0x55, 0x49, 0x67, 0x4f, 0x46, 0x35, 0x57, 0x6a, 0x6d,
    0x69, 0x58, 0x4c, 0x55, 0x73, 0x43, 0x61, 0x70, 0x44, 0x77, 0x6c, 0x76, 0x6b, 0x44, 0x47, 0x70,
    0x73, 0x6f, 0x36, 0x50, 0x61, 0x69, 0x37, 0x75, 0x51, 0x4e, 0x66, 0x45, 0x39, 0x2f, 0x79, 0x4e,
    0x36, 0x51, 0x5a, 0x58, 0x38, 0x55, 0x71, 0x6c, 0x70, 0x4e, 0x68, 0x35, 0x30, 0x2f, 0x57, 0x37,
    0x2b, 0x2b, 0x46, 0x6b, 0x35, 0x4b, 0x4a, 0x59, 0x61, 0x37, 0x6f, 0x59, 0x43, 0x53, 0x64, 0x38,
    0x66, 0x4f, 0x6d, 0x54, 0x49, 0x47, 0x4c, 0x5a, 0x6e, 0x51, 0x64, 0x71, 0x35, 0x41, 0x53, 0x5a,
    0x56, 0x56, 0x33, 0x47, 0x78, 0x63, 0x64, 0x71, 0x50, 0x35, 0x46, 0x72, 0x67, 0x70, 0x55, 0x52,
    0x33, 0x51, 0x42, 0x2f, 0x4f, 0x77, 0x54, 0x37, 0x37, 0x56, 0x66, 0x38, 0x4c, 0x36, 0x52, 0x41,
    0x6e, 0x38, 0x34, 0x69, 0x4f, 0x44, 0x73, 0x66, 0x50, 0x44, 0x42, 0x7a, 0x41, 0x67, 0x4d, 0x42,
    0x41, 0x41, 0x47, 0x6a, 0x67, 0x59, 0x38, 0x77, 0x67, 0x59, 0x77, 0x77, 0x48, 0x77, 0x59, 0x44,
    0x56, 0x52, 0x30, 0x6a, 0x42, 0x42, 0x67, 0x77, 0x46, 0x6f, 0x41, 0x55, 0x45, 0x6f, 0x6f, 0x33,
    0x37, 0x50, 0x6c, 0x7a, 0x56, 0x39, 0x66, 0x6b, 0x67, 0x37, 0x71, 0x31, 0x62, 0x77, 0x50, 0x73,
    0x33, 0x61, 0x34, 0x52, 0x54, 0x73, 0x38, 0x77, 0x43, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x50,
    0x42, 0x41, 0x51, 0x44, 0x41, 0x67, 0x50, 0x34, 0x4d, 0x46, 0x77, 0x47, 0x43, 0x43, 0x73, 0x47,
    0x41, 0x51, 0x55, 0x46, 0x42, 0x77, 0x45, 0x42, 0x42, 0x46, 0x41, 0x77, 0x54, 0x6a, 0x41, 0x6f,
    0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46, 0x42, 0x51, 0x63, 0x77, 0x41, 0x6f, 0x59, 0x63,
    0x61, 0x48, 0x52, 0x30, 0x63, 0x44, 0x6f, 0x76, 0x4c, 0x7a, 0x45, 0x79, 0x4e, 0x79, 0x34, 0x77,
    0x4c, 0x6a, 0x41, 0x75, 0x4d, 0x53, 0x39, 0x6a, 0x59, 0x57, 0x6c, 0x7a, 0x63, 0x33, 0x56, 0x6c,
    0x4c, 0x6d, 0x68, 0x30, 0x62, 0x54, 0x41, 0x69, 0x42, 0x67, 0x67, 0x72, 0x42, 0x67, 0x45, 0x46,
    0x42, 0x51, 0x63, 0x77, 0x41, 0x59, 0x59, 0x57, 0x61, 0x48, 0x52, 0x30, 0x63, 0x44, 0x6f, 0x76,
    0x4c, 0x7a, 0x45, 0x79, 0x4e, 0x79, 0x34, 0x77, 0x4c, 0x6a, 0x41, 0x75, 0x4d, 0x54, 0x6f, 0x79,
    0x4d, 0x44, 0x51, 0x30, 0x4d, 0x7a, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47,
    0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73, 0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51, 0x45, 0x41,
    0x48, 0x57, 0x35, 0x39, 0x66, 0x6d, 0x4c, 0x63, 0x55, 0x32, 0x64, 0x2b, 0x69, 0x63, 0x6e, 0x63,
    0x61, 0x47, 0x58, 0x65, 0x68, 0x53, 0x72, 0x65, 0x48, 0x45, 0x63, 0x51, 0x38, 0x55, 0x6d, 0x64,
    0x58, 0x58, 0x31, 0x35, 0x6b, 0x71, 0x37, 0x79, 0x2b, 0x67, 0x59, 0x33, 0x49, 0x66, 0x49, 0x69,
    0x4d, 0x48, 0x31, 0x49, 0x43, 0x4d, 0x54, 0x56, 0x4b, 0x2f, 0x58, 0x44, 0x6c, 0x56, 0x59, 0x47,
    0x79, 0x6d, 0x31, 0x71, 0x6f, 0x51, 0x77, 0x62, 0x57, 0x78, 0x4f, 0x4a, 0x2f, 0x46, 0x38, 0x41,
    0x67, 0x38, 0x41, 0x59, 0x56, 0x4d, 0x58, 0x71, 0x5a, 0x47, 0x65, 0x6b, 0x51, 0x45, 0x38, 0x42,
    0x64, 0x66, 0x4d, 0x4e, 0x4d, 0x6d, 0x42, 0x67, 0x67, 0x39, 0x68, 0x7a, 0x47, 0x75, 0x68, 0x58,
    0x49, 0x76, 0x2b, 0x6c, 0x73, 0x37, 0x78, 0x39, 0x75, 0x52, 0x41, 0x6c, 0x4a, 0x44, 0x56, 0x56,
    0x32, 0x35, 0x6b, 0x4e, 0x39, 0x61, 0x4d, 0x58, 0x2f, 0x36, 0x45, 0x50, 0x59, 0x36, 0x69, 0x39,
    0x71, 0x48, 0x31, 0x4f, 0x39, 0x4a, 0x77, 0x37, 0x51, 0x45, 0x67, 0x77, 0x4f, 0x62, 0x65, 0x4c,
    0x4e, 0x45, 0x33, 0x55, 0x5a, 0x63, 0x6e, 0x39, 0x6c, 0x4f, 0x74, 0x43, 0x50, 0x57, 0x64, 0x58,
    0x67, 0x58, 0x43, 0x51, 0x39, 0x39, 0x67, 0x36, 0x6d, 0x62, 0x49, 0x30, 0x37, 0x4a, 0x78, 0x37,
    0x66, 0x59, 0x34, 0x51, 0x2b, 0x73, 0x55, 0x4a, 0x4e, 0x42, 0x4c, 0x6a, 0x34, 0x35, 0x62, 0x73,
    0x2f, 0x49, 0x49, 0x43, 0x63, 0x50, 0x6a, 0x41, 0x51, 0x2f, 0x47, 0x62, 0x37, 0x7a, 0x34, 0x48,
    0x52, 0x70, 0x4b, 0x43, 0x44, 0x42, 0x33, 0x53, 0x74, 0x7a, 0x36, 0x66, 0x5a, 0x33, 0x48, 0x63,
    0x52, 0x56, 0x62, 0x57, 0x2f, 0x41, 0x32, 0x63, 0x77, 0x31, 0x48, 0x77, 0x50, 0x32, 0x37, 0x6d,
    0x70, 0x6e, 0x59, 0x71, 0x38, 0x6f, 0x6f, 0x74, 0x77, 0x6d, 0x7a, 0x4b, 0x59, 0x72, 0x74, 0x5a,
    0x73, 0x6c, 0x2b, 0x38, 0x62, 0x38, 0x58, 0x42, 0x71, 0x6f, 0x30, 0x4d, 0x73, 0x6d, 0x69, 0x58,
    0x36, 0x6a, 0x47, 0x71, 0x31, 0x49, 0x4a, 0x2f, 0x61, 0x76, 0x33, 0x43, 0x71, 0x43, 0x31, 0x37,
    0x45, 0x46, 0x2b, 0x63, 0x70, 0x53, 0x74, 0x6b, 0x6d, 0x76, 0x5a, 0x71, 0x61, 0x65, 0x64, 0x67,
    0x5a, 0x56, 0x77, 0x4f, 0x73, 0x53, 0x36, 0x64, 0x6f, 0x37, 0x31, 0x78, 0x78, 0x2b, 0x42, 0x67,
    0x50, 0x56, 0x65, 0x32, 0x7a, 0x67, 0x3d, 0x3d, };
    uint8_t buffer2[] = {
    0x63, 0x68, 0x61, 0x6c,0x6c, 0x65, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };
    buffer_data bufferdata1,nonce;
    bufferdata1.size = 3624;
    bufferdata1.buf  = buffer1;
    TA_report *report1 = Convert(&bufferdata1);
    printf("nonce:%s\n", report1->nonce);
    test_print(report1->uuid,UUID_SIZE,"uuid");
    printf("scenario:%u\n", report1->scenario);
    test_print(report1->image_hash,HASH_SIZE,"img_hash");
    test_print(report1->hash,HASH_SIZE,"hash");
    test_print(report1->reserve,HASH_SIZE,"reserve");

    // base_value *bv = (base_value *)calloc(1, sizeof(base_value));
    // memcpy(bv->uuid, report->uuid, UUID_SIZE*sizeof(uint8_t));
    // memcpy(bv->valueinfo[0], report->image_hash, HASH_SIZE*sizeof(uint8_t));
    // memcpy(bv->valueinfo[1], report->hash, HASH_SIZE*sizeof(uint8_t));

    // save_basevalue(bv);  // just for test
    nonce.size = 9;
    nonce.buf = "challenge";
    bool tv = tee_verify_nonce(&bufferdata1,&nonce);
    printf("test_nonce:%d\n",tv);
    tee_verify(&bufferdata1, 3, "basevalue.txt");//test report1-success
    
    return 0;
}

// void save_basevalue(const base_value *bv) {
//     // char **temp = (char **)malloc(sizeof(char*) * 3);
//     // temp[0] = (char *)malloc(sizeof(char) * (32+4));
//     // temp[1] = (char *)malloc(sizeof(char) * 64);
//     // temp[2] = (char *)malloc(sizeof(char) * 64);
//     char uuid_str[37];
//     char image_hash_str[65];
//     char hash_str[65];
//     memset(uuid_str, '\0', sizeof(uuid_str));
//     memset(image_hash_str, '\0', sizeof(image_hash_str));
//     memset(hash_str, '\0', sizeof(hash_str));

//     uuid_to_str(bv->uuid, uuid_str);
//     hash_to_str(bv->valueinfo[0], image_hash_str);
//     hash_to_str(bv->valueinfo[1], hash_str);

//     const int bvbuf_len = 200;
//     char bvbuf[bvbuf_len];  // 32+4+2+64+64+1=167 < 200
//     memset(bvbuf, '\0', sizeof(bvbuf));
//     strcpy(bvbuf, uuid_str);
//     strcat(bvbuf, " ");
//     strcat(bvbuf, image_hash_str);
//     strcat(bvbuf, " ");
//     strcat(bvbuf, hash_str);
//     strcat(bvbuf, "\n");
//     printf("%s\n", bvbuf);

//     FILE* fp_output = fopen("basevalue.txt", "w");
//     fwrite(bvbuf, sizeof(bvbuf), 1, fp_output);
//     fclose(fp_output);
// }
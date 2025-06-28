/***********************************************************************
    Copyright Buu Information Security Major/
    File Name: hancipher_utf8.c
    Author: 毛家奇
    ID: 2023240381019
    Version: 3.0
    Date: 2025/3/7
    Description:
                通过utf8对文件进行加解密，增加识别GB和UTF - 8文件功能，仅支持 -e 和 -d 命令行选项，无文件则不创建
***********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 判断文件是否为UTF-8编码
int is_utf8(const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        if ((data[i] & 0x80) == 0) {  // 1字节字符
            i++;
        } else if ((data[i] & 0xE0) == 0xC0) {  // 2字节字符
            if (i + 1 >= len || (data[i + 1] & 0xC0) != 0x80) return 0;
            i += 2;
        } else if ((data[i] & 0xF0) == 0xE0) {  // 3字节字符
            if (i + 2 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80) return 0;
            i += 3;
        } else if ((data[i] & 0xF8) == 0xF0) {  // 4字节字符
            if (i + 3 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80) return 0;
            i += 4;
        } else {
            return 0;
        }
    }
    return 1;
}

/***********************************************************************
    Function Name: caesar_encrypt_byte
    Parameters:
                uint8_t c: 【in】 待加密的单个字节
                int shift: 【in】 偏移量
                int is_continuation: in 是否为UTF - 8续字节，1表示是，0表示不是
    Return:
            Type: uint8_t
                加密后的字节
    Description:
                该函数对单个字节进行加密，考虑UTF - 8编码格式
***********************************************************************/
static inline uint8_t caesar_encrypt_byte(uint8_t c, int shift, int is_continuation) {
    if (is_continuation) {
        return ((c - 0x80 + shift) % 0x40) + 0x80;  // 保持10xxxxxx格式
    } else if ((c & 0x80) == 0) {
        return (c + shift) % 0x80;                   // 处理ASCII字符
    } else {
        uint8_t mask = 0xFF << (7 - __builtin_clz((c ^ 0xFF) << 24));
        uint8_t prefix = c & mask;
        uint8_t data = c & ~mask;
        return prefix | ((data + shift) % (0xFF ^ mask + 1));  // 保持前缀位
    }
}
/***********************************************************************
    Function Name: caesar_encrypt_utf8
    Parameters:
                uint8_t *data: 【in/out】待加密的字节数组指针
                size_t len: 【in】 数据长度
                int shift: 【in】 偏移量
    Return:
        Type: void
            None: 直接在原数据上修改
    Description:
                该函数对UTF - 8编码的数据进行凯撒加密，保持字节序列结构不变
***********************************************************************/
void caesar_encrypt_utf8(uint8_t *data, size_t len, int shift) {
    for (size_t i = 0; i < len; ) {
        int cont_bytes = 0;
        if ((data[i] & 0x80) == 0) {                // 1字节字符
            data[i] = caesar_encrypt_byte(data[i], shift, 0);
            i += 1;
        } else if ((data[i] & 0xE0) == 0xC0) {       // 2字节字符
            cont_bytes = 1;
        } else if ((data[i] & 0xF0) == 0xE0) {       // 3字节字符
            cont_bytes = 2;
        } else if ((data[i] & 0xF8) == 0xF0) {       // 4字节字符
            cont_bytes = 3;
        } else {
            i++;                                     // 无效字节，跳过
            continue;
        }

        // 处理首字节
        data[i] = caesar_encrypt_byte(data[i], shift, 0);
        i++;

        // 处理续字节
        for (int j = 0; j < cont_bytes && i < len; j++, i++) {
            if ((data[i] & 0xC0) == 0x80) {
                data[i] = caesar_encrypt_byte(data[i], shift, 1);
            }
        }
    }
}
/***********************************************************************
    Function Name: caesar_decrypt_utf8
    Parameters:
                uint8_t *data: 【in/out】 待解密的字节数组指针
                size_t len: 【in】 数据长度
                int shift: 【in】 偏移量
    Return:
        Type: void
            None: 直接在原数据上修改
    Description:
                该函数对UTF - 8编码的数据进行凯撒解密，保持字节序列结构不变
  ***********************************************************************/
void caesar_decrypt_utf8(uint8_t *data, size_t len, int shift) {
    caesar_encrypt_utf8(data, len, -shift);
}

// 对GB编码的数据进行简单的凯撒加密
void caesar_encrypt_gb(uint8_t *data, size_t len, int shift) {
    for (size_t i = 0; i < len; i++) {
        data[i] = (data[i] + shift) % 256;
    }
}

// 对GB编码的数据进行简单的凯撒解密
void caesar_decrypt_gb(uint8_t *data, size_t len, int shift) {
    caesar_encrypt_gb(data, len, -shift);
}

// 根据文件类型选择加密函数
void choose_encrypt_function(uint8_t *data, size_t len, int shift) {
    if (is_utf8(data, len)) {
        caesar_encrypt_utf8(data, len, shift);
    } else {
        caesar_encrypt_gb(data, len, shift);
    }
}

// 根据文件类型选择解密函数
void choose_decrypt_function(uint8_t *data, size_t len, int shift) {
    if (is_utf8(data, len)) {
        caesar_decrypt_utf8(data, len, shift);
    } else {
        caesar_decrypt_gb(data, len, shift);
    }
}

/***********************************************************************
    Function Name: read_file
    Parameters:
                const char* filename: 【in】 要读取的文件名
                size_t* len: 【out】 读取文件数据的长度
    Type: uint8_t*
            成功: 返回动态分配的文件数据指针
            失败: 返回NULL
    Description:
                该函数以二进制模式读取文件数据，并动态分配内存存储
***********************************************************************/
uint8_t* read_file(const char* filename, size_t* len) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    *len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t* buf = malloc(*len);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    fread(buf, 1, *len, fp);
    fclose(fp);
    return buf;
}
/***********************************************************************
    Function Name: main
    Parameters:
                int argc: 【in】 命令行参数数量
                char *argv[]: 【in】 命令行参数数组
    Return:
    Type: int
            0: 正常退出
            -1: 异常退出
    Description:
    程序提供两种运行模式：
                        1. 无参数模式：自动读取plain.txt，加密到ciphers.txt，解密到decode.txt
                        2. 有参数模式：通过命令行指定加密/解密操作和输入/输出文件
***********************************************************************/
int main(int argc, char *argv[]) {
    int shift = 3;                                   // 固定偏移量
    size_t len;
    uint8_t *data;

    if (argc == 1) {                                 // 自动模式
        data = read_file("plain.txt", &len);
        if (!data) {
            printf("无法读取 plain.txt，不进行操作。\n");
            return -1;
        }

        choose_encrypt_function(data, len, shift);

        FILE *fp = fopen("ciphers.txt", "wb");
        if (fp) {
            fwrite(data, 1, len, fp);
            fclose(fp);
        } else {
            printf("无法打开 ciphers.txt 进行写入，不进行加密文件创建。\n");
        }

        choose_decrypt_function(data, len, shift);

        fp = fopen("decode.txt", "wb");
        if (fp) {
            fwrite(data, 1, len, fp);
            fclose(fp);
        } else {
            printf("无法打开 decode.txt 进行写入，不进行解密文件创建。\n");
        }

        free(data);
        printf("操作完成，若文件可创建，加密文件为ciphers.txt，解密文件为decode.txt\n");
        return 0;
    }

    if (argc != 4) {                                // 参数检查，仅支持 -e 和 -d 选项
        printf("用法: %s -e|-d 输入文件 输出文件\n", argv[0]);
        return -1;
    }

    data = read_file(argv[2], &len);                // 读取输入文件
    if (!data) {
        printf("无法读取输入文件，不进行操作。\n");
        return -1;
    }

    if (strcmp(argv[1], "-e") == 0) {               // 加密操作
        choose_encrypt_function(data, len, shift);
    } else if (strcmp(argv[1], "-d") == 0) {        // 解密操作
        choose_decrypt_function(data, len, shift);
    } else {
        printf("无效参数\n");
        free(data);
        return -1;
    }

    FILE *fp = fopen(argv[3], "wb");               // 写入输出文件
    if (fp) {
        fwrite(data, 1, len, fp);
        fclose(fp);
        printf("操作完成，输出文件为%s\n", argv[3]);
    } else {
        printf("无法打开输出文件进行写入，不进行文件创建。\n");
    }
    free(data);
    return 0;
}

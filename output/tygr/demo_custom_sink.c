#include <stdio.h>

/* 期望漏洞(GT 注解)：污点 argv 经 main 流入自定义缓冲 sink store_record */
// @vuln: buffer_overflow argv -> store_record

/*
 * 自定义的不安全缓冲拷贝：手工 while 循环，无界写入。
 * 关键：它不调用任何 libc sink(没有 strcpy/memcpy/...)，
 * 所以纯「函数名匹配 + 结构启发式(调用了已知 sink?)」都识别不到它。
 * 唯一的线索是它的参数类型 —— dst/src 都是 char* 缓冲(GNN 能恢复)。
 */
void store_record(char *dst, char *src) {
    int i = 0;
    while (src[i] != '\0') {   /* 无上界 → 若 src 长于 dst 即溢出 */
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        store_record(buffer, argv[1]);   /* 污点 argv[1] → 自定义缓冲 sink */
        printf("%s\n", buffer);
    }
    return 0;
}

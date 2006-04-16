       .section ".note.netbsd.ident", "a"
        .long   2f-1f
        .long   4f-3f
        .long   1
1:      .asciz "NetBSD"
2:      .p2align 2
3:      .long   199905
4:      .p2align 2

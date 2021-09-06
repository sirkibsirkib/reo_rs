#ifndef REORS
#define REORS

#include <stdint.h>
#include <stdbool.h>

struct ErrBuf;
struct Proto;

typedef Proto * ArcProto;
typedef uint32_t Name;

unsigned char * read_err(ErrBuf * err_buf, uintptr_t * len);
void err_buf_new(ErrBuf * out);
void err_buf_destroy(ErrBuf * err_buf);

void proto_destroy(ArcProto p);
ArcProto proto_clone(ArcProto p);

bool claim_putter(ArcProto p, Name name, Putter * out, ErrBuf * err_buf);
bool claim_getter(ArcProto p, Name name, Getter * out, ErrBuf * err_buf);

bool put(Putter * putter, uint8_t * msg);
void get(Putter * putter, uint8_t * msg);

#endif
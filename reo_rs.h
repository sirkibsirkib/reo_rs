#ifndef REORS
#define REORS

#include <stdint.h>
#include <stdbool.h>

// genuine type aliases
typedef uint32_t Name;

// opaque pointer types
typedef struct { uintptr_t ptr; } ErrBuf;
typedef struct { uintptr_t ptr; } ArcProto;

// User-accessible types
typedef struct PortCommon {
	ArcProto arc_proto;
	uintptr_t space_index;
} PortCommon;

typedef struct Putter {
	PortCommon common;
} Putter;

typedef struct Getter {
	PortCommon common;
} Getter;

typedef struct {
    uintptr_t size;
    uintptr_t value;
    void (*raw_move)(uint8_t *, const uint8_t *);
    void (*maybe_clone)(uint8_t *, const uint8_t *);
    bool (*maybe_eq)(uint8_t const *, uint8_t const *);
    void (*maybe_drop)(uint8_t *);
} TypeInfoC;

typedef struct TypeKey {
	const TypeInfoC * type_info;
} TypeKey;

/////////////////////////////////////////////////////////////////
////////// CREATE
void reors_err_buf_create(ErrBuf * out);
bool reors_putter_claim(ArcProto arc_proto, Name name, Putter * out, ErrBuf * err_buf);
bool reors_getter_claim(ArcProto arc_proto, Name name, Getter * out, ErrBuf * err_buf);
ArcProto reors_proto_clone(ArcProto arc_proto);

////////// USE

unsigned char * reors_read_err(ErrBuf * err_buf, uintptr_t * len);
bool reors_put(Putter * putter, uint8_t * msg);
void reors_get(Putter * putter, uint8_t * msg);

////////// DESTROY
void reors_proto_destroy(ArcProto arc_proto);
void reors_err_buf_destroy(ErrBuf * err_buf);
void reors_putter_destroy(Putter * putter);
void reors_getter_destroy(Getter * getter);

#endif
#include <cstdint>

typedef struct CProtoHandle {
	inner: uintptr_t;
} CProtoHandle;

CProtoHandle reors_empty_proto_create();

void reors_proto_handle_destroy(CProtoHandle *);
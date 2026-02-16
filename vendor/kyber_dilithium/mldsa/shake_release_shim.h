// Shim for PQClean shake128_inc_ctx_release and shake256_inc_ctx_release
// These are not present in the minimal fips202 implementation, so we define them as no-ops.
#include "../../hqc/lib/fips202/fips202.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void shake128_inc_ctx_release(shake128incctx *state) {}
static inline void shake256_inc_ctx_release(shake256incctx *state) {}

#ifdef __cplusplus
}
#endif

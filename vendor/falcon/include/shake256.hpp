#pragma once
extern "C" {
#include "fips202.h"
}
#include <cstddef>
#include <cstdint>

namespace falcon_shake256 {

constexpr size_t rate = 1088;

template<bool Keccak>
class shake256
{
public:
  shake256()
  {
    shake256_inc_init(&ctx_);
  }

  void absorb(const uint8_t* const data, const size_t len)
  {
    if (finalized_) {
      return;
    }
    shake256_inc_absorb(&ctx_, data, len);
  }

  void finalize()
  {
    if (!finalized_) {
      shake256_inc_finalize(&ctx_);
      finalized_ = true;
    }
  }

  void read(uint8_t* const out, const size_t len)
  {
    if (!finalized_) {
      finalize();
    }
    shake256_inc_squeeze(out, len, &ctx_);
  }

  void hash(const uint8_t* const data, const size_t len)
  {
    shake256_inc_init(&ctx_);
    shake256_inc_absorb(&ctx_, data, len);
    shake256_inc_finalize(&ctx_);
    finalized_ = true;
  }

private:
  shake256incctx ctx_{};
  bool finalized_{ false };
};

} // namespace falcon_shake256

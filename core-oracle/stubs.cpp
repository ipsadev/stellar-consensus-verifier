#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <rust/RustBridge.h>
#include <sodium.h>

namespace stellar
{
namespace rust_bridge
{

bool
verify_ed25519_signature_dalek(const ::std::uint8_t *, const ::std::uint8_t *,
                               const ::std::uint8_t *, ::std::size_t) noexcept
{
    std::fprintf(stderr,
                 "core-oracle: verify_ed25519_signature_dalek was called. This "
                 "oracle links only the quorum predicates and stubs the rust "
                 "bridge, so any answer would be meaningless.\n");
    std::abort();
}

void
init_logging(::stellar::LogLevel)
{
}

void
compute_sha256(const ::std::uint8_t *data, ::std::size_t len,
               ::std::uint8_t *out) noexcept
{
    crypto_hash_sha256(out, data, len);
}

static crypto_hash_sha256_state *
sha256_state(RustSha256 *self)
{
    return reinterpret_cast<crypto_hash_sha256_state *>(self);
}

::rust::Box<RustSha256>
new_rust_sha256() noexcept
{
    auto *state = new crypto_hash_sha256_state;
    crypto_hash_sha256_init(state);

    return ::rust::Box<RustSha256>::from_raw(
        reinterpret_cast<RustSha256 *>(state));
}

void
RustSha256::update(const ::std::uint8_t *data, ::std::size_t len) noexcept
{
    crypto_hash_sha256_update(sha256_state(this), data, len);
}

void
RustSha256::finalize(::std::uint8_t *out) noexcept
{
    crypto_hash_sha256_final(sha256_state(this), out);
    crypto_hash_sha256_init(sha256_state(this));
}

void
RustSha256::reset() noexcept
{
    crypto_hash_sha256_init(sha256_state(this));
}

}

void
printCurrentBacktrace()
{
    std::fprintf(stderr, "core-oracle: backtrace unavailable in this build\n");
}

}

template <>
void
rust::cxxbridge1::Box<stellar::rust_bridge::RustSha256>::drop() noexcept
{
    delete reinterpret_cast<crypto_hash_sha256_state *>(this->ptr);
}

namespace
{

struct Sha256SelfCheck
{
    Sha256SelfCheck()
    {
        static const ::std::uint8_t abc[] = {'a', 'b', 'c'};
        static const ::std::uint8_t expected[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
            0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
            0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

        ::std::uint8_t oneShot[32];
        ::std::uint8_t streamed[32];

        stellar::rust_bridge::compute_sha256(abc, sizeof abc, oneShot);

        auto hasher = stellar::rust_bridge::new_rust_sha256();
        hasher->update(abc, 1);
        hasher->update(abc + 1, 2);
        hasher->finalize(streamed);

        if (std::memcmp(oneShot, expected, 32) != 0 ||
            std::memcmp(streamed, expected, 32) != 0)
        {
            std::fprintf(stderr, "core-oracle: the sha256 bridge stub failed "
                                 "its known-answer test\n");
            std::abort();
        }
    }
};

Sha256SelfCheck const sha256SelfCheck;

}

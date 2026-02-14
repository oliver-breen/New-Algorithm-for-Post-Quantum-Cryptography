#include <pybind11/pybind11.h>

#include "falcon.hpp"
#include "utils.hpp"

namespace py = pybind11;

namespace {

template<size_t N>
py::tuple keygen_impl()
{
  constexpr size_t pklen = falcon_utils::compute_pkey_len<N>();
  constexpr size_t sklen = falcon_utils::compute_skey_len<N>();

  std::string pkey(pklen, '\0');
  std::string skey(sklen, '\0');

  falcon::keygen<N>(reinterpret_cast<uint8_t*>(pkey.data()),
                    reinterpret_cast<uint8_t*>(skey.data()));

  return py::make_tuple(py::bytes(pkey), py::bytes(skey));
}

template<size_t N>
py::bytes sign_impl(const py::bytes& skey_py, const py::bytes& msg_py)
{
  std::string skey = skey_py;
  std::string msg = msg_py;

  constexpr size_t sklen = falcon_utils::compute_skey_len<N>();
  if (skey.size() != sklen) {
    throw py::value_error("Invalid Falcon secret key length");
  }

  constexpr size_t siglen = falcon_utils::compute_sig_len<N>();
  std::string sig(siglen, '\0');

  const bool ok = falcon::sign<N>(
    reinterpret_cast<const uint8_t*>(skey.data()),
    reinterpret_cast<const uint8_t*>(msg.data()),
    msg.size(),
    reinterpret_cast<uint8_t*>(sig.data()));

  if (!ok) {
    throw std::runtime_error("Falcon signing failed");
  }

  return py::bytes(sig);
}

template<size_t N>
bool verify_impl(const py::bytes& pkey_py,
                 const py::bytes& msg_py,
                 const py::bytes& sig_py)
{
  std::string pkey = pkey_py;
  std::string msg = msg_py;
  std::string sig = sig_py;

  constexpr size_t pklen = falcon_utils::compute_pkey_len<N>();
  constexpr size_t siglen = falcon_utils::compute_sig_len<N>();

  if (pkey.size() != pklen) {
    throw py::value_error("Invalid Falcon public key length");
  }
  if (sig.size() != siglen) {
    throw py::value_error("Invalid Falcon signature length");
  }

  return falcon::verify<N>(
    reinterpret_cast<const uint8_t*>(pkey.data()),
    reinterpret_cast<const uint8_t*>(msg.data()),
    msg.size(),
    reinterpret_cast<uint8_t*>(sig.data()));
}

py::tuple py_keygen(const int n)
{
  switch (n) {
    case 512:
      return keygen_impl<512>();
    case 1024:
      return keygen_impl<1024>();
    default:
      throw py::value_error("Unsupported Falcon parameter set");
  }
}

py::bytes py_sign(const int n, const py::bytes& skey, const py::bytes& msg)
{
  switch (n) {
    case 512:
      return sign_impl<512>(skey, msg);
    case 1024:
      return sign_impl<1024>(skey, msg);
    default:
      throw py::value_error("Unsupported Falcon parameter set");
  }
}

bool py_verify(const int n,
               const py::bytes& pkey,
               const py::bytes& msg,
               const py::bytes& sig)
{
  switch (n) {
    case 512:
      return verify_impl<512>(pkey, msg, sig);
    case 1024:
      return verify_impl<1024>(pkey, msg, sig);
    default:
      throw py::value_error("Unsupported Falcon parameter set");
  }
}

py::tuple py_sizes(const int n)
{
  switch (n) {
    case 512:
      return py::make_tuple(
        falcon_utils::compute_pkey_len<512>(),
        falcon_utils::compute_skey_len<512>(),
        falcon_utils::compute_sig_len<512>());
    case 1024:
      return py::make_tuple(
        falcon_utils::compute_pkey_len<1024>(),
        falcon_utils::compute_skey_len<1024>(),
        falcon_utils::compute_sig_len<1024>());
    default:
      throw py::value_error("Unsupported Falcon parameter set");
  }
}

} // namespace

PYBIND11_MODULE(_falcon, m)
{
  m.doc() = "Falcon signature bindings";

  m.def("keygen", &py_keygen, py::arg("n"));
  m.def("sign", &py_sign, py::arg("n"), py::arg("skey"), py::arg("msg"));
  m.def("verify", &py_verify, py::arg("n"), py::arg("pkey"), py::arg("msg"), py::arg("sig"));
  m.def("sizes", &py_sizes, py::arg("n"));
}

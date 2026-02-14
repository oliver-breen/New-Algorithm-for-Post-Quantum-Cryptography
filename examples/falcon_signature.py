from quantaweave import FalconSig


def main() -> None:
    falcon = FalconSig("Falcon-1024")
    public_key, secret_key = falcon.keygen()

    message = b"Falcon signature demo"
    signature = falcon.sign(secret_key, message)

    verified = falcon.verify(public_key, message, signature)
    print(f"verified: {verified}")


if __name__ == "__main__":
    main()

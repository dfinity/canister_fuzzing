import ECDSA "mo:ecdsa";
import Ecdsa "mo:ecdsa";
import Iter "mo:core/Iter";
import Debug "mo:base/Debug";

persistent actor EcdsaSigner {

  /**
   * Parses the provided CBOR bytes.
   * This function does not return a result to the caller, but it will
   * print the outcome of the parsing attempt to the canister's logs.
   * @param bytes The raw CBOR data as an array of Nat8.
   */
  public func sign_ecdsa(message: [Nat8], entropy: [Nat8], randomK: [Nat8]) : async [Nat8] {
    // Create a key pair using secp256k1
    let curve = ECDSA.secp256k1Curve();
    let privateKeyResult = ECDSA.generatePrivateKey(entropy.vals(), curve);

    switch (privateKeyResult) {
        case (#ok(privateKey)) {
            let signatureResult = privateKey.signHashed(message.vals(), randomK.vals());

            switch (signatureResult) {
                case (#ok(signature)) {  
                  let bytes = signature.toBytes(#der);
                  return bytes
                };
                case (#err(e)) {
                  return []
                };
            };
        };
        case (#err(e)) {
          return []
        };
    };
  };
}
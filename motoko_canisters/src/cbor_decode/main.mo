import Cbor "mo:cbor";

actor {
  public func parse_cbor(bytes : Blob) {
    let cbor = Cbor.fromBytes(bytes.vals());
  };
};

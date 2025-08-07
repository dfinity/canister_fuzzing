import DagCbor "mo:dag-cbor";

/**
 * An actor that can parse raw CBOR binary data using the dag-cbor library.
 */
persistent actor CborParser {

  /**
   * Parses the provided CBOR bytes.
   * This function does not return a result to the caller, but it will
   * print the outcome of the parsing attempt to the canister's logs.
   * @param bytes The raw CBOR data as an array of Nat8.
   */
  public func parse_cbor(bytes: [Nat8]) : async () {
    let _dagValue = DagCbor.fromBytes(bytes.vals());
  };
}